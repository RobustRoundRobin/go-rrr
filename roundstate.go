package rrr

import (
	"bytes"
	"crypto/ecdsa"
	"encoding/hex"
	"fmt"
	"math/big"
	"math/rand"
	"sync"

	"github.com/vechain/go-ecvrf"
	"golang.org/x/crypto/sha3"
)

// RoundState type for the round state
type RoundState int

// RoundPhase is the type for the round phase
type RoundPhase int

const (
	// RoundStateInvalid is the invalid and never set state
	RoundStateInvalid RoundState = iota
	// RoundStateNeedBlock is entered if the current block doesn't 'make sense'.
	// We should not ever receive invalid blocks if VerifyHeaders is working,
	// but this is our backstop. The node will not progress until it sees a new
	// node from the network.
	RoundStateNeedBlock
	// RoundStateInactive is set if the node is not in the active selection for the round.
	RoundStateInactive // Indicates conditions we expect to be transitor - endorsers not online etc

	// RoundStateActive is entered if the node is active but is not selected as
	// either a leader or an endorser
	RoundStateActive // Has endorsed or mined in some time in the last Ta rounds.

	// RoundStateLeaderCandidate selected as leader candidate for current round
	RoundStateLeaderCandidate
	// RoundStateEndorserCommittee Is in the endorser committee for the current round.
	RoundStateEndorserCommittee
)

const (
	// RoundPhaseInvalid is the invalid state for RoundPhase
	RoundPhaseInvalid RoundPhase = iota
	// RoundPhaseIntent During the Intent phase, the endorser committee is
	// allowing for intents to arrive so they can, with high probability, pick
	// the oldest active leader candidate.
	RoundPhaseIntent
	// RoundPhaseConfirm During the confirmation phase leaders are waiting for
	// all the endorsements to come in so they fairly represent activity.
	RoundPhaseConfirm
)

type headerByNumberChainReader interface {

	// GetHeaderByNumber retrieves a block header from the database by number.
	GetHeaderByNumber(number uint64) BlockHeader
}

// EndorsmentProtocol implements  5.2 "Endorsement Protocol" and 5.3 "Chain
// Validation" (from the paper)
type EndorsmentProtocol struct {
	logger Logger

	// The following interfaces give rrr the use of go-ethereum crypto and rlp
	// primitives.  This arrangement avoids a circular dependency and licensing
	// issues.
	c          CipherSuite
	rlpEncoder RLPEncoder
	rlpDecoder RLPDecoder

	// Node and chain context
	config     *Config
	genesisEx  GenesisExtraData
	privateKey *ecdsa.PrivateKey
	nodeID     Hash // derived from privateKey

	nodeAddr Address

	vrf  ecvrf.VRF
	T    *RoundTime
	Rand *rand.Rand

	Phase RoundPhase

	roundStateMu sync.RWMutex
	// state
	// Any thread can read this via State(), only the engine run thread is
	// allowed to set it. The engine run thread can read it without the lock,
	// but it must hold the lock to update it.
	state RoundState

	Number         *big.Int
	FailedAttempts uint

	OnlineEndorsers map[Address]Peer

	// These get updated each round on all nodes without regard to which are
	// leaders/endorsers or participants.
	selection  []Address
	endorsers  map[Address]bool
	candidates map[Address]bool

	intentMu sync.Mutex
	sealTask *EngSealTask
	intent   *pendingIntent

	// On endorsing nodes, keep the oldest signed intent we have seen during
	// the intent phase, until the end of the phase or until we see an intent
	// from the oldest candidate.
	signedIntent *EngSignedIntent

	pendingEnrolmentsMu sync.RWMutex
	pendingEnrolments   map[Hash]*EnrolmentBinding

	a *ActiveSelection
}

// NewRoundState creates and initialises a RoundState
func NewRoundState(
	c CipherSuite, rlpDecoder RLPDecoder, rlpEncoder RLPEncoder,
	key *ecdsa.PrivateKey, config *Config, logger Logger,
) *EndorsmentProtocol {

	s := &EndorsmentProtocol{
		logger:     logger,
		privateKey: key,
		c:          c,
		rlpEncoder: rlpEncoder,
		rlpDecoder: rlpDecoder,

		nodeID:   Pub2NodeID(c, &key.PublicKey),
		nodeAddr: PubToAddress(c, &key.PublicKey),
		config:   config,
		vrf:      ecvrf.NewSecp256k1Sha256Tai(),
		T:        NewRoundTime(config.RoundLength, config.ConfirmPhase, logger),

		pendingEnrolments: make(map[Hash]*EnrolmentBinding),

		Number: new(big.Int),
	}
	return s
}

// CalcDifficulty is the difficulty adjustment algorithm. It returns the difficulty
// that a new block should have. For rrr this is just the round number
func (r *EndorsmentProtocol) CalcDifficulty(nodeAddr Address) *big.Int {
	r.logger.Debug("RRR CalcDifficulty")

	r.intentMu.Lock()
	defer r.intentMu.Unlock()

	if r.candidates[nodeAddr] {
		return difficultyForCandidate
	}
	return difficultyForEndorser
}

// CheckGenesis checks that the RRR consensus configuration in the genesis block
// is correct.
func (r *EndorsmentProtocol) CheckGenesis(chain headerByNumberChainReader) error {

	hg := chain.GetHeaderByNumber(0)
	if hg == nil {
		return ErrNoGenesisHeader
	}

	if r.genesisEx.ChainID == zeroHash {
		// geth warmup will call VerifyBranchHeaders on the genesis block
		// before doing anything else. This guard simply avoids an anoying and
		// redundant log message, whilst also guarding against changes in the
		// geth implementation outside of our control.
		seal := hg.GetSeal()
		r.logger.Info("RRR CheckGenesis", "seal", hex.EncodeToString(seal))
		err := r.rlpDecoder.DecodeBytes(seal, &r.genesisEx)
		if err != nil {
			return err
		}
	}

	// All of the enrolments in the genesis block are signed by the long term
	// identity key (node key) of the genesis node.
	ok, genPubBytes, err := VerifyRecoverNodeSig(
		r.c, r.genesisEx.IdentInit[0].ID, r.genesisEx.IdentInit[0].U[:], r.genesisEx.IdentInit[0].Q[:])
	if err != nil || !ok {
		return fmt.Errorf("genesis identity invalid signature: %w", errGensisIdentitiesInvalid)
	}

	// Check the genesis seed and the signatures of all the contributions to the genesis seed alpha.
	hasher := sha3.NewLegacyKeccak256()
	for i, ident := range r.genesisEx.IdentInit {
		a := r.genesisEx.Alpha[i]

		if !VerifyNodeSig(r.c, ident.ID, a.Contribution[:], a.Sig[:]) {
			return fmt.Errorf(
				"genesis identity [%d: %s] alpha sig verify failed: %w",
				i, ident.ID.Hex(), errGensisIdentitiesInvalid)
		}
		hasher.Write(a.Contribution[:])
	}
	alpha := hasher.Sum(nil)

	// Now verify the seed was produced correctly by the genesis signer.
	genPub, err := BytesToPublic(r.c, genPubBytes)
	if err != nil {
		return fmt.Errorf("genesis identity failed to recover public key: %w", err)
	}

	beta, err := r.vrf.Verify(genPub, alpha, r.genesisEx.Proof)
	if err != nil {
		return fmt.Errorf("genesis seed invalid: %w", err)
	}

	if !bytes.Equal(beta, r.genesisEx.Seed) {
		return fmt.Errorf("genesis seed invalid")
	}

	r.logger.Debug("RRR CheckGenesis", "genid", r.genesisEx.IdentInit[0].ID.Hex())

	return nil
}

// PrimeActiveSelection should be called for engine Start
func (r *EndorsmentProtocol) PrimeActiveSelection(chain EngineChainReader) error {

	if err := r.CheckGenesis(chain); err != nil {
		return err
	}

	if r.a != nil {
		r.a.Prime(r.config.Activity, chain.CurrentHeader())
		return nil
	}

	r.a = NewActiveSelection(r.c, r.rlpDecoder, r.rlpEncoder, r.nodeID, r.logger)
	r.a.Reset(r.config.Activity, chain.CurrentHeader())

	return nil
}

// QueueEnrolment enrols a node id. This enrolment is completely open. The SGX
// identity attestation and the minining identity approaches are not presently
// included.
func (r *EndorsmentProtocol) QueueEnrolment(et *EngEnrolIdentity) error {
	r.pendingEnrolmentsMu.Lock()
	defer r.pendingEnrolmentsMu.Unlock()

	eb := &EnrolmentBinding{
		ChainID: r.genesisEx.ChainID,
		NodeID:  Hash(et.NodeID),
		// Round will be updated when we are ready to submit the enrolment. We
		// record it here so we can keep track of how long enrolments have been
		// queued.
		Round: big.NewInt(0).Set(r.Number),
		// Block hash filled in when we issue the intent containing this
		// enrolment.

		// XXX: ReEnrol flag is not necessary for non SGX implementations afaict.
		ReEnrol: et.ReEnrol,
	}

	r.pendingEnrolments[et.NodeID] = eb
	return nil
}

// IsEnrolmentPending returns true if there is an enrolment request queued for
// the nodeID
func (r *EndorsmentProtocol) IsEnrolmentPending(nodeID Hash) bool {
	r.pendingEnrolmentsMu.RLock()
	defer r.pendingEnrolmentsMu.RUnlock()
	_, ok := r.pendingEnrolments[nodeID]
	return ok
}

// NewSignedIntent keeps track of the oldest intent seen in a round. At the end
// of the intent phase (in PhaseTick), if the node is an endorser, an endorsment
// is sent to the oldest seen. Only the most recent intent from any identity
// counts.
func (r *EndorsmentProtocol) NewSignedIntent(et *EngSignedIntent) {
	// endorser <- intent from leader candidate
	if r.state == RoundStateNeedBlock {
		r.logger.Trace("RRR engSignedIntent - need block, ignoring", "et.round", et.RoundNumber)
		return
	}
	// See RRR-spec.md for a more thorough explanation, and for why we don't
	// check the round phase or whether or not we - locally - have selected
	// ourselves as an endorser. handleIntent.
	r.logger.Trace("RRR run got engSignedIntent",
		"round", r.Number, "cand-round", et.RoundNumber, "cand-attempts", et.FailedAttempts,
		"candidate", et.NodeID.Hex(), "parent", et.ParentHash.Hex())

	if err := r.handleIntent(et); err != nil {
		r.logger.Info("RRR run handleIntent", "err", err)
	}
}

// handleIntent accepts the intent and queues it for endorsement if the
// intendee is a candidate for the current round given the failedAttempts
// provided on the intent.
//  Our critical role here is to always select the *OLDEST* intent we see, and
// to allow a 'fair' amount of time for intents to arrive before choosing one
// to endorse. In a healthy network, there will be no failedAttempts, and we
// could count on being synchronised reasonably with other nodes. In that
// situation our local 'endorsing' state can be checked. In the unhealthy
// scenario, or where the current leader candidates are all off line, we can
// only progress if we re-sample. And in that scenario different nodes could
// have been un-reachable for arbitrary amounts of time. So their
// failedAttempts will be arbitrarily different. Further, we can't stop other
// nodes from lying about their failedAttempts. So even if we were willing to
// run through randome samples x failedAttempts to check, the result would be
// meaningless - and would be an obvious way to DOS attack nodes.  Ultimately,
// it is the job of VerifyHeader, on all honest nodes, to check that the
// failedAttempts recorded in the block is consistent with the minters identity
// and the endorsers the minter included.  Now we *could* do special things for
// the firstAttempt or the first N attempts. But if, in the limit, we have to
// be robust in the face of some endorsers not checking, I would like to start
// with them all not checking
func (r *EndorsmentProtocol) handleIntent(et *EngSignedIntent) error {

	var err error

	// Do we agree that the intendee is next in line and that their intent is
	// appropriate ?

	// Check that the public key recovered from the intent signature matches
	// the node id declared in the intent

	var recoveredNodeID Hash
	if recoveredNodeID, err = PubBytes2NodeID(r.c, et.Pub); err != nil {
		return err
	}
	intenderAddr := et.NodeID.Address()

	if recoveredNodeID != et.NodeID {
		r.logger.Info("RRR handleIntent - sender not signer",
			"from-addr", intenderAddr.Hex(), "recovered", recoveredNodeID.Hex(),
			"signed", et.NodeID.Hex())
		return nil
	}

	// Check that the intent round matches our current round.
	if r.Number.Cmp(et.RoundNumber) != 0 {
		r.logger.Info("RRR handleIntent - wrong round",
			"r", r.Number, "ir", et.RoundNumber, "from-addr", intenderAddr.Hex())
		return nil
	}

	// Check that the intent comes from a node we have selected locally as a
	// leader candidate. According to the (matching) roundNumber and their
	// provided value for FailedAttempts
	if !r.a.LeaderForRoundAttempt(
		uint(r.config.Candidates), uint(r.config.Endorsers),
		intenderAddr, et.Intent.FailedAttempts) {
		r.logger.Info(
			"RRR handleIntent - intent from non-candidate",
			"round", r.Number, "cand-f", et.Intent.FailedAttempts, "cand", intenderAddr.Hex())
		return ErrNotLeaderCandidate
	}

	if r.signedIntent != nil {
		// It must be in the map if it was active, otherwise we have a
		// programming error.
		curAge := r.a.aged[r.signedIntent.NodeID.Address()].Value.(*idActivity).ageBlock
		newAge := r.a.aged[intenderAddr].Value.(*idActivity).ageBlock

		// Careful here, the 'older' block will have the *lower* number
		if curAge.Cmp(newAge) < 0 {
			// current is older
			r.logger.Trace(
				"RRR handleIntent - ignoring intent from younger candidate",
				"cand-addr", intenderAddr.Hex(), "cand-f", et.Intent.FailedAttempts)
			return nil
		}
	}

	// Its the first one, or it is from an older candidate and yet is not the oldest
	r.signedIntent = et
	return nil
}

// broadcastCurrentIntent sends the current intent to all known *online* peers
// selected as endorsers. It does this un-conditionally. It is the callers
// responsibility to call this from the right consensus engine state - including
// establishing if the local node is a legitemate leader candidate.
func (r *EndorsmentProtocol) broadcastCurrentIntent(b Broadcaster) {

	r.intentMu.Lock()
	if r.intent == nil {
		r.intentMu.Unlock()
		r.logger.Debug("RRR broadcastCurrentIntent - no intent")
		return
	}

	msg := r.intent.Msg
	r.intentMu.Unlock()

	if len(r.OnlineEndorsers) == 0 {
		return
	}
	err := b.Broadcast(r.nodeAddr, r.OnlineEndorsers, msg)
	if err != nil {
		r.logger.Info("RRR BroadcastCurrentIntent - Broadcast", "err", err)
	}
}
