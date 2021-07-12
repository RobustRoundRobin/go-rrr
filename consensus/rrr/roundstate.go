package rrr

import (
	"crypto/ecdsa"
	"encoding/hex"
	"fmt"
	"math/big"
	"math/rand"
	"sync"
	"time"

	"github.com/vechain/go-ecvrf"
)

// RoundState type for the round state
type RoundState int

// RoundPhase is the type for the round phase
type RoundPhase int

const (
	// RoundStateInvalid is the invalid and never set state
	RoundStateInvalid RoundState = iota
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

	// RoundPhaseBroadcast during the Broadcast phase all nodes are waiting for
	// a NewChainHead event for the current round (including the c nsensus
	// leaders). Any node receiving an otherwise valid HEAD for a different
	// round must align with the round on the recieved head.
	RoundPhaseBroadcast

	// Used to absorb and align the start time with the round time. Means we
	// can deal with most initialisation the same as we do the end of the
	// Broadcast round *and* we may get a block while we wait.
	RoundPhaseStartup
)

type headerByNumberChainReader interface {

	// GetHeaderByNumber retrieves a block header from the database by number.
	GetHeaderByNumber(number uint64) BlockHeader
}

type headerByHashChainReader interface {

	// GetHeaderByNumber retrieves a block header from the database by number.
	GetHeaderByHash([32]byte) BlockHeader
}

// EndorsmentProtocol implements  5.2 "Endorsement Protocol" and 5.3 "Chain
// Validation" (from the paper)
type EndorsmentProtocol struct {
	logger Logger

	// The following interface give rrr the use of go-ethereum crypto and rlp
	// primitives.  This arrangement avoids a circular dependency and licensing
	// issues.
	codec *CipherCodec

	// Node and chain context
	config *Config
	// We use this so often we just pre-compute once, mostly for clarity,
	// = time.Duration(config.RoundLength) * time.Milliseconds
	roundLength     time.Duration
	genesisEx       GenesisExtraData
	genesisSealTime time.Time

	// gensisRoundStart is The effective start time of the genesis round.
	// genesisSealTime.Truncate(roundLength)
	genesisRoundStart time.Time

	// Node identity
	privateKey *ecdsa.PrivateKey
	nodeID     Hash // derived from privateKey
	nodeAddr   Address

	vrf ecvrf.VRF
	T   RoundTime

	Rand *rand.Rand
	// Updated in the NewChainHead method
	chainHead            BlockHeader
	chainHeadExtraHeader *ExtraHeader     // genesis & consensus blocks
	chainHeadExtra       *SignedExtraData // consensus blocks only

	// For this consensus, round length is multiple seconds. An int64 is more
	// than big enough.
	chainHeadRound      uint64
	chainHeadSealTime   time.Time
	chainHeadRoundStart time.Time
	// chainHeadRoundStart  time.Time

	Phase RoundPhase

	roundStateMu sync.RWMutex
	// state
	// Any thread can read this via State(), only the engine run thread is
	// allowed to set it. The engine run thread can read it without the lock,
	// but it must hold the lock to update it.
	state RoundState

	Number         uint64
	FailedAttempts uint32

	// Leaders need to automatically re-enrol if they are idle. At the end of
	// the Confirm phase, if a leader candidate receives no endorsements at
	// all, it will set this flag. The re-enrol message is then sent from the
	// end of the broadcast phase. It is sent to all the freshly selected
	// leaders to give the shortest possible latency on the re-enrolment and to
	// ensure we send the enrolment to nodes we know to be live. The fallback
	// is to send to the node that minted the last block.
	reEnrolSelf bool

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

	a ActiveSelection

	// ne worth of indices into the active selection. resampled by
	// setRoundFromTime. SelectCandidatesAndEndorsers is always passed the
	// current slice
	activeSample []int
}

// NewRoundState creates and initialises a RoundState
func NewRoundState(
	codec *CipherCodec, key *ecdsa.PrivateKey, config *Config, logger Logger,
) *EndorsmentProtocol {

	r := &EndorsmentProtocol{
		logger:     logger,
		privateKey: key,
		codec:      codec,

		nodeID:   NodeIDFromPub(codec.c, &key.PublicKey),
		nodeAddr: PubToAddress(codec.c, &key.PublicKey),
		config:   config,
		vrf:      ecvrf.NewSecp256k1Sha256Tai(),
		T:        NewRoundTime(config),

		pendingEnrolments: make(map[Hash]*EnrolmentBinding),

		roundLength:  time.Duration(config.RoundLength) * time.Millisecond,
		activeSample: make([]int, config.Endorsers),
	}

	if logger != nil {
		logger.Trace(
			"RRR NewRoundState - timer durations",
			"round", r.T.Intent+r.T.Confirm+r.T.Broadcast,
			"i", r.T.Intent, "c", r.T.Confirm, "b", r.T.Broadcast)
	}

	return r
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
		extra := hg.GetExtra()
		r.logger.Info("RRR CheckGenesis", "extraData", hex.EncodeToString(extra))
		err := r.codec.DecodeGenesisExtra(extra, &r.genesisEx)
		if err != nil {
			r.logger.Debug("RRR CheckGenesis - decode extra", "err", err)
			return err
		}
		if err := r.genesisSealTime.UnmarshalBinary(r.genesisEx.ChainInit.SealTime); err != nil {
			r.logger.Debug("RRR CheckGenesis - unmarshal seal time", "err", err)
			return err
		}
		r.genesisRoundStart = r.genesisSealTime.Truncate(r.roundLength)
	}
	r.logger.Trace("RRR CheckGenesis", "chainid", r.genesisEx.ChainID.Hex())
	if err := r.checkGenesisExtra(&r.genesisEx); err != nil {
		r.logger.Debug("RRR CheckGenesis", "err", err)
		return err
	}
	r.logger.Debug("RRR CheckGenesis", "genid", r.genesisEx.Enrol[0].ID.Hex())

	return nil
}

func (r *EndorsmentProtocol) StableSeed(chain EngineChainReader, headNumber uint64) (uint64, uint64, error) {
	if r.config.StablePrefixDepth >= headNumber {
		seed, err := ConditionSeed(r.genesisEx.Seed)
		return seed, 0, err
	}
	stableHeader := chain.GetHeaderByNumber(headNumber - r.config.StablePrefixDepth)
	if stableHeader == nil {
		return 0, 0, fmt.Errorf(
			"block at stablePrefixDepth not found: %d - %d", headNumber, r.config.StablePrefixDepth)
	}
	se, _, _, err := r.codec.DecodeHeaderSeal(stableHeader)
	if err != nil {
		return 0, 0, fmt.Errorf("failed decoding stable header seal: %v", err)
	}
	seed, err := ConditionSeed(se.Seed)
	return seed, se.Intent.RoundNumber, err
}

// PrimeActiveSelection should be called for engine Start
func (r *EndorsmentProtocol) PrimeActiveSelection(chain EngineChainReader) error {

	if err := r.CheckGenesis(chain); err != nil {
		return err
	}

	if r.a != nil {
		r.a.Prime(chain.CurrentHeader())
		return nil
	}

	r.a = NewActiveSelection(r.config, r.codec, r.nodeID, r.logger)

	header := chain.CurrentHeader()
	r.a.Reset(header)

	return nil
}

// QueueEnrolment enrols a node id. This enrolment is completely open. The SGX
// identity attestation and the minining identity approaches are not presently
// included.
func (r *EndorsmentProtocol) QueueEnrolment(et *EngEnrolIdentity) {
	r.pendingEnrolmentsMu.Lock()
	defer r.pendingEnrolmentsMu.Unlock()

	eb := &EnrolmentBinding{
		ChainID: r.genesisEx.ChainID,
		NodeID:  Hash(et.NodeID),
		// Round will be updated when we are ready to submit the enrolment. We
		// record it here so we can keep track of how long enrolments have been
		// queued.
		// Block hash filled in when we issue the intent containing this
		// enrolment.

		// XXX: ReEnrol flag is not necessary for non SGX implementations afaict.
		ReEnrol: et.ReEnrol,
	}
	eb.Round = r.Number

	r.pendingEnrolments[et.NodeID] = eb
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

	r.logger.Trace("RRR NewSignedIntent",
		"round", r.Number, "cand-round", et.RoundNumber,
		"candidate", et.NodeID.Hex(), "parent", et.ParentHash.Hex())

	// First check that the local node is an endorser.

	if !r.endorsers[r.nodeAddr] {
		r.logger.Debug(
			"RRR handleIntent - not selected as an endorser, ignoring intent",
			"r", r.Number, "ir", et.RoundNumber, "from-addr", et.NodeID.Address().Hex())
		return
	}

	// Check that the intent round matches our current round.
	if r.Number != et.RoundNumber {
		r.logger.Debug("RRR NewSignedIntent - wrong round",
			"r", r.Number, "ir", et.RoundNumber, "from-addr", et.NodeID.Address().Hex())
		return
	}

	// Small differences in timers mean we may see intents for the 'current'
	// round before we complete the broadcast phase of the previous round. But
	// we can't do anything about that as we don't know the active selection for
	// the next round yet. Instead, in PhaseTick, we do our best not to enter
	// the Intent phase early. This seems to be sufficient. Also, if we are in
	// the Confirmation phase, we have already sent out our endorsement for the
	// round as we have already sent out our endorsements for the round.

	var phaseOffset time.Duration

	if r.Phase != RoundPhaseIntent {

		offset := time.Since(r.genesisRoundStart.Add(time.Duration(r.Number) * r.roundLength))
		switch r.Phase {
		case RoundPhaseConfirm:
			phaseOffset = offset - r.T.Intent
		case RoundPhaseBroadcast:
			phaseOffset = offset - r.T.Intent - r.T.Confirm
		}

		r.logger.Debug(
			"RRR NewSignedIntent - not in intent phase, ignoring",
			"phase", r.Phase.String(), "phaseOffset", phaseOffset, "r", r.Number,
			"r", r.Number, "ir", et.RoundNumber, "candidate", et.NodeID.Address().Hex())

		return
	}

	// Ok, this node is an endorser and in the right phase. Go ahead and
	// consider the details of the intent.
	if err := r.handleIntent(et); err != nil {
		r.logger.Info("RRR handleIntent", "err", err)
	}
}

// handleIntent accepts the intent and queues it for endorsement if the
// intendee is a candidate for the current round.
//  Our critical role here is to always select the *OLDEST* intent we see, and
// to allow a 'fair' amount of time for intents to arrive before choosing one
// to endorse.
func (r *EndorsmentProtocol) handleIntent(et *EngSignedIntent) error {

	var err error

	// Check that the public key recovered from the intent signature matches
	// the node id declared in the intent

	var recoveredNodeID Hash
	if recoveredNodeID, err = r.codec.NodeIDFromPubBytes(et.Pub); err != nil {
		return err
	}
	intenderAddr := et.NodeID.Address()

	if recoveredNodeID != et.NodeID {
		r.logger.Debug("RRR handleIntent - sender not signer",
			"recovered", recoveredNodeID.Hex(), "signed", et.NodeID.Hex(),
			"from-addr", intenderAddr.Hex())
		return nil
	}

	// Check that the intent comes from a node we have selected locally as a
	// leader candidate. According to the (matching) roundNumber
	if !r.candidates[intenderAddr] {
		r.logger.Debug(
			"RRR handleIntent - intent from non-candidate",
			"round", r.Number, "cand", intenderAddr.Hex())
		return nil
	}

	if r.signedIntent != nil {
		// It must be in the map if it was active, otherwise we have a
		// programming error.
		curAge, _ := r.a.AgeOf(r.signedIntent.NodeID.Address())
		newAge, _ := r.a.AgeOf(intenderAddr)

		// Careful here, the 'older' block will have the *lower* number
		if curAge < newAge {
			// current is older
			r.logger.Trace(
				"RRR handleIntent - ignoring intent from younger candidate",
				"cand-addr", intenderAddr.Hex())
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

	if len(r.OnlineEndorsers) == 0 {
		r.intentMu.Unlock()
		return
	}
	err := b.Broadcast(r.nodeAddr, r.OnlineEndorsers, msg)
	r.intentMu.Unlock()
	if err != nil {
		r.logger.Info("RRR BroadcastCurrentIntent - Broadcast", "err", err)
	}
}

// NewSignedEndorsement keeps track of endorsments received from peers. At the
// end of the confirmation phase, in PhaseTick, if we are a leader and our
// *current* intent has sufficient endorsments, we seal the block. This causes
// geth to broad cast it to the network.
func (r *EndorsmentProtocol) NewSignedEndorsement(et *EngSignedEndorsement) {
	// leader <- endorsment from committee
	if r.state != RoundStateLeaderCandidate {
		// This is un-expected. Likely late, or possibly from
		// broken node
		r.logger.Trace("RRR non-leader ignoring engSignedEndorsement", "round", r.Number)
		return
	}

	// Leaders send out their intent at the end of the broadcast phase. Small
	// differences in timings mean it is common for a leader to still be in the
	// intent phase when the first endorsments come  back. Its just not worth
	// trying to compensate for that. If we are in the Broadcast phase it is to
	// late to do anything with it so we do reject that.

	var phaseOffset time.Duration
	if r.Phase != RoundPhaseConfirm && r.Phase != RoundPhaseIntent {
		offset := time.Since(r.genesisRoundStart.Add(time.Duration(r.Number) * r.roundLength))
		// we are in the Broadcast phase.
		phaseOffset = offset - r.T.Intent - r.T.Confirm

		r.logger.Trace("RRR engSignedEndorsement - ignoring endorsement received out of phase",
			"phase", r.Phase.String(), "phaseOffset", phaseOffset, "round", r.Number,
			"endorser", et.EndorserID.Hex(), "intent", et.IntentHash.Hex())
		return
	}

	r.logger.Trace("RRR engSignedEndorsement",
		"round", r.Number,
		"endorser", et.EndorserID.Hex(), "intent", et.IntentHash.Hex())

	// Provided the endorsment is for our outstanding intent and from an
	// identity we have selected as an endorser in this round, then its
	// endorsment will be included in the block - whether we needed it to reach
	// the endorsment quorum or not.
	if err := r.handleEndorsement(et); err != nil {
		r.logger.Info("RRR run handleEndorsement", "err", err)
	}
}

// call with intentMu held
func (r *EndorsmentProtocol) getNumEndorsements() int {
	if r.intent == nil {
		// r.logger.Debug("RRR no outstanding intent")
		return -1
	}
	return len(r.intent.Endorsements)
}

func (r *EndorsmentProtocol) handleEndorsement(et *EngSignedEndorsement) error {

	if et.Endorsement.ChainID != r.genesisEx.ChainID {
		return fmt.Errorf(
			"confirmation received for wrong chainid: %s",
			hex.EncodeToString(et.Endorsement.ChainID[:]))
	}

	r.intentMu.Lock()
	defer r.intentMu.Unlock()

	if r.intent == nil {
		r.logger.Debug(
			"RRR confirmation stale or un-solicited, no current intent",
			"endid", et.Endorsement.EndorserID.Hex(), "hintent",
			et.SignedEndorsement.IntentHash.Hex())
		return nil
	}

	pendingIntentHash, err := r.codec.HashIntent(&r.intent.SI.Intent)
	if err != nil {
		return err
	}

	if pendingIntentHash != et.SignedEndorsement.IntentHash {
		r.logger.Debug("RRR confirmation for stale or unknown intent",
			"pending", pendingIntentHash.Hex(),
			"received", et.SignedEndorsement.IntentHash.Hex())
		return nil
	}

	// Check the confirmation came from an endorser selected by this node for
	// the current round
	endorserAddr := et.SignedEndorsement.EndorserID.Address()
	if !r.endorsers[endorserAddr] {
		r.logger.Debug(
			"RRR confirmation from unexpected endorser", "endorser",
			et.Endorsement.EndorserID[:])
		return nil
	}

	// Check the confirmation is not from an endorser that has endorsed our
	// intent already this round.
	if r.intent.Endorsers[endorserAddr] {
		r.logger.Trace(
			"RRR redundant confirmation from endorser", "endorser",
			et.Endorsement.EndorserID[:])
		return nil
	}

	// Note: *not* copying, engine run owns everything that is passed to it on
	// the runningCh
	r.intent.Endorsements = append(r.intent.Endorsements, &et.SignedEndorsement)
	r.intent.Endorsers[endorserAddr] = true

	if uint64(len(r.intent.Endorsements)) >= r.config.Quorum {
		r.logger.Trace("RRR confirmation redundant, have quorum",
			"endid", et.Endorsement.EndorserID.Hex(),
			"end#", et.SignedEndorsement.IntentHash.Hex(),
			"hintent", et.SignedEndorsement.IntentHash.Hex())
	}

	return nil
}
