package rrr

// This file deals with most leadership aspects of RoundState. Tracking the seal
// task from the miner, soliciting endorsements for it, and ultimately sealing
// the block.

import (
	"encoding/hex"
	"fmt"
	"time"
)

type SealCommitter interface {
	CurrentBlockHash() [32]byte
	CommitSeal([]byte)
	Canceled() bool
}

// EngSealTask is sent to the engines runningCh to request endorsment to
// create a block. This is initiated by the local miner invoking Seal interface
// method.  If the local node is a leader candidate in the current round this
// will result in an Intent being broadcast. Otherwise it will be ignored by
// the engine. The miner will clear un-answered Seal requests when it sees a
// new chain head.
type EngSealTask struct {
	BlockHeader BlockHeader
	Committer   SealCommitter
	// RoundNumber the Seal was requested. Filled in by the endorsment protocol
	// when it retrieves the task of the run queue.
	RoundNumber uint64
}

type pendingIntent struct {
	Candidate    bool
	SI           *SignedIntent
	Alpha        []byte // the seed on the block that will be parent if the intent block is produced
	SealHash     Hash
	RMsg         RMsg
	Msg          []byte
	Endorsements []*SignedEndorsement
	// Endorsers selected when the intent was issued. This map is not updated
	// after it is first created
	Endorsers map[Address]bool
}

// NewSealTask delivers work from the node to be mined. If we are the leader,
// and we are in the intent phase we immediately broadcast our intent. If not,
// we hang on to it until we are or we receive the next one.
func (r *EndorsmentProtocol) NewSealTask(b Broadcaster, et *EngSealTask) {

	r.logger.Trace("RRR engSealTask",
		"state", r.state.String(), "addr", r.nodeAddr.Hex(),
		"r", r.Number)

	et.RoundNumber = r.Number

	// Note: we don't reset the attempt if we get a new seal task.
	if err := r.newSealTask(r.state, et, r.Number); err != nil {
		r.logger.Info("RRR engSealTask - newSealTask", "err", err)
	}

	if r.state == RoundStateLeaderCandidate && r.Phase == RoundPhaseIntent {

		r.logger.Trace(
			"RRR engSealTask - broadcasting intent (new)", "addr", r.nodeAddr.Hex(), "r", r.Number)

		r.broadcastCurrentIntent(b)
	}
}

func (r *EndorsmentProtocol) newSealTask(
	state RoundState, et *EngSealTask, roundNumber uint64,
) error {
	var err error
	r.intentMu.Lock()
	defer r.intentMu.Unlock()

	var newIntent *pendingIntent
	if newIntent, err = r.newPendingIntent(
		et, r.chainHeadExtraHeader.Seed, roundNumber); err != nil {
		return err
	}

	r.intent = newIntent
	r.sealTask = et
	return nil
}

// refreshSealTask will update the current intent to use the provided
// roundNumber. The effects are immediate, if we have already issued an intent
// for this round and we are still in the intent phase, we just issue another.
// Endorsing peers will endorse the *most recent* intent from the *oldest*
// identity they have selected as leader.
func (r *EndorsmentProtocol) refreshSealTask(parentSeed []byte, roundNumber uint64) error {

	var err error
	r.intentMu.Lock()
	defer r.intentMu.Unlock()

	// Establish which, if any, currently known task can be refreshed.

	// Reconcile whether to re-issue current seal task
	if r.sealTask == nil || r.sealTask.Committer.Canceled() {
		r.intent = nil
		r.sealTask = nil
		r.logger.Trace("RRR refreshSealTask - no task")
		return nil
	}

	// The roundNumber has to change in order for the message to be broadcast.
	newIntent, err := r.newPendingIntent(r.sealTask, parentSeed, roundNumber)
	if err != nil {
		return fmt.Errorf("refreshSealTask - newPendingIntent: %v", err)
	}

	// There is no need to send nil to Results on the previous task, the geth
	// miner worker can't do anything with that information
	r.intent = newIntent

	return nil
}

func (r *EndorsmentProtocol) newPendingIntent(
	et *EngSealTask, parentSeed []byte, roundNumber uint64) (*pendingIntent, error) {

	var err error

	r.logger.Trace("RRR newPendingIntent", "r", roundNumber)
	if len(parentSeed) != 32 {
		return nil, fmt.Errorf("parent seed wrong length want 32 not %d", len(parentSeed))
	}

	pe := &pendingIntent{
		Alpha: make([]byte, 32),
		RMsg:  RMsg{Code: RMsgIntent},
	}
	copy(pe.Alpha, parentSeed)

	pe.SealHash = Hash(et.Committer.CurrentBlockHash())

	// The intent that will need to be confirmed by 'q' endorsers in order for
	// this node to mine this block
	pe.SI = &SignedIntent{
		Intent: Intent{
			ChainID:     r.genesisEx.ChainID,
			NodeID:      r.nodeID,
			RoundNumber: roundNumber,
			ParentHash:  Hash(et.BlockHeader.GetParentHash()),
			TxHash:      Hash(et.BlockHeader.GetTxHash()), // the hash is computed by NewBlock
		},
	}

	pe.RMsg.Raw, err = r.codec.EncodeSignIntent(pe.SI, r.privateKey)
	if err != nil {
		return nil, err
	}

	if pe.Msg, err = r.codec.EncodeToBytes(pe.RMsg); err != nil {
		return nil, err
	}

	pe.Endorsements = make([]*SignedEndorsement, 0, r.config.Quorum)
	pe.Endorsers = make(map[Address]bool)

	return pe, nil
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

	if r.Phase != RoundPhaseConfirm {
		r.logger.Trace("RRR engSignedEndorsement - ignoring endorsement received out of phase",
			"round", r.Number,
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

type sealChainReader interface {
	GetHeaderByNumber(number uint64) BlockHeader
}

// call with intentMu held
func (r *EndorsmentProtocol) getNumEndorsements() int {
	if r.intent == nil {
		// r.logger.Debug("RRR no outstanding intent")
		return -1
	}
	return len(r.intent.Endorsements)
}

// verifyEndorsements verifies the endorsements for the current intent.
// ** call with intentMu held
func (r *EndorsmentProtocol) verifyEndorsements() error {

	// All of these error cases indicate getNumEndorsements has not been used
	// correctly
	if r.intent == nil {
		return fmt.Errorf("RRR no outstanding intent")
	}

	if len(r.intent.Endorsements) == 0 {
		return fmt.Errorf("RRR no endorsments received")
	}

	if len(r.intent.Endorsements) < int(r.config.Quorum) {
		return fmt.Errorf("RRR to few endorsments received")
	}

	intentHash, err := r.codec.HashIntent(&r.intent.SI.Intent)
	if err != nil {
		return err
	}

	// Now check all the endorsments are for the intent
	for _, end := range r.intent.Endorsements {
		if intentHash != end.IntentHash {
			return fmt.Errorf(
				"endorsement intenthash mismatch. endid=%s", end.EndorserID.Hex())
		}
	}

	return nil
}

// ** call with intentMu held
func (r *EndorsmentProtocol) generateIntentSeedProof() ([]byte, []byte, error) {
	// The alpha here is always from the block we are building on, which is updated by refreshSealTask
	beta, pi, err := r.vrf.Prove(r.privateKey, r.intent.Alpha)
	if err != nil {
		return nil, nil, fmt.Errorf("failed proving new seed: %v", err)
	}

	return beta, pi, nil
}

// sealCurrentBlock completes the current block sealing task if the node
// has received the confirmations required to mine a block. If this function
// returns true, RRR has entered the "block disemination" phase. Which, in this
// implementation, simply means we have handed that job on to the general miner
// arrangements in geth (and its eth/devp2p machinery). Note that this is
// called on all nodes, only legitemate leader candidates will recieve enough
// endorsments for non-byzantine scenarios.
// ** call with intentMu and pendingEnrolmentsMu held
func (r *EndorsmentProtocol) sealCurrentBlock(beta, pi []byte, chain sealChainReader) error {

	if r.sealTask == nil {
		return fmt.Errorf("no sealTask to seal")
	}

	sealTimeBytes, err := time.Now().UTC().MarshalBinary()
	if err != nil {
		return fmt.Errorf("failed marshaling seal time: %v", err)
	}
	data := &SignedExtraData{
		ExtraData: ExtraData{
			ExtraHeader: ExtraHeader{
				SealTime: sealTimeBytes,
				Seed:     beta,
				Proof:    pi,
				Enrol:    make([]Enrolment, len(r.pendingEnrolments)),
			},
			Intent:  r.intent.SI.Intent,
			Confirm: make([]Endorsement, len(r.intent.Endorsements)),
		},
	}

	for i, c := range r.intent.Endorsements {
		data.Confirm[i] = c.Endorsement
	}

	i := int(0)
	for _, eb := range r.pendingEnrolments {

		// The round and block hash are not known when the enrolment is queued.
		eb.Round = r.Number
		eb.BlockHash = r.intent.SealHash

		u, err := r.codec.HashEnrolmentBinding(eb)
		if err != nil {
			return err
		}
		r.codec.FillEnrolmentQuote(data.Enrol[i].Q[:], u, r.privateKey) // faux attestation
		data.Enrol[i].U = u
		data.Enrol[i].ID = eb.NodeID
		r.logger.Debug("RRR sealCurrentBlock - adding enrolment", "id", eb.NodeID.Hex(), "seal#", eb.BlockHash.Hex(), "u", u.Hex())
		i++
	}
	r.pendingEnrolments = make(map[Hash]*EnrolmentBinding)

	seal, err := r.codec.EncodeSignExtraData(data, r.privateKey)
	if err != nil {
		return err
	}

	r.sealTask.Committer.CommitSeal(seal)

	r.sealTask = nil
	r.intent = nil

	return nil
}
