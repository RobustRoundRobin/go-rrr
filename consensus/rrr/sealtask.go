package rrr

// This file deals with most leadership aspects of RoundState. Tracking the seal
// task from the miner, soliciting endorsements for it, and ultimately sealing
// the block.

import (
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

	r.logger.Trace("RRR engSealTask", "r", r.Number,
		"state", r.state.String(), "self", r.nodeAddr.Hex())

	et.RoundNumber = r.Number

	// Note: we don't reset the attempt if we get a new seal task.
	if err := r.newSealTask(r.state, et, r.Number); err != nil {
		r.logger.Info("RRR engSealTask - newSealTask", "r", r.Number, "self", r.nodeAddr.Hex(), "err", err)
	}

	if r.state == RoundStateLeaderCandidate && r.Phase == RoundPhaseIntent {

		r.logger.Info(
			"RRR engSealTask - broadcasting intent (new)", "r", r.Number, "self", r.nodeAddr.Hex())

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

	if r.intent != nil && len(r.intent.Endorsements) > 0 {
		var curCancelled bool
		if r.sealTask != nil {
			curCancelled = r.sealTask.Committer.Canceled()
		}
		r.logger.Info(
			"RRR new seal task discarding previous endorsments", "r", r.Number, "self", r.nodeAddr.Hex(), "n", len(r.intent.Endorsements), "cur-canceled", curCancelled)
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
		r.logger.Info("RRR refreshSealTask - no task or task canceled")
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

	pe.Endorsements = make([]*SignedEndorsement, 0, r.config.Quorum)
	pe.Endorsers = make(map[Address]bool)

	return pe, nil
}

type sealChainReader interface {
	GetHeaderByNumber(number uint64) BlockHeader
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

	sealTime := time.Now()

	sealTimeBytes, err := sealTime.UTC().MarshalBinary()
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

		// Because the idling of leaders is pretty strict, we make nodes enrol
		// automaticaly on startup. We don't want the noise of redundant
		// enrolments in the block headers so we just filter them out.

		addr := eb.NodeID.Address()

		if r.a.IsActive(r.Number, addr) {
			r.logger.Debug(
				"RRR sealCurrentBlock - ignoring redundant enrolment",
				"node", eb.NodeID.Hex(), "addr", addr.Hex())
			continue
		}

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
		r.logger.Debug("RRR sealCurrentBlock - adding enrolment", "id", eb.NodeID.Address().Hex(), "seal#", eb.BlockHash.Hex(), "u", u.Hex())
		i++
	}
	r.pendingEnrolments = make(map[Hash]*EnrolmentBinding)

	seal, err := r.codec.EncodeSignExtraData(data, r.privateKey)
	if err != nil {
		return err
	}

	r.sealTask.Committer.CommitSeal(seal)
	due := time.Unix(int64(r.sealTask.BlockHeader.GetTime()), 0)
	delta := time.Since(due)
	r.logger.Info(
		"RRR sealed block",
		"r", r.Number,
		"rs", data.Intent.RoundNumber, // r and rs should be equal
		"bn", r.sealTask.BlockHeader.GetNumber(),
		"delta", delta,
		"due", due,
		"sealed", sealTime.UTC(),
		"sealer", r.nodeAddr.Hex(),
		"#", Hash(r.sealTask.BlockHeader.Hash()).Hex())

	r.sealTask = nil
	r.intent = nil

	return nil
}
