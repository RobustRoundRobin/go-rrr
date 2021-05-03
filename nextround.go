package rrr

// Methods which deal with advancing the state live here. Also, ALL methods
// which interact with the round ticker live here.

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
	"math/rand"
	"time"
)

func (r *EndorsmentProtocol) SetState(state RoundState) RoundState {
	r.roundStateMu.Lock()
	defer r.roundStateMu.Unlock()
	r.state = state
	return r.state
}

func (r *EndorsmentProtocol) State() RoundState {
	r.roundStateMu.RLock()
	defer r.roundStateMu.RUnlock()
	return r.state
}

// StartRounds initialises the current round, establishes the current seed and
// starts the phase ticker. The engine run go routine calls this exactly once
// when it starts up. If the current block is the genesis block and its header
// can't be decoded, we panic.
func (r *EndorsmentProtocol) StartRounds(b Broadcaster, chain EngineChainReader) {

	r.T.Start()

	// We use the intent/confirm phases for the rand initialisation as well as
	// for normal operation.
	r.Phase = RoundPhaseIntent
	r.SetState(RoundStateInactive)

	var err error

	if r.Number, r.Rand, err = r.CurrentRound(chain); err != nil {

		if chain.CurrentHeader().GetNumber().Cmp(big0) == 0 {
			// XXX: TODO: Should we just panic here ? It seems un-recoverable
			// but there may be reasons to keep the node up anyway.
			r.logger.Warn("bad genesis block: %w", err)
		}
		r.SetState(RoundStateNeedBlock)
		return
	}

	if err := r.a.AccumulateActive(
		r.genesisEx.ChainID, r.config.Activity, chain, chain.CurrentHeader()); err != nil {
		r.logger.Warn("RRR StartRounds - AccumulateActive", "err", err)
		r.SetState(RoundStateNeedBlock)
	}
}

// NewChainHead is called to handle the chainHead event from the block chain.
// For a block to make it this far, VerifyHeader and VerifySeal must have seen
// and accepted the block. A 'bad' block here is the result of a programming
// error.
func (r *EndorsmentProtocol) NewChainHead(
	b Broadcaster, chain EngineChainReader, newHeadBlock BlockHeader) {

	var err error
	// Reset the timer when a new block arrives. This should offer lose
	// synchronisation.  RRR's notion of active and age requires that honest
	// nodes give endorsers a consistent amount of time per round to record
	// their endorsement by signing an intent for the leader. Whether or not
	// the endorsement was required to reach the quorum, the presence of the
	// endorsement in the block header is how RRR determines if non leader
	// nodes are active in a particular round. Note that go timers are quite
	// tricky, see
	// https://blogtitle.github.io/go-advanced-concurrency-patterns-part-2-timers/
	r.T.Stop()

	// t.ResetForIntentPhase()
	// roundPhase = RoundPhaseIntent

	var sed *SignedExtraData
	r.Number, r.Rand, sed, err = r.nextRound(chain, newHeadBlock, r.Number)
	if err != nil {
		r.SetState(RoundStateNeedBlock)
		r.logger.Warn("RRR newHead > RoundStateNeedBlock - corruption or bug ?", "err", err)
		return
	}

	// XXX: Make this configurable on/off
	r.Phase = r.T.PhaseAdjust(sed.SealTime)

	r.FailedAttempts = 0
	state, err := r.nextRoundState(b)
	r.SetState(state) // valid on err
	if err != nil {
		r.logger.Info("RRR newHead - nextRoundState", "err", err)
	}

	r.logger.Info(
		fmt.Sprintf("RRR new round *** %s ***", r.state.String()),
		"round", r.Number, "phase", r.Phase.String(), "addr", r.nodeAddr.Hex())

	if r.state != RoundStateLeaderCandidate {
		return
	}

	if len(r.OnlineEndorsers) < int(r.config.Quorum) {
		r.logger.Debug(
			"RRR *** insufficient endorsers online ***", "round", r.Number,
			"addr", r.nodeAddr.Hex(), "err", err)
	}

	// The intent is cleared when the round changes. Here we know we are a
	// leader candidate on the new round, establish our new intent.

	// If there is a current seal task, it will be resused, no matter
	// how long it has been since the local node was a leader
	// candidate.
	if err := r.refreshSealTask(r.Number, r.FailedAttempts); err != nil {
		r.logger.Info("RRR newHead refreshSealTask", "err", err)
		return
	}

	// Make our peers aware of our intent for this round, this may get reset by
	// the arival of a new sealing task
	r.broadcastCurrentIntent(b)
}

// PhaseTick deals with the time based round state transitions. It MUST be
// called each time a tick is read from the ticker. At the end of the intent
// phase, if an endorser, the oldest seen intent is endorsed. At the end of the
// confirmation phase, if a leader candidate AND the current intent has
// sufficient endorsements, the block for the intent is sealed. Geth will then
// broadcast it. Finally, we deal with liveness here. The FailedAttempt counter
// is (almost) always incremented and the endorsers resampled. The exceptions
// are when we are starting and are in RoundStateNodeStarting (normal), and if we
// enter RoundStateNeedsBlock. NeedsBlock means the node will not progress unless
// it sees a new block from the network.
func (r *EndorsmentProtocol) PhaseTick(b Broadcaster, chain EngineChainReader) {

	var confirmed bool
	var err error

	// We MUST reset, else the Stop when a new block arrives will block
	if r.Phase == RoundPhaseIntent {

		// Completed intent phase, the intent we have here, if any, is the
		// oldest we have seen. This gives us liveness in the face of network
		// issues and misbehaviour. The > Nc the stronger the mitigation.
		// Notice that we DO NOT check if we are currently selected as an
		// endorser.
		// XXX: TODO given what we are doing with intents, endorsements and
		// failedAttempts now, I'm not sure having strict intent and
		// confirmation phases makese sense - one 'attempt' phase timer should
		// work just as well.

		if r.state == RoundStateNeedBlock {
			// If we don't have a valid head, we have no buisiness
			// handing out endorsements
			if r.signedIntent != nil {
				r.logger.Trace(
					"RRR PhaseTick - intent -discarding received intent due to round state",
					"r", r.Number, "f", r.FailedAttempts, "state", r.state.String())
				r.signedIntent = nil
			}
		}

		if r.signedIntent != nil {

			oldestSeen := r.signedIntent.NodeID.Address()
			r.logger.Trace(
				"RRR PhaseTick - intent - sending endorsement to oldest seen",
				"r", r.Number, "f", r.FailedAttempts)
			b.SendSignedEndorsement(oldestSeen, r.signedIntent)
			r.signedIntent = nil
		}

		r.logger.Trace(
			"RRR PhaseTick - RoundPhaseIntent -> RoundPhaseConfirm", "r", r.Number, "f", r.FailedAttempts)

		r.T.ResetForConfirmPhase()
		r.Phase = RoundPhaseConfirm
		return
	}

	// completed confirm phase
	r.Phase = RoundPhaseIntent

	// Choosing to include the potential cost of the first call to
	// nextRound in the ticker
	r.T.ResetForIntentPhase()

	// Deal with the 'old' state and any end conditions
	switch r.state {

	case RoundStateNeedBlock:
		// The current head block we have is no good to us, or we have
		// an implementation bug.
		r.logger.Warn("RRR PhaseTick", "state", r.state.String())
		return

	case RoundStateLeaderCandidate:

		if confirmed, err = r.sealCurrentBlock(chain); confirmed {

			r.logger.Info(
				"RRR PhaseTick - sealed block", "addr", r.nodeAddr.Hex(),
				"r", r.Number, "f", r.FailedAttempts)

		} else if err != nil {

			r.logger.Warn("RRR PhaseTick - sealCurrentBlock", "err", err)
		}

	case RoundStateInactive:
		r.logger.Debug("RRR PhaseTick", "state", r.state.String())
	}

	// We always increment failedAttempts if we reach here. This is the local
	// nodes perspective on how many times the network has failed to produce a
	// block. failedAttempts is reset in newHead. Until we *see* a newHead, we
	// consider the attempt failed even if we seal a block above
	r.FailedAttempts++

	state, err := r.nextRoundState(b)
	r.SetState(state)
	if err != nil {
		r.logger.Info("RRR PhaseTick - nextRoundState", "err", err)
	}
	r.logger.Debug("RRR PhaseTick - RoundPhaseConfirm -> RoundPhaseIntent",
		"state", r.state.String(), "addr", r.nodeAddr.Hex(),
		"r", r.Number, "f", r.FailedAttempts)

	// Note: If we just sealed a block (above) then there will be no
	// outstanding intent and refreshSealTask will be a NoOp.  Ultimately, if
	// the block we just sealed doesn't result in a NewChainHead event, we will
	// eventually try again when the failedAttempts counter makes it our turn
	// again. But only if a new task arives. Once we commit to a block seal, we
	// are done with the block regardless of what the network sais about it.
	if r.state == RoundStateLeaderCandidate {
		if err = r.refreshSealTask(r.Number, r.FailedAttempts); err != nil {
			r.logger.Debug("RRR PhaseTick - refreshSealTask", "err", err)
		}

		r.logger.Trace(
			"RRR PhaseTick - broadcasting intent", "addr", r.nodeAddr.Hex(),
			"r", r.Number, "f", r.FailedAttempts)

		r.broadcastCurrentIntent(b)
	}
}

// The roundNumber is always correct, even on err. If err is nil it will be the
// *next* round number, otherwise it will be the round provided by the caller.
func (r *EndorsmentProtocol) nextRound(chain EngineChainReader, head BlockHeader, roundNumber *big.Int) (
	*big.Int, // newRoundNumber
	*rand.Rand, // and seeded deterministic random source
	*SignedExtraData,
	error,
) {
	newRoundNumber, roundSeed, sed, headBlock, err := r.readHead(chain, head)
	if err != nil {
		r.logger.Info("RRR nextRound - failed to readHead", "err", err)
		return roundNumber, nil, nil, err
	}
	if head != nil {
		// Its a block from the network.
		tbloc := time.Unix(int64(head.GetTime()), 0)
		tseal := time.Unix(int64(sed.SealTime), 0)
		tnow := time.Now()

		r.logger.Debug(
			"RRR nextRound - new block",
			"bn", newRoundNumber,
			"l1", tnow.Sub(tseal).Milliseconds(),
			"l2", tnow.Sub(tbloc).Milliseconds(),
			"f", sed.Intent.FailedAttempts,
			"hash", Hash(head.Hash()).Hex())
	}

	roundRand := rand.New(rand.NewSource(int64(roundSeed)))

	bigDiffTmp := big.NewInt(0)

	if bigDiffTmp.Sub(newRoundNumber, roundNumber).Cmp(bigOne) > 0 {
		r.logger.Info(
			"RRR nextRound - skipping round", "cur", roundNumber, "new", newRoundNumber)
	} else if bigDiffTmp.Cmp(big0) < 0 {
		r.logger.Info(
			"RRR nextRound - round moving backwards", "cur", roundNumber, "new", newRoundNumber)
	}

	// Establish the order of identities in the round robin selection. Age is
	// determined based on the identity enrolments in the block, and of the
	// identities which enroled blocks - both of which are entirely independent
	// of the number of attempts required to produce a block in any given
	// round.
	if err := r.a.AccumulateActive(
		r.genesisEx.ChainID, r.config.Activity, chain, headBlock); err != nil {
		if !errors.Is(err, errBranchDetected) {
			r.logger.Info(
				"RRR nextRound - accumulateActive failed", "err", err)
			return nil, nil, nil, err
		}

		// re build the whole selection from new head back Ta worth of blocks
		r.a.Reset(r.config.Activity, headBlock)

		if err := r.a.AccumulateActive(
			r.genesisEx.ChainID, r.config.Activity, chain, headBlock); err != nil {
			r.logger.Warn("resetActive failed to recover from re-org", "err", err)
			return roundNumber, nil, nil, err
		}
	}
	roundNumber.Add(newRoundNumber, bigOne)

	return roundNumber, roundRand, sed, nil
}

func (r *EndorsmentProtocol) CurrentRound(chain EngineChainReader) (
	*big.Int, *rand.Rand, error) {

	headRoundNumber, roundSeed, _, _, err := r.readHead(chain, nil)
	if err != nil {
		return nil, nil, err
	}

	roundRand := rand.New(rand.NewSource(int64(roundSeed)))
	roundNumber := new(big.Int).Add(headRoundNumber, bigOne)

	return roundNumber, roundRand, nil
}

func (r *EndorsmentProtocol) readHead(chain EngineChainReader, head BlockHeader) (
	*big.Int, uint64, *SignedExtraData, BlockHeader, error) {

	if head == nil {
		head = chain.CurrentHeader()
	}

	var err error
	var se *SignedExtraData

	// This implementation of RRR defines the round number as the block number
	blockNumber := head.GetNumber()

	// First, seed the random sequence for the round from the block seed.
	var seed []byte
	if blockNumber.Cmp(big0) > 0 {
		// There is no RRR seal on the genesis block
		se, _, _, err = DecodeHeaderSeal(r.c, r.rlpDecoder, head)
		if err != nil {
			return nil, 0, nil, nil, fmt.Errorf("RRR readHead decodeHeaderSeal: %v", err)
		}

		if se.Intent.RoundNumber.Cmp(blockNumber) != 0 {
			// This should be rejected by VerifyHeader before it reaches the
			// chain.
			return nil, 0, nil, nil, fmt.Errorf(
				"RRR readHead - intent round number %v != block number %v",
				se.Intent.RoundNumber, blockNumber)
		}
		seed = se.Seed
	} else {
		seed = r.genesisEx.ChainInit.Seed
	}

	if len(seed) != 32 {
		return nil, 0, nil, nil, fmt.Errorf(
			"RRR readHead - seed wrong length should be 32 not %d", len(seed))
	}

	// XOR combine the 32 byte seed into a single uint64 making it compatible
	// with rand.NewSource
	s := binary.LittleEndian.Uint64(seed[:8])
	for i := 1; i < 4; i++ {
		s ^= binary.LittleEndian.Uint64(seed[i*8 : i*8+8])
	}

	return blockNumber, s, se, head, nil
}

// nextRoundState re-samples the active identities and returns the round state
// for the current node according to that sample. To reach the shared round
// state, on receipt of a new block, first run accumulateActive then seed the
// random source and then run nextRoundState once for each sampleCount on the
// intent which confirmed the block. It is a programming error if sampleCount < 1
func (r *EndorsmentProtocol) nextRoundState(
	b Broadcaster,
) (RoundState, error) {

	r.intentMu.Lock()
	defer r.intentMu.Unlock()

	r.signedIntent = nil

	// If we are a leader candidate we need to broadcast an intent.
	var err error
	r.candidates, r.endorsers, r.selection, err = r.a.SelectCandidatesAndEndorsers(
		r.Rand.Perm,
		uint(r.config.Candidates), uint(r.config.Endorsers), uint(r.config.Quorum),
		uint(r.config.Activity),
		r.FailedAttempts)
	if err != nil {
		return RoundStateInactive, err
	}

	// How many endorsing peers are online - check this regardles of
	// leadership status.
	r.OnlineEndorsers = b.FindPeers(r.endorsers)

	if len(r.OnlineEndorsers) < int(r.config.Quorum) {
		// XXX: possibly it should be stricter and require e.config.Endorsers
		// online
		return RoundStateInactive, nil
	}

	if !r.candidates[r.nodeAddr] {
		if !r.endorsers[r.nodeAddr] {
			return RoundStateActive, nil // XXX: everyone is considered active for now
		}
		return RoundStateEndorserCommittee, nil
	}
	r.intent = nil

	return RoundStateLeaderCandidate, nil
}
