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

	r.roundStart = time.Now()
	r.T.Start()

	// We use the intent/confirm phases for the rand initialisation as well as
	// for normal operation.
	r.Phase = RoundPhaseIntent
	r.SetState(RoundStateInactive)

	var err error
	// On error stay up and wait for a block, regardless of round agreement
	// mode, a new block could be the result of a re-org that sorts out our
	// state.

	head := chain.CurrentHeader()
	err = r.setChainHead(chain, head)
	if err != nil {
		r.logger.Warn("RRR StartRounds - setChainHead", "err", err)
		r.SetState(RoundStateNeedBlock)
		return
	}

	// Note: we must do this before calling SelectCandidatesAndEndorsers or
	// AdvanceRandomState, and we *may* call that to catch up the DRGB with
	// failed attempts here
	if err := r.a.AccumulateActive(
		r.genesisEx.ChainID, r.config.Activity, chain, r.chainHead); err != nil {
		r.logger.Warn("RRR StartRounds - AccumulateActive", "err", err)
		r.SetState(RoundStateNeedBlock)
	}

	switch r.config.RoundAgreement {

	case RoundAgreementNTP:

		// Set the round number to the block we would have taken the seed from
		// for the current round, so that we advance the random state acordingly

		r.Number.Set(r.seedRound)
		r.samplesTaken = 0
		r.FailedAttempts = 0 // We reset Number so haven't accounted for any failed attempts since the new Number
		roundNumberNow := RoundsSince(r.genesisSealTime, r.config.RoundLength)
		if roundNumberNow > 0 {
			r.advanceRoundNumber(roundNumberNow - 1)
		}

	case RoundAgreementBlockClock:
		fallthrough
	default:
		r.Number.Add(head.GetNumber(), bigOne)

	}
}

func (r *EndorsmentProtocol) nextActivePermutation() []int {

	nActive := r.a.Len()
	if uint64(nActive) < r.config.Candidates+r.config.Quorum {
		r.logger.Info("RRR nextActivePermutation", "msg",
			fmt.Sprintf("%v < (c)%v + (q)%v, len(idle)=%v: %v",
				nActive, r.config.Candidates, r.config.Quorum, r.a.LenIdle(),
				errInsuficientActiveIdents))

		return nil
	}

	// Get a random permutation of indices into the active list. This is random
	// selection of endorsers *without* replacement (the paper suggests with).
	// Note that the state of the DRGB is advanced nActive - nCandidate times.

	r.samplesTaken += (int(nActive) - int(r.config.Candidates))
	// Note: this samples the state na - nc times
	return r.Rand.Perm(nActive - int(r.config.Candidates))
}

// advanceRoundNumber sets the current round number and accounts for the effect
// of any skipped rounds on the state of the random source.  (as though a full
// SelectCandidatesAndEndorsers was run for each of the skiped rounds). We
// don't need to do this for the blockclock model, just the ntp time based
// rounds.
func (r *EndorsmentProtocol) advanceRoundNumber(roundNumberNow uint64) {

	if roundNumberNow == r.Number.Uint64() {
		r.logger.Warn("round (now) == round (cur)", "rnow", roundNumberNow)
	}

	nActive := r.a.Len()

	if uint64(nActive) < r.config.Candidates+r.config.Quorum {
		r.logger.Info("RRR advanceRoundNumber", "msg",
			fmt.Sprintf("%v < (c)%v + (q)%v, len(idle)=%v: %v",
				nActive, r.config.Candidates, r.config.Quorum, r.a.LenIdle(),
				errInsuficientActiveIdents))

		return
	}

	// Work out the absolute number of failed rounds since we got the last block
	failedAttempts := uint32(0)

	// Advance the random state to account for time being ahead of block
	// production (and/or disemination)

	currentNumber := r.Number.Uint64()
	if currentNumber+1 < roundNumberNow {
		// if roundNumberNow+1 < currentNumber { // + 1 skips the case where we would set failedAttempts to 0

		// Don't attempt to accomodate a change that over flows 4B
		failedAttempts = uint32(roundNumberNow - currentNumber - 1)

		// Don't re sample for failed attempts we have already accounted for.
		if failedAttempts > r.FailedAttempts {
			r.logger.Info(
				"RRR Re-sampling DRGB", "fa", failedAttempts, "a", failedAttempts-r.FailedAttempts)

			for i := uint32(0); i < failedAttempts-r.FailedAttempts; i++ {
				// samples the state na - nc times
				r.Rand.Perm(int(nActive) - int(r.config.Candidates))
				r.samplesTaken += (int(nActive) - int(r.config.Candidates))
			}
		}
	}
	r.FailedAttempts = failedAttempts

	r.Number.SetUint64(roundNumberNow)
}

// NewChainHead is called to handle the chainHead event from the block chain.
// For a block to make it this far, VerifyHeader and VerifySeal must have seen
// and accepted the block. A 'bad' block here is the result of a programming
// error.
func (r *EndorsmentProtocol) NewChainHead(
	b Broadcaster, chain EngineChainReader, head BlockHeader) {

	err := r.setChainHead(chain, head)
	if err != nil {
		// This likely means the genesis block is funted (or Start is broken)
		r.logger.Info("RRR NewChainHead - setChainHead", "err", err)
		r.SetState(RoundStateNeedBlock)
		return
	}

	switch r.config.RoundAgreement {
	case RoundAgreementNTP:

		// New seed, so set the round number to match the seed block then
		// advance the DRGB state as appropriate for the intervening
		// failedAttempts.
		r.Number.Set(r.seedRound)
		r.samplesTaken = 0
		r.FailedAttempts = 0 // We reset Number so haven't accounted for any failed attempts since the new Number
		roundNumberNow := RoundsSince(r.genesisSealTime, r.config.RoundLength)
		r.advanceRoundNumber(roundNumberNow)

		return

	case RoundAgreementBlockClock:
		fallthrough
	default:

		if err := r.accumulateActive(chain, head); err != nil {
			r.SetState(RoundStateNeedBlock)
			return
		}

		// Number = head.number + 1
		r.Number.Add(head.GetNumber(), bigOne)

		// Reset the timer when a new block arrives. This should offer lose
		// synchronisation.  RRR's notion of active and age requires that honest
		// nodes give endorsers a consistent amount of time per round to record
		// their endorsement by signing an intent for the leader. Whether or not
		// the endorsement was required to reach the quorum, the presence of the
		// endorsement in the block header is how RRR determines if non leader
		// nodes are active in a particular round. Note that go timers are quite
		// tricky, see
		// https://blogtitle.github.io/go-advanced-concurrency-patterns-part-2-timers/

		r.T.Stop() // MUST do this here, else reseting the ticker will deadlock
		r.Phase = r.T.PhaseAdjust(r.chainHeadSealTime)
		r.FailedAttempts = 0

		r.logger.Info(
			fmt.Sprintf("RRR new round *** %s ***", r.state.String()),
			"round", r.Number, "phase", r.Phase.String(), "addr", r.nodeAddr.Hex())

		r.electAndPropose(b)
	}
}

// setChainHead updates the chain head state variables *including* the Rand
// source. It should be called when the node starts and for every NewChainHead
// event.
func (r *EndorsmentProtocol) setChainHead(chain EngineChainReader, head BlockHeader) error {

	var err error

	r.chainHead = head

	bigBlockNumber := head.GetNumber()
	blockNumber := bigBlockNumber.Uint64()

	if blockNumber == 0 {
		r.chainHeadExtra = nil
		r.chainHeadExtraHeader = &r.genesisEx.ExtraHeader
	} else {
		r.chainHeadExtra, err = r.readSeal(head)
		if err != nil {
			// This likely means the genesis block is funted (or Start is broken)
			return err
		}
		r.chainHeadExtraHeader = &r.chainHeadExtra.ExtraHeader
	}

	roundSeed, seedRound, err := r.StableSeed(chain, blockNumber)
	if err != nil {
		return err
	}
	r.seedRound.SetUint64(seedRound)

	r.Rand = randFromSeed(roundSeed)

	// Establish the round of the chain head. The genesis block is round 0. Note
	// that the current round r.Number will be >= chainHeadRound + 1 in a
	// healthy network.
	r.chainHeadRound.SetUint64(0)
	if blockNumber > 0 {
		// For blockclock the intent roundnumber is the block number (checked by VerifyHeader)
		r.chainHeadRound.Set(r.chainHeadExtra.Intent.RoundNumber)
	}
	return nil
}

func (r *EndorsmentProtocol) PhaseTick2(b Broadcaster, chain EngineChainReader) {

	switch r.Phase {
	case RoundPhaseIntent:
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

	case RoundPhaseConfirm:
		switch r.state {

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
		r.T.ResetForBroadcastPhase()
		r.Phase = RoundPhaseBroadcast

	case RoundPhaseBroadcast:

		// Was the round successful ? do we have the block from the completed
		// round now ?

		switch r.config.RoundAgreement {
		case RoundAgreementNTP:
			// At this point, even for the first round R1 after genesis, we can
			// require r.chainHeadExtra != nil for a succesful round. But we still
			// need to account for failed attempts and those are likely when
			// initialising a new chain.
			if r.chainHeadExtra == nil || r.chainHeadExtra.Intent.RoundNumber.Cmp(r.Round) != 0 {

				var chainHeadRound *big.Int
				if r.chainHeadExtra != nil {
					chainHeadRound = r.chainHeadExtra.Intent.RoundNumber
				}

				r.logger.Info(
					"RRR PhaseTick - round failed to produce block",
					"chr", chainHeadRound, "r", r.Number, "r - 1 - f", r.Number.Int64()-1-r.FailedAttempt)

				r.FailedAttempts += 1
			}

			r.Number.Add(big1)

		case RoundAgreementBlockClock:
			fallthrough
		default:
			r.FailedAttempts++
		}

		r.Phase = RoundPhaseIntent
		r.T.ResetForIntentPhase()
		r.electAndPropose(b)
	default:
		panic("TODO - recovery")
	}

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

	if r.Phase == RoundPhaseIntent {

		// Completed intent phase, the intent we have here, if any, is the
		// oldest we have seen. This gives us liveness in the face of network
		// issues and misbehaviour. The > Nc the stronger the mitigation.
		// Notice that we DO NOT check if we are currently selected as an
		// endorser.

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

	// Deal with the 'old' state and any end conditions
	switch r.state {

	case RoundStateNeedBlock:
		// The current head block we have is no good to us, or we have
		// an implementation bug.
		r.logger.Warn("RRR PhaseTick", "state", r.state.String())
		r.T.ResetForIntentPhase()
		r.Phase = RoundPhaseIntent
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

	switch r.config.RoundAgreement {
	case RoundAgreementNTP:
		// The round is always based on 'now'
		r.ntpNextRound(b, chain)
	case RoundAgreementBlockClock:
		fallthrough
	default:
		r.blockclockNextRoundAttempt(b, chain)
	}
}

func (r *EndorsmentProtocol) accumulateActive(chain EngineChainReader, head BlockHeader) error {

	// Establish the order of identities in the round robin selection. Age is
	// determined based on the identity enrolments in the block, and of the
	// identities which enroled blocks - both of which are entirely independent
	// of the number of attempts required to produce a block in any given
	// round.
	err := r.a.AccumulateActive(
		r.genesisEx.ChainID, r.config.Activity, chain, head)
	if err == nil {
		return nil
	}
	if !errors.Is(err, ErrBranchDetected) {
		r.logger.Info(
			"RRR error while accumulating active identities", "err", err)
		return err
	}

	// re build the whole selection from new head back Ta worth of blocks
	r.a.Reset(r.config.Activity, head)

	if err := r.a.AccumulateActive(
		r.genesisEx.ChainID, r.config.Activity, chain, head); err == nil {
		return nil
	}
	r.logger.Warn("RRR resetActive failed to recover from re-org", "err", err)
	return err
}

// selectCandidatesAndEndorserse re-samples the active identities and returns
// the round state for the current node according to that sample. To reach the
// shared round state, on receipt of a new block, first run accumulateActive
// then seed the random source and then run nextRoundState once for each
// FailedAttempt on the intent which confirmed the block.
func (r *EndorsmentProtocol) selectCandidatesAndEndorsers(
	b Broadcaster,
) (RoundState, error) {

	var err error

	r.intentMu.Lock()
	defer r.intentMu.Unlock()

	r.signedIntent = nil

	permutation := r.nextActivePermutation()
	r.logger.Info("RRR PERMUTATION >>>>>>>>>>>", "r", r.Number, "p", permutation, "ns", r.samplesTaken)

	// If we are a leader candidate we need to broadcast an intent.
	r.candidates, r.endorsers, r.selection, err = r.a.SelectCandidatesAndEndorsers(
		permutation,
		uint32(r.config.Candidates), uint32(r.config.Endorsers), uint32(r.config.Quorum),
		uint32(r.config.Activity),
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

// RoundsSince returns the number of rounds since the provided time for the
// given round length in seconds.
func RoundsSince(when time.Time, roundLength uint64) uint64 {
	roundDuration := time.Duration(roundLength) * time.Second
	return uint64(time.Since(when) / roundDuration)
}

func RoundsInRange(start time.Time, end time.Time, roundLength uint64) uint64 {
	roundDuration := time.Duration(roundLength) * time.Second
	return uint64(end.Sub(start) / roundDuration)
}

func (r *EndorsmentProtocol) ntpNextRound(b Broadcaster, chain EngineChainReader) {

	roundDuration := time.Duration(r.config.RoundLength) * time.Second
	since := time.Since(r.genesisSealTime)
	roundNumberNow := uint64(since / roundDuration)

	// Note: RoundLength is seconds, so our ideal start should always be a
	// whole second.
	idealStart := r.genesisSealTime.Add(time.Duration(roundNumberNow) * roundDuration)

	if roundNumberNow == r.Number.Uint64() {
		pause := roundDuration - time.Since(idealStart)
		r.logger.Info("ROUND TO FAST - waiting", "w", pause)
		time.Sleep(pause)
		roundNumberNow += 1
		idealStart = r.genesisSealTime.Add(time.Duration(roundNumberNow) * roundDuration)
	}

	// roundNumberNow := RoundsSince(r.genesisSealTime, r.config.RoundLength)
	r.advanceRoundNumber(roundNumberNow)

	r.Phase = r.T.PhaseAdjust(idealStart)
	r.electAndPropose(b)
}

func (r *EndorsmentProtocol) blockclockNextRoundAttempt(b Broadcaster, chain EngineChainReader) {
	r.Phase = RoundPhaseIntent
	r.T.ResetForIntentPhase()
	// We always increment failedAttempts if we reach here. This is the local
	// nodes perspective on how many times the network has failed to produce a
	// block. failedAttempts is reset in newHead. Until we *see* a newHead, we
	// consider the attempt failed even if we seal a block above
	r.FailedAttempts++

	r.electAndPropose(b)
}

// electAndPropose selects the candidates and endorsers and determines the nodes
// participation in the round. If the node is a leader, it will then broadcast
// its intent.
func (r *EndorsmentProtocol) electAndPropose(b Broadcaster) {
	state, err := r.selectCandidatesAndEndorsers(b)
	r.SetState(state) // valid on err
	if err != nil {
		r.logger.Info("RRR startRound - candidate and endorser election", "err", err)
		return
	}

	if r.state != RoundStateLeaderCandidate {
		return
	}

	if r.Phase != RoundPhaseIntent {
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
	if err := r.refreshSealTask(r.chainHeadExtraHeader.Seed, r.Number, r.FailedAttempts); err != nil {
		r.logger.Info("RRR newHead refreshSealTask", "err", err)
		return
	}

	r.logger.Trace(
		"RRR broadcasting intent", "addr", r.nodeAddr.Hex(),
		"r", r.Number, "f", r.FailedAttempts, "t", r.roundStart)

	// Make our peers aware of our intent for this round, this may get reset by
	// the arival of a new sealing task
	r.broadcastCurrentIntent(b)
}

func randFromSeed(seed uint64) *rand.Rand {
	return rand.New(rand.NewSource(int64(seed)))
}

// ConditionSeed takes a 32 byte input and XOR's it into a single uint64
func ConditionSeed(seed []byte) (uint64, error) {
	if len(seed) != 32 {
		return 0, fmt.Errorf(
			"seed wrong length should be 32 not %d", len(seed))
	}

	// XOR combine the 32 byte seed into a single uint64 making it compatible
	// with rand.NewSource
	s := binary.LittleEndian.Uint64(seed[:8])
	for i := 1; i < 4; i++ {
		s ^= binary.LittleEndian.Uint64(seed[i*8 : i*8+8])
	}
	return s, nil
}

func (r *EndorsmentProtocol) readSeal(header BlockHeader) (*SignedExtraData, error) {

	var err error
	var se *SignedExtraData

	blockNumber := header.GetNumber()
	if blockNumber.Cmp(big0) == 0 {
		return nil, fmt.Errorf("the genesis block seal can't be read with this method")
	}

	// First, seed the random sequence for the round from the block seed.
	// There is no RRR seal on the genesis block
	se, _, _, err = r.codec.DecodeHeaderSeal(header)
	if err != nil {
		return nil, fmt.Errorf("RRR readSeal decodeHeaderSeal: %v", err)
	}

	return se, nil
}
