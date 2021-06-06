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
// when it starts up.
func (r *EndorsmentProtocol) StartRounds(b Broadcaster, chain EngineChainReader) {

	var err error
	// On error stay up and wait for a block, regardless of round agreement
	// mode, a new block could be the result of a re-org that sorts out our
	// state.

	head := chain.CurrentHeader()
	err = r.setChainHead(chain, head)
	if err != nil {
		r.logger.Crit("RRR StartRounds - setChainHead", "err", err)
		return
	}

	// AccumulateActive from the current head lR

	// Note: we must do this before calling SelectCandidatesAndEndorsers or
	// AdvanceRandomState, and we *may* call that to catch up the DRGB with
	// failed attempts here
	if err := r.a.AccumulateActive(
		r.genesisEx.ChainID, r.config.Activity, chain, r.chainHead); err != nil {
		r.logger.Crit("RRR StartRounds - AccumulateActive", "err", err)
	}

	roundSeed, seedRound, err := r.StableSeed(chain, r.chainHeadRound.Uint64())
	if err != nil {
		r.logger.Crit("RRR StartRounds", "err", err)
		return
	}
	r.Rand = randFromSeed(roundSeed)

	// failedAttempts since the last known round (or genesis seal) is given as:
	//
	// f = [ now - T(lR) ] / rl
	//
	// To aligh the DRGB, we need to evaluate this many permutations
	rl := r.T.Intent + r.T.Confirm + r.T.Broadcast

	now := time.Now()

	lR := r.chainHeadRound

	f := int32(now.Sub(r.chainHeadSealTime) / rl)

	// T(eR) Get the expected start time for the expected round eR
	teR := r.chainHeadSealTime.Add(lR+f) * rl

	// ro = now - T(eR) = offset into expected round
	ro := now.Sub(teR)

	// Pick the phase for ro
	switch {
	case 0 <= ro < r.T.Intent:
		r.Phase = RoundPhaseIntent
		r.T.StartIntent()
		r.logger.Info("RRR StartRounds - Phase = Intent", "f", f, "ro", ro)
	case r.T.Intent <= ro < r.T.Intent+r.T.Confirm:
		r.Phase = RoundPhaseConfirm
		r.T.StartConfirm()
		r.logger.Info("RRR StartRounds - Phase = Confirm", "f", f, "ro", ro)
	case r.T.Intent+r.T.Confirm <= ro <= r.T.Intent+r.T.Confirm+r.T.Broadcast:
		fallthrough
	default:
		r.Phase = RoundPhaseBroadcast
		r.T.StartBroadcast()
		r.logger.Info("RRR StartRounds - Phase = Broadcast", "f", f, "ro", ro)
	}

	for i := 0; i < f; i++ {
		r.nextActivePermutation()
	}

	r.SetState(RoundStateInactive)

	if r.config.RoundAgreement == RoundAgreementBlockClock {
		r.Number.Add(head.GetNumber(), bigOne)
	}
}

func (r *EndorsmentProtocol) nextActivePermutation() []int {

	// DIVERGENCE (5) we do sample *without* replacement because replacement
	// predjudices the quorum in small networks (and network initialisation)

	nsamples := int(r.config.Candidates + r.config.Endorsers)
	nactive := r.a.Len()

	// This will force select them all active identities when na < ns. na=0
	// is not special.
	if nactive <= nsamples {
		s := make([]int, nsamples)
		for i := 0; i < nsamples; i++ {
			s[i] = i
		}
		return s
	}

	// For efficiency, when na is close to ns, we randomly eliminate indices
	// until we only have nsamples left.
	if nactive < nsamples*2 {

		s := make([]int, nactive)

		for i := 0; i < len(s); i++ {
			s[i] = i
		}

		for len(s) > nsamples {
			rv := r.Rand.Intn(len(s))

			// move selected to end then remove then shorten the slice by 1
			s[rv], s[len(s)-1] = s[len(s)-1], s[rv]
			s = s[:len(s)-1]
		}

		return s
	}

	indices := map[int]bool{}
	s := make([]int, nsamples)
	for i := 0; i < nsamples; i++ {
		var rv int
		for {
			rv = r.Rand.Intn(nactive)
			if indices[rv] {
				continue
			}
			break
		}
		indices[rv] = true
		s[i] = rv
	}
	return s
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
		return
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

	return nil
}

// PhaseTick deals with the time based round state transitions. It MUST be
// called each time a tick is read from the ticker. At the end of the intent
// phase, if an endorser, the oldest seen intent is endorsed. At the end of the
// confirmation phase, if a leader candidate AND the current intent has
// sufficient endorsements, the block for the intent is sealed. Geth will then
// broadcast it.
func (r *EndorsmentProtocol) PhaseTick(b Broadcaster, chain EngineChainReader) {

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
			"RRR PhaseTick - RoundPhaseIntent -> RoundPhaseConfirm",
			"r", r.Number, "f", r.FailedAttempts)

		r.T.ResetForConfirmPhase()
		r.Phase = RoundPhaseConfirm

	case RoundPhaseConfirm:
		switch r.state {

		case RoundStateLeaderCandidate:

			if confirmed, err := r.sealCurrentBlock(chain); confirmed {

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

		// XXX: TODO: what if chainHeadExtra.Intent.RoundNumber in the future
		// or the past at this point ? It is the agreed round according to
		// consensus so presumably we should accept it. If it doesn't agree
		// with our time based notion of round, we should probably (at least)
		// warn, possibly run the ntp sync check, and possibly just enter
		// NeedBlock state

		failedAttempts := uint32(0)

		// At this point, even for the first round R1 after genesis, we can
		// require r.chainHeadExtra != nil for a succesful round. But we still
		// need to account for failed attempts and those are likely when
		// initialising a new chain.
		if r.chainHeadExtra == nil || r.chainHeadExtra.Intent.RoundNumber.Cmp(r.Number) != 0 {

			var chainHeadRound *big.Int
			if r.chainHeadExtra != nil {
				chainHeadRound = r.chainHeadExtra.Intent.RoundNumber
			}

			r.logger.Info(
				"RRR PhaseTick - round failed to produce block",
				"chr", chainHeadRound, "r", r.Number, "r - 1 - f",
				r.Number.Int64()-1-int64(r.FailedAttempts))

			failedAttempts = r.FailedAttempts + 1

		}

		r.FailedAttempts = failedAttempts
		if r.config.RoundAgreement == RoundAgreementNTP {
			r.Number.Add(r.Number, bigOne)
		}

		// If we have 0 failed attempts, then the chainHead is the  new block
		// R-1 for the new round R. Otherwise, we keep the active selection we
		// have. XXX: TODO what do we do with an invalid chain head event ?
		if r.FailedAttempts == 0 {

			if r.config.RoundAgreement == RoundAgreementBlockClock {
				r.Number.Add(r.chainHead.GetNumber(), bigOne)
			}

			roundSeed, seedRound, err := r.StableSeed(chain, r.chainHead.GetNumber().Uint64())
			if err != nil {
				r.SetState(RoundStateNeedBlock)
				r.logger.Info("RRR PhaseTick -> RoundStateNeedBlock", "err", err)
				return
			}

			r.Rand = randFromSeed(roundSeed)

			// Establish the round of the chain head. The genesis block is round 0.
			r.chainHeadRound.SetUint64(0)

			if r.chainHeadExtra != nil { //  nil for genesis round R1
				// For blockclock the intent roundnumber is the block number
				// (checked by VerifyHeader)
				r.chainHeadRound.Set(r.chainHeadExtra.Intent.RoundNumber)
			}
			// Note: this sets chainHeadRound == R-1 with respect to current
			// r.Number at this point

			// Update the active selection from the new head

			if err := r.accumulateActive(chain, r.chainHead); err != nil {
				r.SetState(RoundStateNeedBlock)
				r.logger.Info("RRR PhaseTick -> RoundStateNeedBlock (2)", "err", err)
				return
			}
		}

		r.Phase = RoundPhaseIntent
		r.T.ResetForIntentPhase()
		r.electAndPropose(b)
	default:
		panic("TODO - recovery")
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
