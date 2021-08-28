package rrr

// Methods which deal with advancing the state live here. Also, ALL methods
// which interact with the round ticker live here.

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math/rand"
	"sort"
	"time"
)

var (
	ErrFutureBlock = errors.New("the time on the head block is in the future with respect to the reference value")
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

	head := chain.CurrentHeader()

	now := time.Now() // use the same now for all time calcs here

	// On startup we see NewChainHead before StartRounds. But for start/stop
	// mining its uncertain.
	r.newChainHead(now, b, chain, head)

	// T(eR) Get the expected start time for the expected round eR
	eR := r.chainHeadRoundStart.Add(time.Duration(int64(r.FailedAttempts)) * r.roundLength)

	// ro = now - T(eR) = offset into expected round
	ro := now.Sub(eR)
	if ro < 0 {
		r.logger.Info("RRR alignRoundState - future block", "ro", ro)
		ro = time.Duration(0)
	}

	r.Phase = RoundPhaseBroadcast // so we start participating in our first round when the startup timer expires
	r.T.Start(ro)
	r.logger.Info("RRR StartRounds", "r", r.Number, "ro", ro)

	r.SetState(RoundStateInactive)
}

// NewChainHead is called to handle the chainHead event from the block chain.
// For a block to make it this far, VerifyHeader and VerifySeal must have seen
// and accepted the block. A 'bad' block here is the result of a programming
// error.
func (r *EndorsmentProtocol) NewChainHead(
	b Broadcaster, chain EngineChainReader, head BlockHeader) {
	r.newChainHead(time.Now(), b, chain, head)
}

// newChainHead is called from NewChainHead and StartRounds. It accepts now as a
// parameter so that some related calculations can work with a single consistent
// instant.
func (r *EndorsmentProtocol) newChainHead(
	now time.Time, b Broadcaster, chain EngineChainReader, head BlockHeader) {

	if r.chainHead != nil && head.Hash() == r.chainHead.Hash() {
		r.logger.Info("RRR newChainHead - setChainHead head known")
		return
	}

	err := r.setChainHead(chain, head)
	if err != nil {
		// This likely means the genesis block is funted (or Start is broken)
		r.logger.Info("RRR newChainHead - setChainHead", "err", err)
		return
	}

	// We have to accumulate active before attempting to update the seed. When
	// we update the seed, we need to sync up the DRGB. And that is depenent on
	// nActive. AccumulateActive is not dependent on the seed, just the block
	// headers.

	// After the rounds have started, we only update the active selection when
	// we get a new block.
	if err = r.accumulateActive(chain, head); err != nil {
		r.logger.Crit("RRR newChainHead - accumulateActive", "err", err)
	}

	err = r.updateStableSeed(now, chain)
	if err != nil {
		r.logger.Crit("RRR newChainHead - updateStableSeed", "err", err)
	}
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
		r.logger.Info("RRR PhaseTick - END OF INTENT .........", "r", r.Number)
		if r.signedIntent != nil {

			oldestSeen := r.signedIntent.NodeID.Address()
			r.logger.Trace(
				"RRR PhaseTick - intent - sending endorsement to oldest seen", "r", r.Number)
			b.SendSignedEndorsement(oldestSeen, r.signedIntent)
			r.signedIntent = nil
		}

		r.logger.Trace(
			"RRR PhaseTick - RoundPhaseIntent -> RoundPhaseConfirm", "r", r.Number)

		r.T.ResetForConfirmPhase()
		r.Phase = RoundPhaseConfirm

	case RoundPhaseConfirm:
		r.logger.Info("RRR PhaseTick - END OF CONFIRM .........", "r", r.Number)
		switch r.state {

		case RoundStateLeaderCandidate:

			r.completeLeaderConfirmPhase(chain)

		case RoundStateInactive:
			r.logger.Debug("RRR PhaseTick", "state", r.state.String())
		}

		// XXX: TODO if we need to do a phase adjustment to aligh with 'now',
		// doing it here lets us use the broadcast phase as an absorber. A
		// particular case we care about is the leap second case.
		r.T.ResetForBroadcastPhase()
		r.Phase = RoundPhaseBroadcast

	case RoundPhaseBroadcast:

		roundBlockArrived := r.Number == r.chainHeadRound

		now := time.Now()

		offset, roundAdvanced := r.setRoundForTime(now)

		// The following factors make it worth dealing with the offset here:
		// 1. The timers are absoloute (monotonic) time so leaps will throw the
		// phase out of whack with respec to the wall clock, as will vanila
		// inaccuracies due to os variasions and load.
		// 2. geth stops the consensus engine while it is synching blocks and
		// restarts at arbirary times (Though we try to account for that in
		// StartRound)

		endConfirm := r.T.Intent + r.T.Confirm
		endRound := endConfirm + r.T.Broadcast
		if roundAdvanced {
			if roundBlockArrived && roundAdvanced {
				// This means the new block arived in the aloted time.
				r.logger.Info("RRR PhaseTick - ROUND SUCCESS ++++++++", "r", r.Number)
			} else {

				var role string
				switch r.state {
				case RoundStateLeaderCandidate:
					role = "leader"
				case RoundStateEndorserCommittee:
					role = "endorser"
				default:
					role = "none"
				}

				r.logger.Info(
					"RRR PhaseTick - ROUND FAILED  xxxxxxxx",
					"r", r.Number, "f", r.FailedAttempts,
					"advanced", roundAdvanced, "newhead", roundBlockArrived, "ro", role)
			}
			r.logger.Info("RRR PhaseTick - END OF ROUND ---------", "r", r.Number)
		} else {

			// The timers can't be perfectly acurate. Sometimes we come up
			// early. The way the round number accounting works (rounding) it is
			// better that we never finish early (relative to the round start)
			r.logger.Debug(
				"RRR PhaseTick - delaying intent phase (fast round)",
				"r", r.Number, "d", endRound-offset)
			r.Phase = RoundPhaseBroadcast
			r.T.Reset(endRound - offset)
			return
		}

		switch {
		case offset < (r.T.Intent*2)/3:
			r.Phase = RoundPhaseIntent
			r.T.Reset(r.T.Intent - offset)
			// This commits to the round states for all nodes candidate, endorser,
			// none. incomming intents are invalid (and ignored) if the source
			// identity is not selected as a confirmer here. A NewChainHead can
			// happen at any time, and it will update the DRGB and so on imediately,
			// but that won't disturb the selections made here.
			r.electAndPropose(b)

		case offset < endConfirm:
			r.Phase = RoundPhaseConfirm
			r.T.Reset(endConfirm - offset)
			r.logger.Debug(
				"RRR PhaseTick - skipped intent phase (catchup)",
				"r", r.Number, "o", offset, "advanced", roundAdvanced)
		case offset <= endRound:
			r.Phase = RoundPhaseBroadcast
			r.T.Reset(endRound - offset)
			r.logger.Debug(
				"RRR PhaseTick - delaying intent phase by (slow round)",
				"r", r.Number, "d", endRound-offset)

		default:
			r.logger.Warn("RRR PhaseTick - round offset to large", "offset", offset, "advanced", roundAdvanced)
		}

		// If we have gone idle, attempt to re-enrol
		r.autoEnrolSelf(b)

	default:
		panic("TODO - recovery")
	}

}

func (r *EndorsmentProtocol) completeLeaderConfirmPhase(chain sealChainReader) {

	r.intentMu.Lock()
	defer r.intentMu.Unlock()
	r.pendingEnrolmentsMu.Lock()
	defer r.pendingEnrolmentsMu.Unlock()

	n := r.getNumEndorsements()
	switch {
	case n < 0:
		r.logger.Debug("RRR no outstanding intent")
		return
	case n < int(r.config.Quorum):
		r.logger.Info("RRR insufficient endorsers to become leader",
			"q", int(r.config.Quorum), "got", n)
		return
	default:
		r.logger.Info("RRR confirmed as leader",
			"q", int(r.config.Quorum), "got", len(r.intent.Endorsements))

		if r.sealTask == nil {
			r.logger.Trace("RRR seal task canceled or discarded")
			return
		}

		err := r.verifyEndorsements()
		if err != nil {
			r.logger.Info("RRR PhaseTick - verifyEndorsements", "err", err)
			return
		}
		beta, pi, err := r.generateIntentSeedProof()
		if err != nil {
			r.logger.Info("RRR PhaseTick - generateIntentSeedProof", "err", err)
			return
		}

		// At this point we expect to have everything we need to seal the block
		// so its an error if we can't
		err = r.sealCurrentBlock(beta, pi, chain)
		if err != nil {
			r.logger.Warn("RRR PhaseTick - sealCurrentBlock", "err", err)
			return
		}
		r.logger.Info(
			"RRR PhaseTick - sealed block", "addr", r.nodeAddr.Hex(), "r", r.Number)
	}
}

// autoEnrolSelf should be called imediately after determing the candidates and
// endorsers for the *new* round (at the begining of the intent phase)
//
// Leaders should automatically re-enrol if they are idle. It is sent to all the
// freshly selected leaders to give the shortest possible latency on the
// re-enrolment and to ensure we send the enrolment to nodes we know to be live.
func (r *EndorsmentProtocol) autoEnrolSelf(b Broadcaster) {

	if r.a.IsActive(r.nodeAddr) && !r.a.IsIdle(r.Number, r.nodeAddr) {
		r.logger.Info("RRR autoEnrolSelf - self is active")
		return
	}

	// Enrolments are included by the leader. The fastest re-enrol is achived
	// by sending our request to all of the leaders for the next round.
	cands := r.a.NOldest(r.Number, int(r.config.Candidates*2))

	if len(cands) == 0 {
		r.logger.Info("RRR PhaseTick - no candidates found to re-enrol self")
		return
	}

	rmsg, err := r.newEnrolIdentityMsg(r.nodeID, true)
	if err != nil {
		r.logger.Info("RRR PhaseTick - encoding auto reenrol msg", "err", err)
	}
	msg, err := r.codec.EncodeToBytes(rmsg)
	if err != nil {
		r.logger.Info("RRR PhaseTick - encoding RMsgEnrol", "err", err.Error())
		return
	}

	m := map[Address]bool{}
	for _, id := range cands {
		if id == r.nodeID {
			continue
		}
		m[id.Address()] = true
	}
	peers := b.FindPeers(m)

	err = b.Broadcast(r.nodeAddr, peers, msg)
	if err != nil {
		r.logger.Info("RRR PhaseTick - Broadcasting RMsgEnrol", "err", err.Error())
		return
	}
	r.logger.Info("RRR PhaseTick - Broadcast RMsgEnrol", "self", r.nodeAddr.Hex())
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
		err = r.chainHeadSealTime.UnmarshalBinary(r.genesisEx.ExtraHeader.SealTime)
		if err != nil {
			return err
		}

	} else {
		r.chainHeadExtra, err = r.readSeal(head)
		if err != nil {
			// This likely means the genesis block is funted (or Start is broken)
			return err
		}

		r.chainHeadExtraHeader = &r.chainHeadExtra.ExtraHeader

		// head seal time is only used for telemetry
		err = r.chainHeadSealTime.UnmarshalBinary(r.chainHeadExtraHeader.SealTime)
		if err != nil {
			return err
		}
	}

	// Establish the round of the chain head. The genesis block is round 0.
	r.chainHeadRound = uint64(0)

	if r.chainHeadExtra != nil { //  nil for genesis round R1
		// For blockclock the intent roundnumber is the block number
		// (checked by VerifyHeader)
		r.chainHeadRound = r.chainHeadExtra.Intent.RoundNumber
	}

	// round number will include the effect of leap seconds
	r.chainHeadRoundStart = r.genesisRoundStart.Add(
		time.Duration(r.chainHeadRound) * r.roundLength)

	return nil
}

func (r *EndorsmentProtocol) accumulateActive(chain EngineChainReader, head BlockHeader) error {

	var err error

	// Establish the order of identities in the round robin selection. Age is
	// determined based on the identity enrolments in the block, and of the
	// identities which enroled blocks - both of which are entirely independent
	// of the number of attempts required to produce a block in any given
	// round.
	if err = r.a.AccumulateActive(
		r.Number, r.genesisEx.ChainID, chain, head); err == nil {
		return nil
	}
	if !errors.Is(err, ErrBranchDetected) {
		r.logger.Info(
			"RRR error while accumulating active identities", "err", err)
		return err
	}

	// re build the whole selection from new head back Ta worth of blocks
	r.a.Reset(head)

	if err := r.a.AccumulateActive(
		r.Number, r.genesisEx.ChainID, chain, head); err == nil {
		return nil
	}

	r.logger.Warn(
		"RRR resetActive failed to recover from re-org", "err", err)
	return err
}

// selectCandidatesAndEndorsers re-samples the active identities and returns
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

	r.logger.Info(
		"RRR ACTIVE SAMPLE >>>>>>>>>",
		"s", r.activeSample, "ns", r.selectionRand.NumSamplesRead(),
		"r", r.Number, "bn", r.chainHead.GetNumber(), "#head", Hash(r.chainHead.Hash()).Hex())

	sort.Ints(r.activeSample)

	// If we are a leader candidate we need to broadcast an intent.
	r.candidates, r.endorsers, err = r.a.SelectCandidatesAndEndorsers(
		r.Number, r.activeSample,
	)
	if err != nil {
		return RoundStateInactive, err
	}

	// How many endorsing peers are online - check this regardles of
	// leadership status.
	r.onlineEndorsers = b.FindPeers(r.endorsers)

	// XXX: TODO if we are not selected as leader, there is no harm in being in
	// RoundStateEndorserCommittee. Also, we may not be able to directly
	// connect in larger networks at all. We may need to adjust this to send to
	// *any* peer so that the gossip can work
	if len(r.onlineEndorsers) < int(r.config.Quorum) {
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

// Called from NewChainHead to align with the random seed for the stable
// ancestor of the new head.
func (r *EndorsmentProtocol) updateStableSeed(
	now time.Time, chain EngineChainReader,
) error {

	roundSeed, _, err := r.StableSeed(chain, r.chainHead.GetNumber().Uint64())
	if err != nil {
		return err
	}
	r.selectionRand = randFromSeed(roundSeed)

	r.FailedAttempts = 0 // because we just set the seed
	r.setRoundForTime(now)

	return nil
}

// setRoundForTime sets the round and the number and aligns the DRGB state and
// returns the duration offset into the current round and a boolean indicating
// if the round has advanced. If the time sealed on the chainHead is ahead of
// now f is set to 0. And a log is emited.
func (r *EndorsmentProtocol) setRoundForTime(now time.Time) (time.Duration, bool) {

	rh := r.chainHeadRound

	newRound := false

	// f is the number of rounds since block produced by round rh according to
	// (now - thead) / rl
	r.FailedAttempts = r.alignFailedAttempts(now, rh, r.FailedAttempts)

	round := rh + uint64(r.FailedAttempts)
	if r.Number != round {

		newRound = true

		r.logger.Info(
			"RRR setRoundForTime - round change",
			"rh", rh, "cur", r.Number, "new", round)
		r.Number = round
	}

	// Calculate the expected start time for the current round and return the
	// duration offset to now.

	// This is robust in the face of leap seconds. The round is calculated from
	// the wall clock time, so eR will include the effect of leaps.

	eR := r.genesisRoundStart.Add(time.Duration(rh+uint64(r.FailedAttempts)) * r.roundLength)

	return now.Sub(eR), newRound
}

// alignFailedAttempts samples the DRGB once for each new failed attempt.  Ie,
// `f - fprevious` times. fprevious should be the last return value from this
// function or 0 if the seed has just been initialised from a new block. f is
// calculated by this function as (now - rh) / roundLength. rh is the start time
// of the round that produced the current head block. leap seconds are
// effectively ignored. As they accumulate they will eventually result in a
// skipped round - which is just a single additional failed attempt.  Note that
// the base time comes from marshaled binary time which omits the monotonic
// clock (as they are not meaningfull accross process boundaries). So the call
// to time.Sub in this function uses wall clock time. Refs for time in
// go:
// 	https://golang.org/pkg/time/#hdr-Monotonic_Clocks
// 	https://go.googlesource.com/proposal/+/master/design/12914-monotonic.md
func (r *EndorsmentProtocol) alignFailedAttempts(
	now time.Time, rh uint64, fprevious uint32, // from current round (or zero if NewChainHead)
) uint32 {

	// failedAttempts since the round that produced the chain heaad is given as:
	//
	// 	f = [ now - T(rh) ] / rl
	//
	// To align the DRGB, we need to evaluate f permutations. For a 'good'
	// round, the block is sealed and broadcast at the end of the confirm phase
	// and arrives *before* the end of the round. This will result in f=0 and R
	// will be the current round.
	//
	// For initialisation, before the first block is produced,
	// chainHeadRoundStart is the timestamp sealed on the genesis block tuncated
	// (rounded down) to the nearest multiple of roundLength.

	rl := r.roundLength
	// 	f = [ now - T(rh) ] / rl

	// This subtraction will use wall clock time as seal time came from a
	// MarshalBinary time - which omits monotonic. We could do now =
	// now.Round(0) but it isn't necessary.
	d := now.Sub(r.chainHeadRoundStart)

	// is the current chain head from the future ?
	if d < 0 {
		r.logger.Info("RRR alignFailedAttempts - future block ?", "d", d, "now", now, "th", r.chainHeadRoundStart)
		return 0
	}

	f := uint32(d / rl)

	r.logger.Trace("RRR alignFailedAttempts", "f", f, "fprevious", fprevious, "delta", f-fprevious)
	if f < fprevious {
		r.logger.Info("RRR alignFailedAttempts - noop, f < fprevious", "f", f, "fprevious", fprevious, "delta", fprevious-f)
		return f
	}

	if f == fprevious {
		r.logger.Trace("RRR alignFailedAttempts - noop, f = fprevious", "f", f)
		return f
	}

	if r.a.NumActive() <= int(r.config.Endorsers) {
		r.logger.Debug(
			"RRR alignFailedAttempts - noop, a < ne",
			"a", r.a.NumActive())
		return f
	}

	var i uint32
	for i = fprevious; i < f-1; i++ {
		r.activeSample = r.a.NextActiveSample(rh+uint64(i+1), r.selectionRand, r.activeSample)
		r.logger.Debug(
			"RRR DRGB CATCHUP  ...........",
			"r", r.Number, "s", r.activeSample,
			"a", r.a.NumActive(), "i", i)
	}

	// Always do one
	r.activeSample = r.a.NextActiveSample(rh+uint64(f), r.selectionRand, r.activeSample)
	r.logger.Debug(
		"RRR DRGB SAMPLE   ...........",
		"r", r.Number, "ns", r.selectionRand.NumSamplesRead(), "s", r.activeSample,
		"a", r.a.NumActive(), "df", f-fprevious, "f", f,
		"th", r.chainHeadRoundStart.Truncate(time.Millisecond).UnixNano(),
		"bn", r.chainHead.GetNumber(), "br", r.chainHeadRound, "#", Hash(r.chainHead.Hash()).Hex())

	return f
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

	if len(r.onlineEndorsers) < int(r.config.Quorum) {
		r.logger.Debug(
			"RRR *** insufficient endorsers online ***", "round", r.Number,
			"addr", r.nodeAddr.Hex(), "err", err)
	}

	// The intent is cleared when the round changes. Here we know we are a
	// leader candidate on the new round, establish our new intent.

	// If there is a current seal task, it will be resused, no matter
	// how long it has been since the local node was a leader
	// candidate.
	if err := r.refreshSealTask(r.chainHeadExtraHeader.Seed, r.Number); err != nil {
		r.logger.Info("RRR newHead refreshSealTask", "err", err)
		return
	}

	r.logger.Trace(
		"RRR broadcasting intent", "addr", r.nodeAddr.Hex(), "r", r.Number)

	// Make our peers aware of our intent for this round, this may get reset by
	// the arival of a new sealing task
	r.broadcastCurrentIntent(b)
}

type drng struct {
	*rand.Rand
	nSamples int
}

func (r *drng) Intn(n int) int {
	sample := r.Rand.Intn(n)
	r.nSamples++
	return sample
}

func (r *drng) NumSamplesRead() int {
	return r.nSamples
}

func randFromSeed(seed uint64) dRNG {
	r := drng{
		Rand: rand.New(rand.NewSource(int64(seed))),
	}
	return &r
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
