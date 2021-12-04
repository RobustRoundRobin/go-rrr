package rrr

import (
	"fmt"
	"sort"
)

type activity struct {
	config         *Config
	codec          *CipherCodec
	idleRoundLimit uint64
	selfNodeID     Hash

	// active is the map of all enroled identities. identities are removed fro
	// this map if the don't enrol a block at least once in the activity
	// threshold Ta rounds. Or if they are a leader candidate and fail to
	// produce a block within Nc rounds (if we are applying that rule)
	active map[Address]*Participant
	aged   []*Participant

	lastBlockSeen    Hash
	activeBlockFence uint64
	logger           Logger
}

func NewActiveSelection3(
	config *Config, codec *CipherCodec, selfNodeID Hash, logger Logger) ActiveSelection {
	a := &activity{
		config:     config,
		codec:      codec,
		selfNodeID: selfNodeID,
		logger:     logger,
	}
	a.idleRoundLimit = a.config.MinIdleAttempts
	if a.config.Candidates > a.config.MinIdleAttempts {
		a.idleRoundLimit = a.config.Candidates
	}
	logger.Debug("RRR NewActiveSelection3", "idleRoundLimit", a.idleRoundLimit)

	return a
}

func (a *activity) AccumulateActive(
	roundNumber uint64, chainID Hash, chain BlockHeaderReader, head BlockHeader,
) error {
	var err error

	if head == nil {
		return nil
	}
	headHash := Hash(head.Hash())

	blockActivity := BlockActivity{}
	var headActivity BlockActivity

	depth := uint64(0)
	bigHeadNumber := head.GetNumber()
	headNumber := bigHeadNumber.Uint64()
	cur := head

	// Record activity of all blocks until we reach the genesis block or
	// until we reach a block we have recorded already. We are traversing
	// 'youngest' block to 'oldest'. We remember the last block seen on the
	// last traversal and use it as our end condition.
	for {

		h := Hash(cur.Hash())
		if h == headHash {
			headActivity = blockActivity
		}

		// The seal hash must be used to verify enrolments as the enrolements are
		// contained in the extra data and obviously cant reference the full
		// hash of the block header they are delivered in.
		hseal := cur.HashForSeal()

		// Reached the last block we updated for, we are done
		if h == a.lastBlockSeen {
			a.logger.Trace("RRR accumulateActive - complete, reached last seen", "#", h.Hex())
			break
		}

		var curRound uint64
		if curRound, err = cur.GetRound(a.codec); err != nil {
			return fmt.Errorf("bad seal, failed to decode: %w", err)
		}

		// If we have exceeded the Ta depth horizon we are done. Note we do this
		// directly on the number in the header and the activity, rather than
		// relying on the cached activeBlockFence.
		curNumber := cur.GetNumber().Uint64()
		depth = 0
		if headNumber > curNumber {
			depth = headNumber - curNumber
		}

		if depth >= a.config.Activity || curNumber > headNumber {
			a.logger.Trace("RRR accumulateActive - complete, reached activity depth", "Ta", a.config.Activity)
			break
		}

		// Now we look at the activeBlockFence. If the number is at or beyond
		// the fence and we haven't matched the hash yet it means we have a
		// chain re-org. The exception accommodates the first pass after node
		// startup.
		if a.lastBlockSeen != zeroHash && curNumber <= a.activeBlockFence && headNumber != 0 {
			// re-orgs are fine provided verifyBranch is working, but we can't
			// deal with them sensibly here. The expectation is that everything
			// in aged gets moved to idles then we re-run accumulateActive to
			// re-order the whole list.
			return fmt.Errorf(
				"reached a lower block without matching hash of last seen, head-bn=%v, head-#=%s: %w",
				headNumber, head.Hash(), ErrBranchDetected)
		}

		if err = a.codec.DecodeBlockActivity(&blockActivity, chainID, cur); err != nil {
			return err
		}

		a.logSealerAge(cur, &blockActivity)

		// Do any enrolments. (Re) Enrolling an identity moves it to the
		// youngest position in the activity set
		a.enrolIdentities(
			chainID, blockActivity.SealerID, blockActivity.SealerPub, blockActivity.Enrol,
			h, hseal, curNumber, curRound)

		// The sealer is the oldest of those identities active for this block and so is added last.
		a.refreshAge(blockActivity.SealerID, h, curNumber, curRound, 0)

		// The endorsers are active, they do not move in the age ordering.
		// Note however, for any identity enrolled after genesis, as we are
		// walking youngest -> oldest we may/probably will encounter
		// confirmations before we see the enrolment. For that to happen, the
		// identity must have been enrolled within Ta of this *cur* block else
		// it could not have been selected as an endorser. However, it may not
		// be within Ta of where we started accumulateActive
		for _, end := range blockActivity.Confirm {
			// xxx: should probably log when we see a confirmation for an
			// enrolment we haven't had yet, that is 'interesting'
			a.recordActivity(end.EndorserID, h, curNumber, curRound)
		}

		// a.logger.Trace("RRR accumulateActive - parent", "cur", cur.Hash(), "parent", cur.GetParentHash())
		parentHash := Hash(cur.GetParentHash())
		if parentHash == zeroHash {
			a.logger.Debug("RRR accumulateActive - complete, no more blocks")
			break
		}

		cur = chain.GetHeaderByHash(parentHash)

		if cur == nil {
			return fmt.Errorf("block #`%s' not available locally", parentHash.Hex())
		}
	}

	a.lastBlockSeen = headHash
	a.activeBlockFence = headNumber

	// deal with idles
	activeHorizon := uint64(0)
	if headNumber > a.config.Activity {
		activeHorizon = headNumber - a.config.Activity
	}

	a.logger.Trace(
		"RRR AccumulateActive - for block", "r", roundNumber, "hr", headActivity.RoundNumber,
		"a", len(a.active), "bn", headNumber, "#", headHash.Hex())

	a.aged = a.sortedByAgeExcluding(nil)

	// Deal with culling of idles do to lack of activity. activity means
	// producing a block or endorsing a block.  We chose do this based on the
	// block number the activity was recorded for (the :paper: is a little
	// ambiguous on this point). This makes network startup, consensus restart,
	// and recovery from long periods of network inavailability much cleaner. If
	// the network is not active, blocks are not produced by any candidate, and
	// liveness is not going to be improved by removing identities from the
	// active set. This means the only way for the active set to diverge based
	// on time (rather than block height) is due to the application of the
	// oldest for rule to the oldest candidate in successive calls to
	// SelectCandidates

	var i int
	var p *Participant
	for i, p = range a.aged {

		addr := p.nodeID.Address()
		lastActiveBlock := p.ageBlock
		if p.endorsedBlock > p.ageBlock {
			lastActiveBlock = p.endorsedBlock
		}

		if lastActiveBlock >= activeHorizon {
			break
		}

		if len(a.active) < int(a.config.Candidates)+int(a.config.Endorsers) {
			a.logger.Trace("RRR AccumulateActive - aborting activity horizon cull (only nc+ne left)")
			break
		}

		a.logger.Trace("RRR AccumulateActive - identity fell below activity horizon",
			"gi", p.genesisOrder, "end", p.endorsedBlock,
			"last", p.ageBlock, "id", addr.Hex())

		delete(a.active, p.nodeID.Address())
	}
	a.aged = a.aged[i:]

	return nil
}

func (a *activity) NOldest(roundNumber uint64, n int) []Address {
	if n == 0 {
		return nil
	}
	oldest := make([]Address, 0, n)
	for _, p := range a.aged {
		oldest = append(oldest, p.nodeID.Address())
		if len(oldest) == n {
			break
		}
	}
	return oldest
}

func (a *activity) NextActiveSample(roundNumber uint64, source DRNG, s []int) []int {

	nactive := a.NumActive()

	nsamples := len(s)

	// This will force select them all active identities when na <= ns. na=0
	// is not special.
	if nactive <= nsamples {
		a.logger.Trace("RRR NextActiveSample - returning identity sample, to few active", "a", a.NumActive(), "ns", nsamples)
		for i := 0; i < nsamples; i++ {
			s[i] = i
		}
		return s
	}

	return RandSampleRange(source, nactive, s)
}

func (a *activity) SelectCandidatesAndEndorsers(
	roundNumber uint64, permutation []int,
) (map[Address]bool, map[Address]bool, error) {

	Nc := int(a.config.Candidates)
	Ne := int(a.config.Endorsers)

	if len(a.active) < (Nc + int(a.config.Quorum)) {
		return nil, nil, fmt.Errorf("insufficient active identities")
	}

	candidates := make(map[Address]bool)
	endorsers := make(map[Address]bool)

	for i, p := range a.aged {

		if i >= Nc {
			break
		}

		// if we don't have at least Nc+Ne endorsers don't apply the idles rule.
		if len(a.active) <= (int(a.config.Candidates) + int(a.config.Endorsers)) {
			candidates[p.nodeID.Address()] = true
			continue
		}

		// oldestFor idle rule
		if !p.oldestForIdleRule(i, roundNumber, a.idleRoundLimit) {
			candidates[p.nodeID.Address()] = true
			continue
		}

		delete(a.active, p.nodeID.Address())
		a.logger.Debug(
			"RRR selectCandEs - dropped idle leader",
			"cand", fmt.Sprintf("%s:%05d.%02d", p.nodeID.Address().Hex(), p.ageBlock, p.genesisOrder),
			"r", roundNumber, "ar", p.ageBlock,
		)
	}

	byid := a.sortedByIdExcluding(candidates)

	mperm := map[int]bool{}
	for _, i := range permutation {
		mperm[i] = true
	}

	// permutation is over the range [0, len(a.active) - Nc] and we excluded
	// the candidates in the sort. we error above for a.active being to short
	for i, p := range byid {
		if !mperm[i] {
			continue
		}
		if len(endorsers) >= Ne {
			break
		}
		endorsers[p.nodeID.Address()] = true
	}

	return candidates, endorsers, nil
}

func (a *activity) Reset(head BlockHeader) {
	a.active = make(map[Address]*Participant)
	a.lastBlockSeen = Hash{}
	a.activeBlockFence = 0
	a.Prime(head)
}

func (a *activity) Prime(head BlockHeader) {

	// Note: block sync will stop the consensus. On re-start this will discard
	// the current activeSelection. So we also need to reset the last block hash seen.

	// If we have just started up. Position lastBlockSeen such that it
	// encompasses the block range required by Ta 'active'. This ensures we
	// always warm up our picture of activity consistently. See
	// selectCandidatesAndEndorsers

	// horizon = head - activity

	horizon := uint64(0)
	headNumber := head.GetNumber().Uint64()

	if headNumber > a.config.Activity {
		horizon = headNumber - a.config.Activity
	}

	a.activeBlockFence = horizon

	// Notice that we _do not_ record the hash here, we leave that to
	// accumulateActive, which will then correctly deal with collecting the
	// 'activity' in the genesis block.
}

func (a *activity) AgeOf(nodeAddr Address) (uint64, bool) {
	if p, ok := a.active[nodeAddr]; ok {
		return p.ageBlock, true
	}
	return 0, false
}

func (a *activity) NumActive() int {
	return len(a.active)
}

func (a *activity) IsActive(_ uint64, addr Address) bool {
	_, ok := a.active[addr]
	return ok
}

// recordActivity is called for a node to indicate it is active in the current
// round.
func (a *activity) recordActivity(nodeID Hash, endorsed Hash, blockNumber, roundNumber uint64) *Participant {

	var p *Participant
	nodeAddr := nodeID.Address()

	if p = a.active[nodeAddr]; p == nil {
		p = &Participant{
			nodeID: nodeID,
		}
		a.active[nodeAddr] = p
	}
	p.endorsedBlock = blockNumber
	p.endorsedRound = roundNumber

	return p
}

func (a *activity) enrolIdentities(
	chainID Hash, sealerID Hash,
	sealerPub []byte, enrolments []Enrolment, block Hash, blockSeal Hash, blockNumber, roundNumber uint64,
) error {

	enbind := EnrolmentBinding{}

	// Gensis block can't refer to itself
	if roundNumber > 0 {
		enbind.ChainID = chainID
		enbind.Round = roundNumber
		enbind.BlockHash = blockSeal
	}

	verifyEnrolment := func(e Enrolment, reEnrol bool) (bool, error) {

		enbind.NodeID = e.ID
		enbind.ReEnrol = reEnrol

		u, err := a.codec.HashEnrolmentBinding(&enbind)
		if err != nil {
			return false, err
		}
		if u != e.U {
			// We try with and without re-enrolment set, so hash match isn't an
			// error
			return false, nil
		}

		// Did the block sealer sign the indidual enrolment.
		if !a.codec.c.VerifySignature(sealerPub, u[:], e.Q[:64]) {
			a.logger.Debug("RRR enrolIdentities - verify failed",
				"sealerID", sealerID.Hex(), "e.ID", e.ID.Hex(), "e.U", e.U.Hex())
			return false, fmt.Errorf("sealer-id=`%s',id=`%s',u=`%s':%w",
				sealerID.Hex(), e.ID.Hex(), u.Hex(), errEnrolmentNotSignedBySealer)
		}

		// XXX: We ignore the re-enrol flag for now. Strictly, if re-enrol is
		// false we need to ensure that the identity is genuinely new.
		// if !reEnrol {

		return true, nil
	}

	// The 'youngest' enrolment in the block is the last in the slice.
	for i := 0; i < len(enrolments); i++ {

		// Note that the "oldest" order for an enrolee is 1. The block sealer
		// gets order = 0
		order := len(enrolments) - i // the last enrolment is the youngest
		enr := enrolments[order-1]

		// the usual case once we are up and running is re-enrolment so we try
		// it first.
		var ok bool
		var err error

		if ok, err = verifyEnrolment(enr, true); err != nil {
			return err
		}
		if !ok {
			if ok, err = verifyEnrolment(enr, false); err != nil {
				return err
			}
		}
		if !ok {
			return fmt.Errorf("sealer-id=`%s',id=`%s',u=`%s':%w",
				sealerID.Hex(), enr.ID.Hex(), enr.U.Hex(), errEnrolmentInvalid)
		}

		// For the genesis block sealer id is also the first enroled identity.
		// The sealer age is refreshed directly in AccumulateActive. But note
		// that we still apply all the verification
		if sealerID == enr.ID {
			a.logger.Trace(
				"RRR enrolIdentities - sealer found in enrolments",
				"bn", blockNumber, "r", roundNumber, "#", block.Hex())
			continue
		}
		a.logger.Debug("RRR enroled identity", "id", enr.ID.Hex(), "o", order, "bn", blockNumber, "r", roundNumber, "#", block.Hex())

		a.refreshAge(enr.ID, block, blockNumber, roundNumber, order)
	}
	return nil
}

// refreshAge called to indicate that nodeID has minted a block or been
// enrolled.
func (a *activity) refreshAge(
	nodeID Hash, block Hash, blockNumber, roundNumber uint64, order int,
) {
	nodeAddr := nodeID.Address()

	var p *Participant

	if p = a.active[nodeAddr]; p == nil {
		p = &Participant{nodeID: nodeID}
		a.active[nodeAddr] = p
	}

	if p.ageBlock <= blockNumber {
		p.ageBlock = blockNumber
		p.order = order
	}

	if p.ageRound <= roundNumber {
		p.ageRound = roundNumber
	}

	if blockNumber == 0 {
		p.genesisOrder = order
	}
}

func (a *activity) sortedByAgeExcluding(excluding map[Address]bool) []*Participant {
	s := make([]*Participant, 0, len(a.active))
	for _, p := range a.active {
		if excluding[p.nodeID.Address()] {
			continue
		}
		s = append(s, p)
	}
	sort.Sort(ParticipantByAge(s))
	return s
}

func (a *activity) sortedByIdExcluding(excluding map[Address]bool) []*Participant {
	s := make([]*Participant, 0, len(a.active))
	for _, p := range a.active {
		if excluding[p.nodeID.Address()] {
			continue
		}
		s = append(s, p)
	}
	sort.Sort(ParticipantByID(s))
	return s
}

func (a *activity) logSealerAge(cur BlockHeader, blockActivity *BlockActivity) {

	a.logger.Debug("RRR accumulateActive - sealer",
		"addr", a.logger.LazyValue(func() string { return blockActivity.SealerID.Address().HexShort() }),
		"age", a.logger.LazyValue(func() string {
			curNumber := cur.GetNumber().Uint64()
			if sealer := a.active[blockActivity.SealerID.Address()]; sealer != nil {
				return fmt.Sprintf("%05d.%02d", curNumber, sealer.order)
			}
			return fmt.Sprintf("%05d.--", curNumber)
		}),
	)
}
