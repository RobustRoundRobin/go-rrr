package rrr

// This file deals with the age ordering of identities and their selection as
// leader candidates or intent endorsers. And in particular covers 5.1
// "Candidate and Endorser Selection" from the paper.

import (
	"container/list"
	"errors"
	"fmt"
	"math/big"
	"sort"
	"strings"
)

var (
	errEnrolmentInvalid           = errors.New("identity enrolment could not be verified")
	errGensisIdentitiesInvalid    = errors.New("identities in genesis extra are invalid or badly encoded")
	errEnrolmentNotSignedBySealer = errors.New("identity enrolment was not indidualy signed by the block sealer")
	ErrBranchDetected             = errors.New("branch detected")
	errPermutationInvalidLength   = errors.New("permutation count must match ne (n endorsers)")
	big0                          = big.NewInt(0)
	zeroAddr                      = Address{}
	zeroHash                      = Hash{}
)

type ActiveSelection interface {

	// AccumulateActive should be called each time a new block arrives to
	// maintain the active selection of candidates and endorsers.
	AccumulateActive(
		roundNumber uint64, chainID Hash, chain BlockHeaderReader, head BlockHeader,
	) error
	NumActive() int

	NOldest(roundNumber uint64, n int) []Address

	NextActiveSample(roundNumber uint64, source DRNG, s []int) []int

	// SelectCandidatesAndEndorsers should be called once a round with a fresh
	// permutation of indices into the active selection. There must be exactly
	// nEndorsers worth of indices.
	SelectCandidatesAndEndorsers(
		roundNumber uint64, permutation []int,
	) (map[Address]bool, map[Address]bool, error)

	// Reset resets and primes the active selection such that head - ta is the
	// furthest back the next selection will look
	Reset(head BlockHeader)

	// Prime primes the active selection such that the next selection will look as
	// far back as head - ta but no further
	Prime(head BlockHeader)

	// AgeOf returns the age of the identity. The boolean return is false if the
	// identity is not active.
	AgeOf(nodeID Address) (uint64, bool)

	IsActive(roundNumber uint64, addr Address) bool
}

func NewActiveSelection(
	config *Config, codec *CipherCodec, selfNodeID Hash, logger Logger) ActiveSelection {
	a := &activeList{
		config:     config,
		codec:      codec,
		selfNodeID: selfNodeID,
		logger:     logger,
	}
	a.idleRoundLimit = a.config.MinIdleAttempts
	if a.config.Candidates > a.config.MinIdleAttempts {
		a.idleRoundLimit = a.config.Candidates
	}

	return a
}

// idActivity is used to cache the 'age' and 'activity' of RRR identities.
//
// * In normal operation 'age' is the number of blocks since an identity last minted
// * When an identity is first enrolled, and so has not minted yet, 'age' is
//   number of blocks since they were enrolled.
// * A node is 'active' in the round (block) that enrolled (or re-enrolled) it.
// * A node is 'active' in any round (block) that it signed an intent endorsement in.
//
// 	"In case multiple candidates have the same age (i.e., they were enrolled in
// 	the same block), we choose the oldest candidate in the order their
// 	enrollment messages appear in the block. If an endorser receives intent
// 	messages that refer to more than one chain branches, the endorser picks the
// 	branch to confirm using Select Branch" -- 5.2 Endorsment
type idActivity struct {

	// nodeID is the 'identity'
	nodeID Hash

	// ageHash is the hash of last block minited by the identity
	ageHash Hash

	// ageBlock is the number of the block most recently minted by the
	// identity OR the block the identity was enrolled on - udpated by
	// esbalishAge
	ageBlock uint64

	// ageRound is the round number the idenity was most recently active in - as per ageBlock
	ageRound uint64

	// endorsedHash is the hash of the block most recently endorsed by the
	// identity
	endorsedHash Hash

	// endorsedBlock is the number of the block most recently endorsed by the
	// identity
	endorsedBlock uint64
	// endorsedRound is the round number that produced the last block endorsed
	// by the identity.
	endorsedRound uint64

	// order in the block that the identities enrolment appeared.  The first
	// time an identity is selected, it has not minted so it is conceivable
	// that its 'age' is the same as another leader candidate (because they
	// were enrolled on the same block and they both have not minted). In this
	// case, the order is the tie breaker. Once the identity mints, order is
	// set to zero. order is initialised to zero for the genesis identity.
	order int

	// genesiOrder is for telemetry, it is (or will be) undefined for nodes
	// whose initial enrol is not in the genesis block.
	genesisOrder int
}

// activeList tracks the active identities and facilitates ordering them by
// age.
type activeList struct {
	config *Config
	codec  *CipherCodec

	// activeSelection  is maintained in identity age order - with the youngest at
	// the front.
	activeSelection *list.List                // list of *idActive
	aged            map[Address]*list.Element // map of NodeID.Addresss() -> Element in active

	// Because AccumulateActive processes the chain from HEAD -> genesis, we can
	// encounter endorsments before we see the enrolment. To accomodate this we
	// put 'new' identity activity into the newPool. Then IF we encounter the
	// enrolment within Ta of HEAD we move it to the activeSelection
	newPool map[Address]*idActivity

	// When updating activity, we walk back from the block we are presented
	// with. We ERROR if we reach a block number lower than activeBlockFence
	// without matching the hash - that is a branch and we haven't implemented
	// SelectBranch yet.
	lastBlockSeen    Hash
	activeBlockFence uint64

	idleRoundLimit uint64

	// lastOldest is the id of the identity at the oldest position after the
	// last call to AccumulateActive.
	lastOldest Address
	// becameOldest is the round that lastOldest was set by AccumulateActive
	becameOldest uint64

	selfNodeID Hash // for logging only
	logger     Logger
}

// enumeration and access

func (a *activeList) NumActive() int {
	return a.activeSelection.Len()
}

func (a *activeList) IsActive(roundNumber uint64, addr Address) bool {
	_, ok := a.aged[addr]
	return ok && !a.isIdle(roundNumber, addr)
}

// minViableSelection returns the smallest size of network the consensus
// parameters guarantee liveness for. When the active selection is smaller than
// this, the network will halt until and unless the Nc oldest identities are
// online.
func (a *activeList) minViableSelection() int {
	return int(a.config.Candidates + a.config.Endorsers)
}

// maxIdle returns the number of identities in the active selection that
// can go idle without rendering the network inoperable. Strictly this should
// be  max(0, len(active) - (Nc + Q)). But that doesn't allow for any endorsers
// to be offline so we make it max(0, len(active) - (Nc + Ne)).
func (a *activeList) maxIdle() int {
	x := a.activeSelection.Len() - a.minViableSelection()
	if x < 0 {
		x = 0
	}
	return x
}

// IdleLeaders returns all leaders that are idle according to the "oldest for
// rule". At network startup this may be the *entire* active selection.
func (a *activeList) IdleLeaders(roundNumber uint64) []Hash {

	var idles []Hash

	_, _ = a.firstActiveElement(roundNumber, func(becameOldest uint64, pos int, el *list.Element) bool {
		idles = append(idles, el.Value.(*idActivity).nodeID)
		return true
	})

	return idles
}

// NumIdle returns the number of identities idled due to failed round since the
// last successful.
func (a *activeList) NumIdle(roundNumber uint64) int {
	return len(a.IdleLeaders(roundNumber))
}

type idleCallback func(becameOldest uint64, pos int, el *list.Element) bool

func (a *activeList) firstActiveElement(roundNumber uint64, callbacks ...idleCallback) (int, *list.Element) {

	maxIdle := a.maxIdle()

	// initialise becameOldest for the oldest identity in the current active
	// selection. This is only used for the first item. The subsequent items
	// 'became' odlest if and only if the predecessors were removed. So they are
	// all relative to the round of the youngest identity in the active
	// selection - which will change for each accumulate as long as the chain is
	// progressing. The becameOldest for active[0] only changes if that identity
	// mints a block or is re-enroled.
	youngest := a.activeSelection.Front().Value.(*idActivity)
	becameOldest := a.becameOldest
	// becameOldest := youngest.ageRound

	var icur int
	var cur, next *list.Element

	for icur, cur = 0, a.activeSelection.Back(); cur != nil && icur < maxIdle; cur, icur = next, icur+1 {

		next = cur.Prev()
		// This means there have not been sufficient failed rounds since the
		// last block seen by accumulate active to make the icur identity idle.
		// And as we are visiting oldest -> youngest the same holds for all
		// further id's
		if roundNumber < becameOldest {
			return icur, cur
		}

		oldestFor := int(roundNumber-becameOldest) - icur

		// Same reasoning as above
		if oldestFor < int(a.idleRoundLimit) {
			// Note that this catches the case where oldestFor comes out < 0
			return icur, cur
		}

		for _, cb := range callbacks {

			if !cb(becameOldest, icur, cur) {
				return icur, cur
			}
		}

		// becameOldest = youngest.ageRound + uint64(icur) + 1
		becameOldest = youngest.ageRound + uint64(icur)
	}
	return icur, cur
}

// isIdle returns true if the address is in the idle leaders
func (a *activeList) isIdle(roundNumber uint64, id Address) bool {

	var found = false

	_, _ = a.firstActiveElement(roundNumber, func(becameOldest uint64, pos int, el *list.Element) bool {
		if el.Value.(*idActivity).nodeID.Address() != id {
			return true
		}
		found = true
		return false
	})
	return found
}

func (a *activeList) NOldest(roundNumber uint64, n int) []Address {

	var cands []Address

	// Skip past the idle
	for _, cur := a.firstActiveElement(
		roundNumber); cur != nil && len(cands) < n; cur = cur.Prev() {
		cands = append(cands, cur.Value.(*idActivity).nodeID.Address())
	}
	return cands
}

// AgeOf returns the age of the identity or nil if it is not known
func (a *activeList) AgeOf(nodeID Address) (uint64, bool) {
	aged, ok := a.aged[nodeID]
	if !ok {
		return 0, false
	}

	return aged.Value.(*idActivity).ageBlock, true
}

// Reset resets and primes the active selection such that head - ta is the
// furthest back the next selection will look
func (a *activeList) Reset(head BlockHeader) {

	// It feels wrong to lean this much on garbage collection. But lets see how
	// it goes.
	a.newPool = make(map[Address]*idActivity)
	a.aged = make(map[Address]*list.Element)
	a.lastBlockSeen = Hash{}
	a.activeBlockFence = 0
	a.activeSelection = list.New()
	a.Prime(head)
}

// Prime primes the active selection such that the next selection will look as
// far back as head - ta but no further
func (a *activeList) Prime(head BlockHeader) {

	// Note: block sync will stop the consensus. On re-start this will discard
	// the current activeSelection. If we have a list (re-start) then we also
	// need to reset the last block hash seen.
	// if e.activeSelection != nil {
	// 	e.lastBlockSeen = zeroHash
	// }

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

// BlockHeaderReader defines the interface required by AccumulateActive
type BlockHeaderReader interface {
	GetHeaderByHash(hash [32]byte) BlockHeader
}

// AccumulateActive is effectively SelectActive from the paper, but with the
// 'obvious' caching optimisations.
func (a *activeList) AccumulateActive(
	roundNumber uint64, chainID Hash, chain BlockHeaderReader, head BlockHeader,
) error {

	var err error

	if head == nil {
		return nil
	}
	headHash := Hash(head.Hash())
	if headHash == a.lastBlockSeen {
		return nil
	}

	if a.activeSelection.Len() > 0 {

		// Remove leaders idled due to the oldest-for rule since the last accumulate
		_, _ = a.firstActiveElement(roundNumber, func(becameOldest uint64, pos int, el *list.Element) bool {

			a.activeSelection.Remove(el)

			act := el.Value.(*idActivity)
			delete(a.aged, act.nodeID.Address())
			a.logger.Debug(
				"RRR AccumulateActive - culled idle leader",
				"cand", fmt.Sprintf("%s:%05d.%02d", act.nodeID.Address().Hex(), act.ageRound, act.genesisOrder),
				"r", roundNumber, "ic", pos, "of", roundNumber-becameOldest, "ar", act.ageRound,
			)

			if a.activeSelection.Len() <= a.minViableSelection() {
				// Note: We could restore this guarantee if we re-introduced the failed
				// attempts mechanism from the "block clock" implementation. I may still
				// do that as a configuration item.
				a.logger.Warn(
					"RRR AccumulateActive - liveness not guaranteed until more candidates are online",
					"r", roundNumber, "nidle", pos+1, "a", a.activeSelection.Len())
			}

			return true
		})
	}

	blockActivity := BlockActivity{}
	var headActivity BlockActivity

	depth := uint64(0)
	bigHeadNumber := head.GetNumber()
	headNumber := bigHeadNumber.Uint64()
	cur := head

	youngestKnown := a.activeSelection.Front()

	// Record activity of all blocks until we reach the genesis block or
	// until we reach a block we have recorded already. We are traversing
	// 'youngest' block to 'oldest'. We remember the last block seen on the
	// last traversal and use it as our fence.  We insert all block enrolments
	// (also in reverse order) immediately after the fence. This maintains the
	// list in descending age order back -> front (see the spec for a less
	// dense description) Note the sealer is considered older than all of the
	// identities it enrolls.
	for {

		h := Hash(cur.Hash())

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

		if h == headHash {
			headActivity = blockActivity
		}

		// Do any enrolments. (Re) Enrolling an identity moves it to the
		// youngest position in the activity set
		youngestKnown, err = a.enrolIdentities(
			chainID, youngestKnown,
			blockActivity.SealerID, blockActivity.SealerPub, blockActivity.Enrol,
			h, hseal, curNumber, curRound)

		if err != nil {
			return err
		}

		// The sealer is the oldest of those identities active for this block and so is added last.
		youngestKnown = a.refreshAge(youngestKnown, blockActivity.SealerID, h, curNumber, curRound, 0)

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
		"a", a.activeSelection.Len(), "bn", headNumber, "#", headHash.Hex())

	// We always iterate oldest -> youngest
	var next *list.Element

	for cur, i := a.activeSelection.Back(), 0; cur != nil; cur, i = next, i+1 {
		next = cur.Prev()
		age := cur.Value.(*idActivity)

		addr := age.nodeID.Address()

		if age.lastActiveBlock() >= activeHorizon {
			break
		}

		a.logger.Trace("RRR AccumulateActive - identity fell below activity horizon",
			"gi", age.genesisOrder, "end", age.endorsedBlock,
			"last", age.lastActiveBlock(), "id", addr.Hex())

		a.activeSelection.Remove(cur)
		delete(a.aged, age.nodeID.Address())
	}

	oldest := a.activeSelection.Back().Value.(*idActivity)
	youngest := a.activeSelection.Front().Value.(*idActivity)
	if a.lastOldest != oldest.nodeID.Address() {
		a.becameOldest = youngest.ageRound // yes, we mean youngest - its the most recent round
		a.lastOldest = oldest.nodeID.Address()

		a.logger.Trace("RRR AccumulateActive - new oldest active",
			"r", roundNumber, "bo", a.becameOldest, "ar", oldest.ageRound,
			"id", oldest.nodeID.Address().Hex())
	}

	// a.logSelectionOrder(head, &headActivity, roundNumber)

	return nil
}

// NextActiveSample returns a random permutation of indices into nActive.
// The permutation should be ne (n endorsers) elements long. It is sample without
// replacement.  This is contrary to the paper because replacement causes issues
// for small networks in the case where endorsers are selected more than once by
// the same permutation.
func (a *activeList) NextActiveSample(roundNumber uint64, source DRNG, s []int) []int {
	// divergence (3) we do sample *without* replacement because replacement
	// predjudices the quorum in small networks (and network initialisation)

	if a.activeSelection.Len() == 0 {
		panic("RRR NextActiveSample must not be called unless there is a current active selection")
	}

	nsamples := len(s)

	nactive := a.activeSelection.Len() - a.NumIdle(roundNumber)

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

// SelectCandidatesAndEndorsers determines if the current node is a leader
// candidate and what the current endorsers are. The key requirement of RRR met
// here  is that the results of this function should be the same on all nodes
// assuming they run accumulateActive starting from the same `head' block. This
// is both SelectCandidates and SelectEndorsers from the paper. Notice: the
// indices in the permutation are assumed to be sorted in ascending order.
func (a *activeList) SelectCandidatesAndEndorsers(
	roundNumber uint64, permutation []int,
) (map[Address]bool, map[Address]bool, error) {

	// Start with the oldest identity, and iterate towards the youngest. As we
	// walk the active list We gather the candidates and the endorsers The
	// candidates are the Nc first entries, the endorsers are picked using the
	// `permuation`
	//
	// NOTICE: divergence (1) A node is a candidate OR an endorser but not both.
	// The paper allows a candidate to also be an endorser. Discussion with the
	// author suggests this divergence helps small networks without undermining
	// the model.
	//
	// NOTICE: divergence (2) The paper specifies that the endorsers be sorted
	// by public key to produce a stable ordering for selection. But we get a
	// stable ordering by age naturally. So we use the permutation to pick the
	// endorser entries by position in the age order sort of active identities.
	// We can then eliminate the sort and also, usually, terminate the list scan
	// early.

	Na := int(a.config.Activity)
	Nc := int(a.config.Candidates)
	Ne := int(a.config.Endorsers)

	if len(permutation) != Ne {
		return nil, nil, fmt.Errorf(
			"%d != %d: %w", len(permutation), Ne, errPermutationInvalidLength)
	}

	a.logger.Trace(
		"RRR selectCandEs", "na", Na, "agelen", len(a.aged),
		"self", a.selfNodeID.Address().Hex(), "selfID", a.selfNodeID.Hex())

	candidates := make(map[Address]bool)
	endorsers := make(map[Address]bool)

	selection := make([]Address, 0, Ne+Nc)

	icur, cur := a.firstActiveElement(roundNumber, func(becameOldest uint64, pos int, el *list.Element) bool {
		act := el.Value.(*idActivity)
		a.logger.Debug(
			"RRR selectCandEs - skipped idle leader",
			"cand", fmt.Sprintf("%s:%05d.%02d", act.nodeID.Address().Hex(), act.ageRound, act.genesisOrder),
			"r", roundNumber, "ic", pos, "of", roundNumber-becameOldest, "ar", act.ageRound,
		)

		if a.activeSelection.Len()-pos <= a.minViableSelection() {
			// Note: We could restore this guarantee if we re-introduced the failed
			// attempts mechanism from the "block clock" implementation. I may still
			// do that as a configuration item.
			a.logger.Warn(
				"RRR selectCandEs - liveness not guaranteed until more candidates are online",
				"r", roundNumber, "nidle", pos+1, "a", a.activeSelection.Len())
		}

		return true
	})
	nIdle := icur

	var next *list.Element

	// Take the first nc that pass the "oldest for" rule
	for ; cur != nil && len(candidates) < Nc; icur, cur = icur+1, cur.Prev() {

		age := cur.Value.(*idActivity)

		addr := age.nodeID.Address()

		selection = append(selection, Address(addr)) // telemetry only
		candidates[Address(addr)] = true

		a.logger.Debug(
			"RRR selectCandEs - C",
			"cand", fmt.Sprintf("%s:%05d.%02d", addr.Hex(), age.ageBlock, age.genesisOrder),
			"r", roundNumber, "a", age.lastActiveBlock(), "ar", age.ageRound,
			"ic", icur)
		// Note: divergence (1) leader candidates can not be endorsers
	}

	// The permutation is limited to active endorser positions. The leader
	// candidates don't consume 'positions'. We assume the permutation is
	// sorted ascending and just take them one after the other until all are
	// consumed.

	for iperm := 0; iperm < len(permutation) && cur != nil; icur, cur = icur+1, next {
		next = cur.Prev() // so we can remove, and yes, we are going 'backwards'
		age := cur.Value.(*idActivity)
		addr := age.nodeID.Address()

		// divergence (2) instead of sorting the endorser candidates by address
		// (public key) we rely on all nodes seeing the same 'age ordering',
		// and select them by randomly chosen position in that ordering.

		// The permutation is just a random permutation of integers in the
		// range [0, ne).

		pos := permutation[iperm]

		if pos != icur-len(candidates)-nIdle {
			a.logger.Trace(
				"RRR selectCandEs - a", "actv",
				fmt.Sprintf("%s:%05d.%02d", addr.Hex(), age.ageBlock, age.order),
				"r", roundNumber, "a", age.lastActiveBlock(), "ar", age.ageRound,
				"ia", icur, "pos", pos,
			)
			continue
		}

		iperm++

		// XXX: age < Te (created less than Te rounds) grinding attack mitigation

		a.logger.Debug(
			"RRR selectCandEs - E", "endo",
			fmt.Sprintf("%s:%05d.%02d", addr.Hex(), age.ageBlock, age.order),
			"r", roundNumber, "a", age.lastActiveBlock(), "ar", age.ageRound,
			"ie", icur, "pos", pos,
		)

		endorsers[Address(addr)] = true
		selection = append(selection, Address(addr)) // telemetry only
	}

	a.logSelection(candidates, endorsers, selection, Nc, Ne)

	a.logger.Debug("RRR selectCandEs - iendorsers", "p", permutation)
	if len(selection)-Nc == 0 {
		a.logger.Info("RRR selectCandEs - no endorsers selected", "p", permutation)
	}

	return candidates, endorsers, nil
}

// RandomSample fils the slice s with a selection of integers sampled in the
// range [0, limit) without replacement. Each number in the range has an equal
// probability of being included. limit must be greater than the length of the
// slice. This function pancis if it is not
//
// TODO: We use the method described in 4 here
// 	https://cs.stackexchange.com/questions/104930/efficient-n-choose-k-random-sampling
// See also Knuth V2.3.4.2 Algorithm S, and the improvements on it offered in
// the answer to ex 8 and here
// http://www.ittc.ku.edu/~jsv/Papers/Vit84.sampling.pdf.
// for theoretical background and pseudo code. The methods guarantee that any
// single element would be selected with P nEndorsers/nActive

func RandSampleRange(source DRNG, limit int, s []int) []int {

	nsamples := len(s)

	// This will force select them all active identities when na <= ns. na=0
	// is not special.
	if limit <= nsamples {
		panic("limit must be greater than the length of the slice - otherwise all elements would be selected")
	}

	// if nactive isn't at least twice as big as nsamples, invert the process
	// and evict randomly chosen elements.
	if limit < nsamples*2 {

		s = make([]int, limit)

		for i := 0; i < limit; i++ {
			s[i] = i
		}

		for len(s) > nsamples {
			rv := source.Intn(len(s))

			// move selected to end then remove then shorten the slice by 1
			s[rv], s[len(s)-1] = s[len(s)-1], s[rv]
			s = s[:len(s)-1]
		}
		return s
	}

	indices := map[int]bool{}
	for i := 0; i < nsamples; i++ {
		var rv int
		for {
			rv = source.Intn(limit)
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

func RandSelect(source DRNG, limit, nsamples int) map[int]bool {

	s := map[int]bool{}

	// This will force select them all active identities when na <= ns. na=0
	// is not special.
	if limit <= nsamples {
		panic("limit must be greater than the length of the slice - otherwise all elements would be selected")
	}

	// if nactive isn't at least twice as big as nsamples, invert the process
	// and evict randomly chosen elements.
	if limit < nsamples*2 {

		for i := 0; i < limit; i++ {
			s[i] = true
		}

		for len(s) > nsamples {
			rv := source.Intn(len(s))

			delete(s, rv)
		}
		return s
	}

	for i := 0; i < nsamples; i++ {
		var rv int
		for {
			rv = source.Intn(limit)
			if s[rv] {
				continue
			}
			break
		}
		s[rv] = true
	}
	return s
}

type selectionItem struct {
	act *idActivity
	pos int
}

type ByAge []selectionItem

func (a ByAge) Len() int { return len(a) }
func (a ByAge) Less(i, j int) bool {
	// the identity with lowest enrol order in same block is older
	if a[i].act.ageBlock == a[j].act.ageBlock {
		return a[i].act.order < a[j].act.order
	}
	return a[i].act.ageBlock < a[j].act.ageBlock
}

func (a ByAge) Swap(i, j int) { a[i], a[j] = a[j], a[i] }

// LogSelectionOrder is an expensive diagnostic. TODO: wrap this in a lazy logger or query the log level explicitly
func (a *activeList) LogSelectionOrder(head BlockHeader, headActivity *BlockActivity, roundNumber uint64) {

	a.logger.Debug(
		"RRR AccumulateActive - logSelectionOrder",
		"r", roundNumber,
		"a", a.activeSelection.Len(),
		"nidle", a.NumIdle(roundNumber),
	)

	active := make([]selectionItem, a.activeSelection.Len())
	logs := make([]string, a.activeSelection.Len())

	icur, cur := a.firstActiveElement(roundNumber, func(becameOldest uint64, pos int, el *list.Element) bool {

		act := el.Value.(*idActivity)
		active[pos].act = act
		active[pos].pos = pos

		a.logger.Debug(
			"RRR AccumulateActive - ordered",
			"r", roundNumber,
			"ar", act.ageRound,
			"id", act.nodeID.Address().Hex(),
			"ia", pos,
			"of", roundNumber-becameOldest,
		)
		return true
	})

	for ; cur != nil; icur, cur = icur+1, cur.Prev() {

		active[icur].act = cur.Value.(*idActivity)
		active[icur].pos = icur

		logs[icur] = fmt.Sprintf("%d %s", active[icur].act.ageBlock, active[icur].act.nodeID.Address().HexShort())

		a.logger.Debug(
			"RRR AccumulateActive - ordered",
			"r", roundNumber,
			"ar", active[icur].act.ageRound,
			"id", active[icur].act.nodeID.Address().Hex(),
			"ia", icur,
		)

	}
	active = active[:icur] // trim off nil items

	sort.Sort(ByAge(active))

	// Is the oldest correct
	if active[0].pos != 0 {

		// find the entry we expected to be the oldest (lowest ageBlock)
		var expectedPos0 int
		for expectedPos0 = 0; expectedPos0 < len(active); expectedPos0++ {
			if active[expectedPos0].pos == 0 {
				break
			}
		}
		a.logger.Info(
			"RRR AccumulateActive - oldest in queue wrong, have",
			"p", active[0].pos, "a", active[0].act.ageBlock, "id", active[0].act.nodeID.Address().Hex())
		a.logger.Info(
			"RRR AccumulateActive - oldest in queue wrong, expected",
			"p", active[expectedPos0].pos, "a", active[expectedPos0].act.ageBlock, "id", active[expectedPos0].act.nodeID.Address().Hex())
	}

	// is the full order correct ?
	sortedLogs := make([]string, len(active))
	wasSorted := true
	for i := 0; i < len(active); i++ {
		sortedLogs[i] = fmt.Sprintf("%d %s", active[i].act.ageBlock, active[i].act.nodeID.Address().HexShort())
		if active[i].pos != i {
			wasSorted = false
		}
	}
	if !wasSorted {
		// one or more are out of place
		a.logger.Info("RRR accumulateActive - queue not age ordered, have",
			"a", strings.Join(logs, ", "))
		a.logger.Info("RRR accumulateActive - queue not age ordered, expected",
			"a", strings.Join(sortedLogs, ", "))
	}
}

func (a *activeList) logSealerAge(cur BlockHeader, blockActivity *BlockActivity) {

	a.logger.Debug("RRR accumulateActive - sealer",
		"addr", a.logger.LazyValue(func() string { return blockActivity.SealerID.Address().HexShort() }),
		"age", a.logger.LazyValue(func() string {
			curNumber := cur.GetNumber().Uint64()
			if sealer := a.aged[blockActivity.SealerID.Address()]; sealer != nil {
				age := sealer.Value.(*idActivity)
				if age.ageBlock < curNumber {
					return fmt.Sprintf("%d->%d.%02d", age.ageBlock, curNumber, age.order)
				}
				return fmt.Sprintf("%05d.%02d", curNumber, age.order)

			}
			// first block from this sealer since it went idle or was first
			// enrolled. if it went idle we could have seen an endorsement for
			// it but we haven't, if it is new this will be the first encounter
			// with the identity.
			return fmt.Sprintf("%05d.--", curNumber)
		}),
	)
}
func (a *activeList) logSelection(
	candidates map[Address]bool, endorsers map[Address]bool,
	selection []Address, nCandidates, nEndorsers int) {

	a.logger.Debug("RRR selectCandEs", "selected", a.logger.LazyValue(
		func() string {
			// Dump a report of the selection. By reporting as "block.order", we
			// can, for small development networks, easily correlate with the
			// network. We probably also want the full list of nodeID's for
			// larger scale testing.
			strcans := []string{}
			strends := []string{}

			for _, addr := range selection {

				if Address(addr) == zeroAddr {
					break // fewer than desired candidates
				}
				// it is a programming error if we get nil here, either for the map entry or for the type assertion
				el := a.aged[Address(addr)]
				if el == nil {
					a.logger.Crit("no entry for", "addr", addr.Hex())
					continue // incase Crit isn't terminal and to silence linter
				}
				age := el.Value.(*idActivity)
				if age == nil {
					a.logger.Crit("element with no value", "addr", addr.Hex())
					continue // incase Crit isn't terminal and to silence linter
				}

				s := fmt.Sprintf("%d.%d:%s", age.ageBlock, age.order, Address(addr).HexShort())
				if candidates[addr] {
					strcans = append(strcans, s)
				} else {
					strends = append(strends, s)
				}
			}
			return fmt.Sprintf("|%s|%s|", strings.Join(strcans, ","), strings.Join(strends, ","))
		}),
	)
}

// lastActiveBlock returns the higher of endorsedBlock and ageBlock
func (a *idActivity) lastActiveBlock() uint64 {

	if a.endorsedBlock > a.ageBlock {
		return a.endorsedBlock
	}
	return a.ageBlock
}

func (a *activeList) enrolIdentities(
	chainID Hash, fence *list.Element, sealerID Hash,
	sealerPub []byte, enrolments []Enrolment, block Hash, blockSeal Hash, blockNumber, roundNumber uint64,
) (*list.Element, error) {

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

	// The 'youngest' enrolment in the block is the last in the slice. And it
	// is essential that we refreshAge youngest to oldest
	// (resuting in oldest <- youngest order)
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
			return fence, err
		}
		if !ok {
			if ok, err = verifyEnrolment(enr, false); err != nil {
				return fence, err
			}
		}
		if !ok {
			return fence, fmt.Errorf("sealer-id=`%s',id=`%s',u=`%s':%w",
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

		fence = a.refreshAge(fence, enr.ID, block, blockNumber, roundNumber, order)
	}
	return fence, nil
}

func newIDActivity(nodeID Hash) *idActivity {
	return &idActivity{
		nodeID:        nodeID,
		ageBlock:      0,
		endorsedBlock: 0,
	}
}

// recordActivity is called for a node to indicate it is active in the current
// round.
func (a *activeList) recordActivity(nodeID Hash, endorsed Hash, blockNumber, roundNumber uint64) *idActivity {

	var aged *idActivity
	nodeAddr := nodeID.Address()
	if el := a.aged[nodeAddr]; el != nil {
		// Easy case, we simply don't have to care about age at all, it is what
		// it is.
		aged = el.Value.(*idActivity)
	} else {

		// Interesting case, activity from an identity whose enrolment we
		// haven't seen yet. We put the new entry straight onto the idle set.
		// refreshAge (below) will pluck it out of the idle set if it is
		// encountered within HEAD - Ta

		aged = newIDActivity(nodeID)
		a.newPool[nodeAddr] = aged
	}
	aged.endorsedHash = endorsed
	aged.endorsedBlock = blockNumber
	aged.endorsedRound = roundNumber

	return aged
}

// refreshAge called to indicate that nodeID has minted a block or been
// enrolled. If this is the youngest block minted by the identity, we move its
// entry to the oldest position which is younger than the fence. The fence is
// the youngest known when we start the accumulate active process.
// Because accumulateActive works from the head (youngest) towards genesis we
// are visiting from the youngest to the oldest. By always inserting at the
// oldest position younger than the fence, we preserve that order.  In the
// special case where the list starts empty the fence is nil. In this case to
// preserve the order we just need to PushBack, each identity encountered is
// 'older' than the previous
func (a *activeList) refreshAge(
	fence *list.Element, nodeID Hash, block Hash, blockNumber, roundNumber uint64, order int,
) *list.Element {
	var aged *idActivity

	nodeAddr := nodeID.Address()

	if el := a.aged[nodeAddr]; el != nil {

		// the case where an identity matching the fence mines or endorses
		if fence == el {
			fence = fence.Next() // older position (closer to front)
		}

		aged = el.Value.(*idActivity)

		// If the last block we saw for this identity is older, we need to
		// reset the age by moving it after the fence. Otherwise, we assume we
		// have already processed it and it is in the appropriate place.
		// But note if we have a re-org, ageBlock *can* be from the 'other'
		// branch and so > head. The aged pool needs to be re-set for a re-org.
		if aged.ageBlock <= blockNumber {

			a.logger.Trace("RRR refreshAge - move",
				"fenced", bool(fence != nil), "addr", nodeAddr.HexShort(), "age",
				fmt.Sprintf("%d->%d.%02d", aged.ageBlock, blockNumber, order))

			if fence != nil {
				// Note: 'Before' means *in front of* (younger position)
				a.activeSelection.MoveBefore(el, fence)
			} else {
				// Here we are assuming the list started *empty*
				a.activeSelection.MoveToBack(el)
			}
			aged.ageBlock = blockNumber
			aged.ageRound = roundNumber
			aged.ageHash = block
			aged.order = order
		}

	} else {

		// If it was enrolled within HEAD - Ta and has been active, it will be
		// in the idle pool because the age wasn't known when the activity was
		// seen by recordActivity. In either event there is no previous age.
		if aged = a.newPool[nodeAddr]; aged != nil {
			a.logger.Trace(
				"RRR refreshAge - from idle", "addr", nodeAddr.HexShort(),
				"age", fmt.Sprintf("%05d.%02d", blockNumber, order))
		} else {
			a.logger.Trace(
				"RRR refreshAge - new", "addr", nodeAddr.HexShort(), "age",
				fmt.Sprintf("%05d.%02d", blockNumber, order))
			aged = newIDActivity(nodeID)
		}
		delete(a.newPool, nodeAddr)

		aged.ageBlock = blockNumber
		aged.ageRound = roundNumber
		aged.ageHash = block
		aged.order = order

		if fence != nil {
			// Note: 'Before' means *in front of* (younger position)
			a.aged[nodeAddr] = a.activeSelection.InsertBefore(aged, fence)
		} else {
			// Here we are assuming the list started *empty*
			a.aged[nodeAddr] = a.activeSelection.PushBack(aged)
		}
	}

	// Setting ageBlock resets the age of the identity. The test for active is
	// sensitive to this. If endorsedBlock for an identity is outside of Ta,
	// then it is still considered 'active' if ageBlock is inside Ta.
	// Re-enrolment is how the current leader re-activates idle identities.

	if blockNumber == 0 {
		aged.genesisOrder = order
	}
	return fence
}
