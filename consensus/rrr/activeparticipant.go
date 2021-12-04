package rrr

import (
	"bytes"
)

type Participant struct {
	// nodeID is the 'identity'
	nodeID Hash

	// ageRound is the round number the identity most recently minted a block
	// in OR the round its identity was enroled
	ageRound uint64

	// ageBlock is the block most recently minted by, or endorsed by, the identity
	ageBlock uint64

	// endorsedRound is the round number that produced the last block endorsed
	// by the identity.
	endorsedRound uint64
	// endorsedBlock is the block last endorsed by the identity
	endorsedBlock uint64

	// candidateRound is the most recent round the particpant was a candidate block producer
	candidateRound uint64

	// failedRounds is the number of rounds the participant was a candidate
	failedRounds uint64

	// order in the block that the identities enrolment appeared.  The first
	// time an identity is selected, it has not minted so it is conceivable
	// that its 'age' is the same as another leader candidate (because they
	// were enrolled on the same block and they both have not minted). In this
	// case, the order is the tie breaker. Once the identity mints, order is
	// set to zero. order is initialised to zero for the genesis identity.
	order        int
	genesisOrder int
}

// oldestForIdleRule tests if the participant should be culled for inactivity
// due to the idle for rule. It must not be called more than once for any
// participant in any round.
func (p *Participant) oldestForIdleRule(icandidate int, roundNumber, idleRoundLimit uint64) bool {

	// ageRound will only be equal to the candidate round if the participant has
	// mined or endorsed a block since it was last a candidate. As candidates
	// are excluded from endorsing a block, once a participants age makes it a
	// candidate, its ageRound will not change until it mines a block or gets
	// re-enroled after being idle culled due to this rule. We make this a
	// >= rather than an == test to account for the re-enrolment case.
	if p.ageRound >= p.candidateRound && p.ageRound != 0 {
		p.failedRounds = 0
		p.candidateRound = roundNumber
		return false
	}

	if p.candidateRound == 0 {
		return false
	}

	d := roundNumber - p.candidateRound
	if uint64(icandidate) < d {
		p.failedRounds += d - uint64(icandidate)
	}

	p.candidateRound = roundNumber

	return p.failedRounds > idleRoundLimit
}

type ParticipantByAge []*Participant

func (a ParticipantByAge) Len() int { return len(a) }
func (a ParticipantByAge) Less(i, j int) bool {
	// the identity with lowest enrol order in same block is older
	if a[i].ageBlock == a[j].ageBlock {
		return a[i].order < a[j].order
	}
	return a[i].ageBlock < a[j].ageBlock
}

func (a ParticipantByAge) Swap(i, j int) { a[i], a[j] = a[j], a[i] }

type ParticipantByID []*Participant

func (a ParticipantByID) Len() int { return len(a) }
func (a ParticipantByID) Less(i, j int) bool {
	return bytes.Compare(a[i].nodeID[:], a[j].nodeID[:]) < 0
}

func (a ParticipantByID) Swap(i, j int) { a[i], a[j] = a[j], a[i] }
