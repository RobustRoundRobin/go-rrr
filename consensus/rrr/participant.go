package rrr

import "bytes"

type Participant struct {
	// nodeID is the 'identity'
	nodeID Hash

	// ageRound is the round number the identity most recently minted a block
	// in OR the round its identity was enroled
	ageRound uint64

	// endorsedRound is the round number that produced the last block endorsed
	// by the identity.
	endorsedRound uint64

	candidateRound uint64
	failedRounds   uint64

	// order in the block that the identities enrolment appeared.  The first
	// time an identity is selected, it has not minted so it is conceivable
	// that its 'age' is the same as another leader candidate (because they
	// were enrolled on the same block and they both have not minted). In this
	// case, the order is the tie breaker. Once the identity mints, order is
	// set to zero. order is initialised to zero for the genesis identity.
	order        int
	genesisOrder int
}

type ParticipantByAge []*Participant

func (a ParticipantByAge) Len() int { return len(a) }
func (a ParticipantByAge) Less(i, j int) bool {
	// the identity with lowest enrol order in same block is older
	if a[i].ageRound == a[j].ageRound {
		return a[i].order < a[j].order
	}
	return a[i].ageRound < a[j].ageRound
}

func (a ParticipantByAge) Swap(i, j int) { a[i], a[j] = a[j], a[i] }

type ParticipantByID []*Participant

func (a ParticipantByID) Len() int { return len(a) }
func (a ParticipantByID) Less(i, j int) bool {
	return bytes.Compare(a[i].nodeID[:], a[j].nodeID[:]) < 0
}

func (a ParticipantByID) Swap(i, j int) { a[i], a[j] = a[j], a[i] }
