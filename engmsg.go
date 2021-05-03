package rrr

import (
	"time"
)

// consensus message types

// RMsgCode identifies the rrr message type. rrrMsg identifies rrr's
// message type to the devp2p layer as being consensus engine specific. Once
// that outer message is delivered to rrr, RMsgCode is how rrr
// differentiates each of its supported message payloads.
type RMsgCode uint

const (
	// RMsgInvalid is the *never set* invalid message code
	RMsgInvalid RMsgCode = iota
	// RMsgIntent identifies RRR intent messages
	RMsgIntent
	// RMsgConfirm identifies RRR endorsement messages (confirmations)
	RMsgConfirm

	// RMsgRandContribSolicit ...
	RMsgRandContribSolicit
	// RMsgRandContrib ...
	RMsgRandContrib
	// RMsgRandAgreementSolicit ...
	RMsgRandAgreementSolicit
	// RMsgRandAgreement ...
	RMsgRandAgreement
)

// RMsg is the dev p2p (eth) message for RRR
type RMsg struct {
	Code RMsgCode
	// Seq should be incremented to cause an explicit message resend. It is not
	// used for any other purpose
	Seq uint
	Raw []byte
}

// eng* types can be sent at any tome the the engines runningCh.
type EngSignedIntent struct {
	SignedIntent
	Pub        []byte // Derived from signature
	ReceivedAt time.Time
	Seq        uint // from RMsg
}
type EngSignedEndorsement struct {
	SignedEndorsement
	Pub        []byte // Derived from signature
	ReceivedAt time.Time
	Seq        uint // from RMsg
}

type EngEnrolIdentity struct {
	NodeID  [32]byte
	ReEnrol bool
}
