package rrr

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

	// RMsgEnrol is used to alow nodes to self enrol and automatically re-enrol
	// without needing to go through the rpc mechanism
	RMsgEnrol

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
	Raw  []byte

	// Gossiping support for partialy connected networks (which is increasingly
	// common the larger the number of active identities)

	Round uint64

	// If the message is to be gossiped, To are the intended recipients. Any
	// node that has a direct connection for any To address will simply send
	// directly, remove it from the To list, and only re-broadcast if any To's
	// remain. Note that in any given round we are only gossiping RMsgIntent's or
	// RMsgConfirm's. And we are only gossiping amongst leader candidates and
	// endorsers selected for the current round - not the entire network.
	To []Address

	// telemetry only, incremented each time the message is re-gossiped
	PathLength uint32
}

// eng* types can be sent at any tome the the engines runningCh.
type EngSignedIntent struct {
	SignedIntent
	Pub []byte // Derived from signature
}
type EngSignedEndorsement struct {
	SignedEndorsement
	Pub []byte // Derived from signature
}

type EngEnrolIdentity struct {
	NodeID [32]byte

	Round   uint64
	ReEnrol bool
}
