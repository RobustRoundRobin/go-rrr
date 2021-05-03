package rrr

// Home for stringers and other telemetry related distractions
func (p RoundPhase) String() string {
	switch p {
	case RoundPhaseIntent:
		return "RoundPhaseIntent"
	case RoundPhaseConfirm:
		return "RoundPhaseConfirm"
	default:
		return "RoundPhaseInvalid"
	}
}

func (s RoundState) String() string {
	switch s {
	case RoundStateNeedBlock:
		return "RoundStateNeedBlock"
	case RoundStateInvalid:
		return "RoundStateInvalid"
	case RoundStateInactive:
		return "RoundStateInactive"
	case RoundStateActive:
		return "RoundStateActive"
	case RoundStateLeaderCandidate:
		return "RoundStateLeaderCandidate"
	case RoundStateEndorserCommittee:
		return "RoundStateEndorserCommittee"
	default:
		return "<unknown>"
	}
}

func (c RMsgCode) String() string {
	switch c {
	case RMsgInvalid:
		return "RMsgInvalid"
	case RMsgIntent:
		return "RMsgIntent"
	case RMsgConfirm:
		return "RMsgConfirm"
	case RMsgRandContribSolicit:
		return "RMsgRandContribSolicit"
	case RMsgRandContrib:
		return "RMsgRandContrib"
	case RMsgRandAgreementSolicit:
		return "RMsgRandAgreementSolicit"
	case RMsgRandAgreement:
		return "RMsgRandAgreement"
	default:
		return "RMsgInvalid"
	}
}
