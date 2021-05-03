package rrr

// Config carries the RRR consensus configuration
type Config struct {
	ConfirmPhase uint64 `toml:",omitempty"` // Duration of the confirmation phase in milliseconds (must be < round)
	RoundLength  uint64 `toml:",omitempty"` // Duration of each round in milliseconds

	Candidates        uint64 `toml:",omitempty"` // Number of leader candidates (Nc) to propose from the oldest identities on each round
	Endorsers         uint64 `toml:",omitempty"` // Number of endorsers (Ne) to select from the most recently active identities
	Quorum            uint64 `toml:",omitempty"` // Number of endorsments required to confirm an intent
	Activity          uint64 `toml:",omitempty"` // Activity threshold (Ta) (in blocks). Any identity with confirmation messages recorded within this many rounds of the head are considered active.
	StablePrefixDepth uint64 `toml:"omitempty"`  // d stable block prefix (for seed r-d)
}

// DefaultConfig provides the default rrr consensus configuration
var DefaultConfig = &Config{
	ConfirmPhase:      5000,
	RoundLength:       6000,
	Candidates:        5,
	Endorsers:         100,
	Quorum:            54,
	Activity:          200,
	StablePrefixDepth: 12,
}
