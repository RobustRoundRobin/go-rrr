package rrr

const (
	RRRActiveMethodSortEndorsers = "sortendorsers"
	// RRRActiveMethodRotateCandidates is implemented as a variant on
	// sortendorsers where rather than idling leaders that fail to produce
	// within Nc, we 'rotate' the candidate selection through the active
	// selection acording to the number of failed rounds.
	RRRActiveMethodRotateCandidates = "rotatecandidates"
	RRRActiveMethodSampleAged       = "sampleaged"
)

// Config carries the RRR consensus configuration
type Config struct {
	IntentPhase  uint64 `toml:",omitempty"` // How long endorsers wait to decide the oldes leader
	ConfirmPhase uint64 `toml:",omitempty"` // Duration of the confirmation phase in milliseconds (must be < round)
	RoundLength  uint64 `toml:",omitempty"` // Duration of each round in milliseconds

	Candidates        uint64 `toml:",omitempty"` // Number of leader candidates (Nc) to propose from the oldest identities on each round
	Endorsers         uint64 `toml:",omitempty"` // Number of endorsers (Ne) to select from the most recently active identities
	Quorum            uint64 `toml:",omitempty"` // Number of endorsments required to confirm an intent
	Activity          uint64 `toml:",omitempty"` // Activity threshold (Ta) (in blocks). Any identity with confirmation messages recorded within this many rounds of the head are considered active.
	StablePrefixDepth uint64 `toml:"omitempty"`  // d stable block prefix (for seed r-d)

	// MinIdleAttempts if the identity is oldest for
	// MAX(Candidates,MinIdleAttempts) it is made idle. Used to avoid over
	// agressive idling in small networks.
	MinIdleAttempts uint64 `toml:"omitempty"`
	GossipFanout    int    `toml:"omitempty"`

	// ActivityMethod selects one of the alternative implementations for
	// tracking identity activity
	// sortendorsers - closest to paper, simplest implementation, may struggle with > 10000s of identities
	// sampleaged - maintains all idenities in age order all the time and does not sort in SelectActive
	ActivityMethod string `toml:"ommitempty"`
}

// DefaultConfig provides the default rrr consensus configuration
var DefaultConfig = &Config{
	IntentPhase:       1000,
	ConfirmPhase:      1000,
	RoundLength:       4000,
	Candidates:        2,
	Endorsers:         7,
	Quorum:            4,
	Activity:          2000,
	StablePrefixDepth: 6,
	MinIdleAttempts:   5,
	GossipFanout:      4,
	ActivityMethod:    RRRActiveMethodSortEndorsers,
}
