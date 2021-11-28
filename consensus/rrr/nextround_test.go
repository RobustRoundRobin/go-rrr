package rrr

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"gotest.tools/assert"
)

type TestLogger struct {
	t *testing.T
}

func (l *TestLogger) LazyValue(func() string) interface{} {
	return nil
}

func (l *TestLogger) log(msg string, ctx ...interface{}) {

	if len(ctx)%2 != 0 {
		panic("even number of context arguments required")
	}

	s := make([]string, 0, len(ctx)/2)

	for i := 0; i < len(ctx); i += 2 {
		s = append(s, fmt.Sprintf("%v=%v", ctx[i], ctx[i+1]))
	}

	fmt.Println(msg + " " + strings.Join(s, ", "))

}

func (l *TestLogger) Trace(msg string, ctx ...interface{}) { l.log(msg, ctx...) }
func (l *TestLogger) Debug(msg string, ctx ...interface{}) { l.log(msg, ctx...) }
func (l *TestLogger) Info(msg string, ctx ...interface{})  { l.log(msg, ctx...) }
func (l *TestLogger) Warn(msg string, ctx ...interface{})  { l.log(msg, ctx...) }
func (l *TestLogger) Crit(msg string, ctx ...interface{}) {
	l.log(msg, ctx...)
	panic("crit")
}

// activeSelection implements enough of the ActiveSelection interface to keep
// alignForFailedAttempts and next
type activeSelection struct {
	logger    Logger
	numActive int
}

func (a *activeSelection) AccumulateActive(
	roundNumber uint64, chainID Hash, chain BlockHeaderReader, head BlockHeader,
) error {
	return nil
}

func (a *activeSelection) SelectCandidatesAndEndorsers(
	roundNumber uint64, permutation []int,
) (map[Address]bool, map[Address]bool, error) {
	return nil, nil, nil
}

func (a *activeSelection) LeaderForRoundAttempt(
	nCandidates, nEndorsers uint32, id Address) bool {
	return true
}
func (a *activeSelection) Reset(head BlockHeader) {
}
func (a *activeSelection) Prime(head BlockHeader)                         {}
func (a *activeSelection) AgeOf(nodeID Address) (uint64, bool)            { return 0, false }
func (a *activeSelection) NumActive() int                                 { return a.numActive }
func (a *activeSelection) IdleLeaders() []Hash                            { return nil }
func (a *activeSelection) IsActive(roundNumber uint64, addr Address) bool { return true }
func (a *activeSelection) NOldest(roundNumber uint64, n int) []Address    { return nil }
func (a *activeSelection) NextActiveSample(
	roundNumber uint64, source DRNG, s []int) []int {
	return nil
}

func TestAlignFailedAttempts(t *testing.T) {

	now := time.Now()
	logger := &TestLogger{t}

	table := []struct {
		name         string
		headSealTime time.Time
		now          time.Time
		headRound    uint64
		fcarry       uint32
		roundLength  uint64
		endorsers    uint64
		nActive      int
		fexpect      uint32
	}{
		{
			"perfect start",
			now, now,
			0,    // rh (headRound)
			0,    // fcarry
			5000, // roundLength
			3,    // endorsers
			5,    // num active
			0,
		},
	}

	for _, test := range table {
		t.Run(test.name, func(t *testing.T) {
			r := EndorsmentProtocol{
				logger: logger,
				config: &Config{
					RoundLength: test.roundLength,
					Endorsers:   test.endorsers,
				},
				roundLength:         time.Duration(test.roundLength) * time.Millisecond,
				chainHeadRoundStart: test.headSealTime,
				a:                   &activeSelection{logger: logger, numActive: test.nActive},
			}
			factual := r.alignFailedAttempts(test.now, test.headRound, test.fcarry)
			assert.Equal(t, factual, test.fexpect)
		})
	}
}
