package rrr

import (
	"time"
)

// RoundTime takes (some) of the sharp edges of go's time.Timer and provides
// conveniences for manaing the time based RRR state
type RoundTime struct {
	config    *Config
	Confirm   time.Duration
	Intent    time.Duration
	Broadcast time.Duration

	// Ticker has to be public, but use Start and StopTicker. The only
	// legitemate direct use is <-t.Ticker.C in a select case. And that is only
	// safe if Start and StopTicker are used correctly.  time.Timer's are
	// tricky. See:
	// https://blogtitle.github.io/go-advanced-concurrency-patterns-part-2-timers/

	Ticker *time.Timer
	logger Logger
}

type RoundTimeOption func(r *RoundTime)

// NewRoundTime creates and configures a RoundTime. Does *not* call Start
func NewRoundTime(
	config *Config, opts ...RoundTimeOption) RoundTime {

	roundDuration := time.Duration(config.RoundLength) * time.Second
	c := time.Duration(config.ConfirmPhase) * time.Millisecond
	t := RoundTime{
		Confirm:   c / 2,
		Intent:    c - (c / 2),
		Broadcast: roundDuration - c,
		logger:    logger,
	}

	for _, o := range opts {
		o(t)
	}

	return t
}

// Start creates and starts the ticker. time.Timer's are a bit tricky. Be very
// careful to StopTicker correctly if you want call this more than once.
func (t *RoundTime) Start() {
	t.Ticker = time.NewTimer(t.Intent)
}

// Stop stops and, if necessary, drains the ticker
func (t *RoundTime) Stop() {
	if !t.Ticker.Stop() {
		<-t.Ticker.C
	}
}

// ResetForIntentPhase resets the ticker appropriately for begining the intent
// phase (without adjustment). Be very careful to call StopTicker exactly once
// before calling this.
func (t *RoundTime) ResetForIntentPhase() {
	t.Ticker.Reset(t.Intent)
}

// ResetForConfirmPhase resets the ticker appropriately for begining the
// confirm phase (without adjustment). Be very careful to call StopTicker
// exactly once before calling this.
func (t *RoundTime) ResetForConfirmPhase() {
	t.Ticker.Reset(t.Confirm)
}

func (t *RoundTime) ResetForBroadcastPhase() {
	t.Ticker.Reset(t.Broadcast)
}
