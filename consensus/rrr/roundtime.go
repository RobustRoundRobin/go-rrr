package rrr

import (
	"math"
	"time"
)

// RoundTime takes (some) of the sharp edges of go's time.Timer and provides
// conveniences for manaing the time based RRR state
type RoundTime struct {
	Confirm time.Duration
	Intent  time.Duration

	// Ticker has to be public, but use Start, StopTicker and PhaseAdjust. The
	// only legitemate direct use is <-t.Ticker.C in a select case. And that is
	// only safe if Start, StopTicker and PhaseAdjust are used correctly.
	// time.Timer's are tricky. See:
	// https://blogtitle.github.io/go-advanced-concurrency-patterns-part-2-timers/

	Ticker *time.Timer
	logger Logger
}

// NewRoundTime creates and configures a RoundTime. Does *not* call Start
func NewRoundTime(roundLength uint64, confirmPhase uint64, logger Logger) *RoundTime {
	t := &RoundTime{}
	t.Configure(roundLength, confirmPhase, logger)
	return t
}

// Configure initialises the round phase durations. logger may be nil
func (t *RoundTime) Configure(roundLength uint64, confirmPhase uint64, logger Logger) {

	roundDuration := time.Duration(roundLength) * time.Millisecond
	t.Confirm = time.Duration(confirmPhase) * time.Millisecond
	t.Intent = time.Duration(roundLength-confirmPhase) * time.Millisecond
	t.logger = logger

	if t.logger != nil {
		t.logger.Trace(
			"RRR RoundTime Configure",
			"round", roundDuration, "confirm", t.Confirm, "intent", t.Intent)
	}
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

// PhaseAdjust calculates and applies an adjustment for the block latency to
// the round phase and ticker. It's expected use is just after a new block
// arrives. In this implementation of RRR the new block arrival is defined as
// the start of the next round. The latency between the signed seal time from
// the successul leader and 'now' is applied to the round phase and ticker.
// This assumes losely synchronised clocks. This RRR implementation does not
// require this but it does smooth things out. Lastly, time.Timer's are a bit
// tricky, be very careful to StopTicker exactly once before calling this.
// XXX: TODO: We need to gather emprical evidence for this being worth while.
func (t *RoundTime) PhaseAdjust(sealTime uint64) RoundPhase {

	phase, tick := t.BlockLatencyAdjustment(
		time.Now(), time.Unix(int64(sealTime), 0))
	t.Ticker.Reset(tick)
	return phase
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

// BlockLatencyAdjustment trims the duration for the intent phase according to
// how long the block took to reach us. This *assumes* the clocks on the nodes
// are roughly in synch. We don't need this but if it is turned on things are
// 'smoother'.
func (t *RoundTime) BlockLatencyAdjustment(
	now, sealTime time.Time) (
	RoundPhase, time.Duration) {

	if now.After(sealTime) {
		latency := now.Sub(sealTime)

		if latency >= t.Intent+t.Confirm {
			// We don't adjust our local attempt counter, we just align best we
			// can with the phase.
			m := math.Mod(float64(latency), float64(t.Intent+t.Confirm))
			i, _ := math.Modf(m)
			latency = time.Duration(i)
		}
		if latency < t.Intent {
			// Easy case, the adjustment just shortens the intent phase.
			return RoundPhaseIntent, t.Intent - latency
		}

		if latency < t.Intent+t.Confirm {
			// Also fairly easy case. The adjustment puts us in the confirm
			// phase
			latency -= t.Intent
			return RoundPhaseConfirm, t.Confirm - latency
		}
		panic("this should be impossible")
		// Now we need to consider adjusting the attempt
	}

	if t.logger != nil {
		t.logger.Warn("seal time ahead of node now", "now", now, "seal", sealTime)
	}

	return RoundPhaseIntent, time.Duration(0)
}
