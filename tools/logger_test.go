package tools_test

// Tests for go-rrr/consensus/rrr
import (
	"github.com/ethereum/go-ethereum/log"
)

// Logger wrapper for rrr so we can provide LazyValue
type Logger struct {
	L log.Logger
}

func (l Logger) LazyValue(fn func() string) interface{} {
	return log.Lazy{Fn: fn}
}
func (l Logger) Trace(msg string, ctx ...interface{}) {
	l.L.Trace(msg, ctx...)
}
func (l Logger) Debug(msg string, ctx ...interface{}) {
	l.L.Debug(msg, ctx...)
}
func (l Logger) Info(msg string, ctx ...interface{}) {
	l.L.Info(msg, ctx...)
}
func (l Logger) Warn(msg string, ctx ...interface{}) {
	l.L.Warn(msg, ctx...)
}
func (l Logger) Crit(msg string, ctx ...interface{}) {
	l.L.Crit(msg, ctx...)
}
