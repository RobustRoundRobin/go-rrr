package rrr

// Logger is the go-ethereum compatible logging interface used in rrr
type Logger interface {
	LazyValue(func() string) interface{}
	Trace(msg string, ctx ...interface{})
	Debug(msg string, ctx ...interface{})
	Info(msg string, ctx ...interface{})
	Warn(msg string, ctx ...interface{})
	Crit(msg string, ctx ...interface{})
}
