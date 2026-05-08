package obs

import "runtime/debug"

// SafeGo launches fn in a new goroutine wrapped with a deferred recover so
// a panic inside fn is caught, logged via the global logger, and does not
// crash the process.  name identifies the goroutine in the log line so the
// call site is traceable; the captured stack is included so the panic
// site inside fn is visible without re-running with GOTRACEBACK=all.
func SafeGo(name string, fn func()) {
	go func() {
		defer func() {
			if r := recover(); r != nil {
				Default().Error("panic recovered",
					"where", name,
					"panic", r,
					"stack", string(debug.Stack()))
			}
		}()
		fn()
	}()
}
