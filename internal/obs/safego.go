package obs

// SafeGo launches fn in a new goroutine wrapped with a deferred recover so
// a panic inside fn is caught, logged via the global logger, and does not
// crash the process.  name identifies the goroutine in the log line so the
// call site is traceable without a full stack dump.
func SafeGo(name string, fn func()) {
	go func() {
		defer func() {
			if r := recover(); r != nil {
				Default().Error("panic recovered", "where", name, "panic", r)
			}
		}()
		fn()
	}()
}
