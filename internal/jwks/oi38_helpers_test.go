package jwks

import "time"

// setFetchTimeout overrides v's fetch bound.
func setFetchTimeout(v *Verifier, d time.Duration) { v.fetchTimeout = d }

// waitIdle waits for the fetch in flight, if any, to be applied.
func waitIdle(v *Verifier) {
	v.mu.Lock()
	call := v.inflight
	v.mu.Unlock()
	if call != nil {
		<-call.done
	}
}

// settled verifies tok on path and then waits for any refresh the
// verification started, so a test reads the cache and the fetch count after
// the refresh has been applied.
func settled(path cooldownPath, v *Verifier, tok []byte) error {
	err := path.verify(v, tok)
	waitIdle(v)
	return err
}
