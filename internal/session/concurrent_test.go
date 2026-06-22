package session

// Regression test for audit finding #14: Session was shared by raw pointer
// across IKEv2, S2b/GTP-U callbacks, cleanup, and the admin API with no
// synchronization at all. Run with -race; this test also fails functionally
// (not just under the race detector) if a snapshot ever observes a torn
// write — see the invariant check below.

import (
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestConcurrentLifecycleAndReads simulates the real access pattern the
// audit flagged: one goroutine driving a session through its lifecycle
// (state transitions, S2B context swaps, MSK/IMSI updates — the IKEv2/S2b
// write side) while several goroutines concurrently read it the way the
// admin API does (Manager.Snapshot + Session.Snapshot/RLock), plus a
// goroutine doing PGW-style out-of-band field updates concurrently. Run
// with `go test -race` — any unsynchronized access fails the build.
func TestConcurrentLifecycleAndReads(t *testing.T) {
	mgr := NewManager()
	sess := mgr.GetOrCreate("sess-1")

	const iterations = 2000
	var wg sync.WaitGroup
	stop := make(chan struct{})

	// Writer: drives the session through IKEv2/S2b-style field updates and
	// state transitions, the way auth.go does.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < iterations; i++ {
			sess.Lock()
			sess.IMSI = "311435300070581"
			sess.NAI = "0311435300070581@nai.epc.mnc435.mcc311.3gppnetwork.org"
			sess.MSK = make([]byte, 64)
			// Invariant under test: EBI is always derived from
			// PGWControlTEID within the SAME assignment, so any snapshot
			// that observes one half must observe the matching other half.
			teid := uint32(i)
			sess.S2B = &S2BContext{
				PGWControlTEID: teid,
				EBI:            uint8(teid),
				PGWUserIP:      net.IPv4(10, 0, 0, byte(i%256)),
			}
			_ = sess.Transition(StateEAPAuthenticating)
			_ = sess.Transition(StateEAPAuthenticated)
			_ = sess.Transition(StateS2BCreateSessionSent)
			_ = sess.Transition(StateS2BAccepted)
			_ = sess.Transition(StateGTPUInstalling)
			_ = sess.Transition(StateDatapathInstalling)
			_ = sess.Transition(StateActive)
			// Reset for the next round so transitions stay legal.
			sess.State = StateNew
			sess.Unlock()
		}
	}()

	// Out-of-band writer: simulates a PGW callback (handlePGWDeleteBearer
	// style) flipping HandoverComplete independently of the main lifecycle.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < iterations; i++ {
			sess.Lock()
			sess.HandoverComplete = !sess.HandoverComplete
			sess.Unlock()
		}
	}()

	var torn atomic.Int64

	// Readers: simulate the admin API's Manager.Snapshot + per-session read.
	for r := 0; r < 4; r++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				for _, s := range mgr.Snapshot() {
					view := s.Snapshot()
					if view.S2B != nil && view.S2B.EBI != uint8(view.S2B.PGWControlTEID) {
						torn.Add(1)
					}
				}
				// Also exercise direct RLock-based reads (the pattern used
				// by sessionDetail/clientSummary/stats.go).
				sess.RLock()
				_ = sess.IMSI
				_ = sess.State
				if sess.S2B != nil {
					_ = sess.S2B.PGWUserIP
				}
				sess.RUnlock()
			}
		}()
	}

	go func() {
		time.Sleep(500 * time.Millisecond)
		close(stop)
	}()

	wg.Wait()

	if got := torn.Load(); got != 0 {
		t.Fatalf("observed %d torn reads of S2B (EBI/PGWControlTEID mismatch) — Snapshot is not atomic relative to Lock-protected writes", got)
	}
}
