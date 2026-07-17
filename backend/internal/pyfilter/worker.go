package pyfilter

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"sync"
	"time"
)

// errTimeout is returned when the Python worker doesn't answer in time. The
// caller treats this as a dead worker and respawns.
var errTimeout = errors.New("pyfilter: worker timed out")

// scriptSpec is what we hand the harness for each script.
type scriptSpec struct {
	ID         string   `json:"id"`
	Name       string   `json:"name"`
	Code       string   `json:"code"`
	ServiceIDs []string `json:"service_ids,omitempty"`
	Directions []string `json:"directions,omitempty"`
	Protocols  []string `json:"protocols,omitempty"`
}

// Match is one script's verdict on a flow.
type Match struct {
	Script string `json:"script"`
	Name   string `json:"name"`
	Reason string `json:"reason"`
	// Block asks Janus to drop the CURRENT message synchronously (inline, on the
	// proxy hot path) — a request before it reaches the backend, or a response
	// before it reaches the client. Only honored for scripts marked Blocking;
	// produced by returning {"drop": True} or {"block": True} from match().
	Block bool `json:"block"`
	// Close is requested by flow.close(). TCP already closes on every blocked
	// message; protocols that support message drops may expose it as best-effort.
	Close bool `json:"close,omitempty"`
	Error bool `json:"error"`
}

type ConsoleLine struct {
	Script string `json:"script"`
	Text   string `json:"text"`
}

// worker wraps a single long-lived `python3 harness.py` process. The protocol
// is strictly request/response, so a mutex serializes access; there is no need
// for id-based response correlation.
type worker struct {
	cmd    *exec.Cmd
	stdin  io.WriteCloser
	stdout *bufio.Reader
	mu     sync.Mutex
	dead   bool
}

// spawnWorker starts a new Python worker running the embedded harness.
func spawnWorker(pythonPath, harness string) (*worker, error) {
	// The worker deliberately has no portable in-process "sandbox": OS-level
	// isolation and resource limits belong to the Janus deployment/container.
	// Keeping that boundary explicit avoids platform-specific half-sandboxes
	// that are easy to bypass while preserving local development support.
	cmd := exec.Command(pythonPath, "-u", "-c", harness)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	cmd.Stderr = nil // discard the interpreter's stderr; script errors travel in-band
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	return &worker{
		cmd:    cmd,
		stdin:  stdin,
		stdout: bufio.NewReaderSize(stdout, 64*1024),
	}, nil
}

// roundtrip writes one request and reads exactly one response line, bounded by
// timeout. On any error (including timeout) the worker is marked dead; callers
// must not reuse a dead worker.
func (w *worker) roundtrip(req any, timeout time.Duration, dst any) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.dead {
		return errors.New("pyfilter: worker is dead")
	}

	payload, err := json.Marshal(req)
	if err != nil {
		return err
	}
	payload = append(payload, '\n')
	if _, err := w.stdin.Write(payload); err != nil {
		w.terminateLocked()
		return err
	}

	type result struct {
		line []byte
		err  error
	}
	ch := make(chan result, 1)
	go func() {
		line, err := w.stdout.ReadBytes('\n')
		ch <- result{line, err}
	}()

	select {
	case r := <-ch:
		if r.err != nil {
			w.terminateLocked()
			return fmt.Errorf("pyfilter: read: %w", r.err)
		}
		if dst == nil {
			return nil
		}
		if err := json.Unmarshal(r.line, dst); err != nil {
			w.terminateLocked()
			return fmt.Errorf("pyfilter: decode: %w", err)
		}
		return nil
	case <-time.After(timeout):
		// The reader goroutine is still blocked; killing the process unblocks it
		// and the abandoned goroutine exits. Wait reaps the child before this
		// method returns, so repeated script timeouts cannot accumulate zombies.
		w.terminateLocked()
		return errTimeout
	}
}

// terminateLocked kills and reaps the interpreter. Caller holds w.mu.
func (w *worker) terminateLocked() {
	if w.dead {
		return
	}
	w.dead = true
	if w.stdin != nil {
		_ = w.stdin.Close()
	}
	if w.cmd != nil && w.cmd.Process != nil {
		_ = w.cmd.Process.Kill()
		_ = w.cmd.Wait()
	}
}

// stop terminates the worker process.
func (w *worker) stop() {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.terminateLocked()
}

func (w *worker) isDead() bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.dead
}
