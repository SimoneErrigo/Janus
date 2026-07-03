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
	ID   string `json:"id"`
	Name string `json:"name"`
	Code string `json:"code"`
}

// Match is one script's verdict on a flow.
type Match struct {
	Script string `json:"script"`
	Name   string `json:"name"`
	Reason string `json:"reason"`
	Error  bool   `json:"error"`
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
		w.dead = true
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
			w.dead = true
			return fmt.Errorf("pyfilter: read: %w", r.err)
		}
		if dst == nil {
			return nil
		}
		if err := json.Unmarshal(r.line, dst); err != nil {
			w.dead = true
			return fmt.Errorf("pyfilter: decode: %w", err)
		}
		return nil
	case <-time.After(timeout):
		// The reader goroutine is still blocked; killing the process unblocks it
		// and the abandoned goroutine exits. The worker is discarded.
		w.dead = true
		_ = w.cmd.Process.Kill()
		return errTimeout
	}
}

// stop terminates the worker process.
func (w *worker) stop() {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.dead = true
	if w.cmd != nil && w.cmd.Process != nil {
		_ = w.cmd.Process.Kill()
	}
}

func (w *worker) isDead() bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.dead
}
