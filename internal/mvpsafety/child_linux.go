//go:build linux

package mvpsafety

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"path/filepath"
	"sync"
	"syscall"
	"time"
)

// Child owns a single process group and starts exactly one Wait goroutine.
// Context cancellation always triggers group termination; non-zero child exit
// due to requested termination is distinct from a failure to terminate/reap.
type Child struct {
	cmd       *exec.Cmd
	done      chan struct{}
	stopWatch chan struct{}
	stopOnce  sync.Once
	grace     time.Duration
	signal    func(int, syscall.Signal) error
	mu        sync.Mutex
	signalErr error
}

func StartChild(ctx context.Context, exe string, args []string, grace time.Duration) (*Child, error) {
	if ctx == nil || ctx.Err() != nil || !filepath.IsAbs(exe) || grace <= 0 || grace > time.Second {
		return nil, fmt.Errorf("bounded absolute child command required")
	}
	cmd := exec.Command(exe, args...)
	cmd.Env = []string{"PATH=/usr/bin:/bin"}
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	c := &Child{cmd: cmd, done: make(chan struct{}), stopWatch: make(chan struct{}), grace: grace, signal: syscall.Kill}
	if e := cmd.Start(); e != nil {
		return nil, e
	}
	go func() { _ = cmd.Wait(); close(c.done) }()
	go func() {
		select {
		case <-ctx.Done():
			_ = c.Close(context.Background())
		case <-c.stopWatch:
		case <-c.done:
		}
	}()
	return c, nil
}
func (c *Child) Name() string { return "owned-child" }
func (c *Child) send(s syscall.Signal) error {
	e := c.signal(-c.cmd.Process.Pid, s)
	if errors.Is(e, syscall.ESRCH) {
		return nil
	}
	if e != nil {
		c.mu.Lock()
		c.signalErr = e
		c.mu.Unlock()
	}
	return e
}
func (c *Child) Close(ctx context.Context) error {
	c.stopOnce.Do(func() { close(c.stopWatch) })
	select {
	case <-c.done:
		return nil
	default:
	}
	_ = c.send(syscall.SIGTERM)
	timer := time.NewTimer(c.grace)
	defer timer.Stop()
	select {
	case <-c.done:
		return nil
	case <-timer.C:
	case <-ctx.Done():
	}
	_ = c.send(syscall.SIGKILL)
	// Reap wait is bounded even when the caller supplied no deadline.
	timer2 := time.NewTimer(c.grace)
	defer timer2.Stop()
	select {
	case <-c.done:
		return nil
	case <-timer2.C:
		return fmt.Errorf("child did not terminate/reap")
	case <-ctx.Done():
		select {
		case <-c.done:
			return nil
		default:
			return fmt.Errorf("child reap deadline")
		}
	}
}
func (c *Child) VerifyClosed(context.Context) error {
	select {
	case <-c.done:
		if c.cmd.ProcessState == nil || !c.cmd.ProcessState.Exited() && c.cmd.ProcessState.Sys() == nil {
			return fmt.Errorf("Wait did not reap process")
		}
		return nil
	default:
		return fmt.Errorf("child still alive/unreaped")
	}
}
