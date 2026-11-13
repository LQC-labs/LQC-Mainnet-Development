//go:build linux

package mvpsafety

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"syscall"
	"time"
)

type CleanupEvent struct {
	Check     string
	OK        bool
	ElapsedNS int64
}

// CleanupObservation adds independent post-close probes without starting a
// listener/process or opening a DB. Register it with the existing Coordinator.
type CleanupObservation struct {
	mu        sync.Mutex
	start     time.Time
	events    []CleanupEvent
	owner     Resource
	probe     CleanupProbe
	home, rpc string
	children  []Resource
}

func NewCleanupObservation(plan Plan, rpc string, owner Resource, probe CleanupProbe, children []Resource) (*CleanupObservation, error) {
	if !plan.intact() || owner == nil || probe == nil || len(children) > 2 {
		return nil, fmt.Errorf("sealed plan/bounded cleanup inventory required")
	}
	if _, e := LocalRPC("http://" + rpc); e != nil {
		return nil, e
	}
	for _, c := range children {
		if c == nil {
			return nil, fmt.Errorf("missing owned child")
		}
	}
	return &CleanupObservation{start: time.Now(), owner: owner, probe: probe, home: plan.Home, rpc: rpc, children: append([]Resource{}, children...)}, nil
}
func (c *CleanupObservation) Name() string { return "observed-node-cleanup" }
func (c *CleanupObservation) record(label string, e error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.events = append(c.events, CleanupEvent{Check: label, OK: e == nil, ElapsedNS: time.Since(c.start).Nanoseconds()})
}
func (c *CleanupObservation) Trace() []CleanupEvent {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]CleanupEvent{}, c.events...)
}
func (c *CleanupObservation) Close(ctx context.Context) error {
	e := c.owner.Close(ctx)
	c.record("node-close", e)
	all := e
	for _, child := range c.children {
		e = child.Close(ctx)
		c.record("owned-child-close", e)
		all = errors.Join(all, e)
	}
	return all
}
func (c *CleanupObservation) VerifyClosed(ctx context.Context) error {
	var all error
	checks := []struct {
		label string
		f     func() error
	}{{"owner-resource-proof", func() error { return c.owner.VerifyClosed(ctx) }}, {"RPC-listener-closed", func() error { return c.probe.ListenerClosed(ctx, c.rpc) }}, {"DB-locks-released", func() error { return c.probe.DBsClosed(ctx, c.home) }}, {"home-lock-released", func() error { return c.probe.HomeUnlocked(ctx, c.home) }}}
	for _, check := range checks {
		e := check.f()
		c.record(check.label, e)
		all = errors.Join(all, e)
	}
	for _, child := range c.children {
		e := child.VerifyClosed(ctx)
		c.record("owned-child-wait-reap-proof", e)
		all = errors.Join(all, e)
	}
	return all
}

// ProcessObservation requires BOTH the existing Wait/reap proof and an
// independent process-group absence proof; parent exit alone is insufficient.
type ProcessObservation struct {
	Owned     Resource
	GroupGone func(context.Context) error
}

func (p ProcessObservation) Name() string { return "owned-process-group" }
func (p ProcessObservation) Close(ctx context.Context) error {
	if p.Owned == nil {
		return fmt.Errorf("missing owned process")
	}
	return p.Owned.Close(ctx)
}
func (p ProcessObservation) VerifyClosed(ctx context.Context) error {
	if p.Owned == nil || p.GroupGone == nil {
		return fmt.Errorf("process inventory/probe missing")
	}
	wait := p.Owned.VerifyClosed(ctx)
	group := p.GroupGone(ctx)
	return errors.Join(wait, group)
}

// Signal zero observes existence only; it never terminates or signals a process.
// Offline tests never call this OS probe. PID ownership must come from the
// current run's process supervisor, never from a user-supplied unrelated PID.
func LinuxOwnedGroupGone(ctx context.Context, pid int) error {
	if e := ctx.Err(); e != nil {
		return e
	}
	if pid <= 1 {
		return fmt.Errorf("invalid owned process group")
	}
	e := syscall.Kill(-pid, 0)
	if errors.Is(e, syscall.ESRCH) {
		return nil
	}
	return fmt.Errorf("owned group still present or absence unproven")
}
