package mvpsafety

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"
)

type Resource interface {
	Name() string
	Close(context.Context) error
	VerifyClosed(context.Context) error
}
type EvidenceSink interface {
	Save(context.Context, Report) (string, error)
}
type Step struct {
	Name   string
	Intent *Intent
	Run    func(context.Context) error
}
type Report struct {
	Status           string
	RunID            string
	Events           []string
	Errors           []string
	EvidenceHash     string
	UnjoinedCallback bool
}
type timing struct{ total, step, reserve, close, evidence time.Duration }
type Coordinator struct {
	mu        sync.Mutex
	p         Policy
	plan      Plan
	budget    *Budget
	sink      EvidenceSink
	resources []Resource
	state     string
	limits    timing
}

func NewCoordinator(p Policy, plan Plan, sink EvidenceSink) (*Coordinator, error) {
	if e := p.Validate(); e != nil {
		return nil, e
	}
	if !plan.intact() || sink == nil {
		return nil, fmt.Errorf("validated untampered plan and evidence sink required")
	}
	b, e := NewBudget(p)
	if e != nil {
		return nil, e
	}
	return &Coordinator{p: p, plan: plan, budget: b, sink: sink, state: "fresh", limits: timing{time.Duration(p.TotalSeconds) * time.Second, time.Duration(p.StepSeconds) * time.Second, time.Duration(p.CleanupReserveSeconds) * time.Second, time.Duration(p.CloseSeconds) * time.Second, time.Duration(p.EvidenceSeconds) * time.Second}}, nil
}
func (c *Coordinator) Register(r Resource) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.state != "fresh" && c.state != "running" {
		return ErrBlocked
	}
	if r == nil || len(c.resources) >= 4 {
		return fmt.Errorf("bounded resource registry")
	}
	for _, old := range c.resources {
		if old.Name() == r.Name() {
			return fmt.Errorf("duplicate resource")
		}
	}
	c.resources = append(c.resources, r)
	return nil
}
func bounded(ctx context.Context, f func(context.Context) error) (err error, joined bool) {
	ch := make(chan error, 1)
	go func() {
		defer func() {
			if recover() != nil {
				ch <- fmt.Errorf("callback panic")
			}
		}()
		ch <- f(ctx)
	}()
	select {
	case e := <-ch:
		return e, true
	case <-ctx.Done():
		select {
		case e := <-ch:
			return errors.Join(ctx.Err(), e), true
		default:
			return ctx.Err(), false
		}
	}
}
func deadlineContext(end time.Time, d time.Duration) (context.Context, context.CancelFunc) {
	limit := time.Now().Add(d)
	if end.Before(limit) {
		limit = end
	}
	return context.WithDeadline(context.Background(), limit)
}
func (c *Coordinator) Run(parent context.Context, steps []Step) (Report, error) {
	c.mu.Lock()
	if c.state != "fresh" {
		c.mu.Unlock()
		return Report{Status: "BLOCKED"}, ErrBlocked
	}
	c.state = "running"
	c.mu.Unlock()
	r := Report{Status: "CHECKS_COMPLETE", RunID: c.plan.RunID}
	start := time.Now()
	end := start.Add(c.limits.total)
	work, cancel := context.WithDeadline(parent, end.Add(-c.limits.reserve))
	defer cancel()
	fail := func(e error) { r.Errors = append(r.Errors, e.Error()) }
	if len(steps) > int(c.p.MaxTransactions) {
		fail(fmt.Errorf("step count exceeds bounded plan"))
		steps = nil
	}
	for _, step := range steps {
		if work.Err() != nil {
			fail(work.Err())
			break
		}
		if step.Name == "" || step.Run == nil {
			fail(fmt.Errorf("invalid step"))
			break
		}
		if step.Intent != nil {
			if e := c.budget.Reserve(*step.Intent); e != nil {
				fail(e)
				break
			}
		}
		r.Events = append(r.Events, "begin:"+step.Name)
		ctx, stop := context.WithTimeout(work, c.limits.step)
		e, joined := bounded(ctx, step.Run)
		stop()
		r.UnjoinedCallback = r.UnjoinedCallback || !joined
		if e != nil {
			fail(fmt.Errorf("stage %s: %w", step.Name, e))
			break
		}
		r.Events = append(r.Events, "end:"+step.Name)
	}
	cancel()
	c.mu.Lock()
	c.state = "cleaning"
	resources := append([]Resource{}, c.resources...)
	c.mu.Unlock()
	for i := len(resources) - 1; i >= 0; i-- {
		resource := resources[i]
		ctx, stop := deadlineContext(end, c.limits.close)
		r.Events = append(r.Events, "close:"+resource.Name())
		e, joined := bounded(ctx, resource.Close)
		stop()
		r.UnjoinedCallback = r.UnjoinedCallback || !joined
		if e != nil {
			fail(fmt.Errorf("close %s: %w", resource.Name(), e))
		}
		ctx, stop = deadlineContext(end, c.limits.close)
		r.Events = append(r.Events, "verify:"+resource.Name())
		e, joined = bounded(ctx, resource.VerifyClosed)
		stop()
		r.UnjoinedCallback = r.UnjoinedCallback || !joined
		if e != nil {
			fail(fmt.Errorf("verify %s: %w", resource.Name(), e))
		}
	}
	if r.UnjoinedCallback {
		fail(fmt.Errorf("callback did not join within deadline; unsafe continuation blocked"))
	}
	if time.Now().After(end) {
		fail(fmt.Errorf("overall runtime deadline exceeded"))
	}
	if len(r.Errors) > 0 {
		r.Status = "BLOCKED"
	}
	ctx, stop := deadlineContext(end, c.limits.evidence)
	var hash string
	saveErr, joined := bounded(ctx, func(ctx context.Context) error { var e error; hash, e = c.sink.Save(ctx, r); return e })
	stop()
	validHash := false
	if joined {
		decoded, e := hex.DecodeString(hash)
		validHash = e == nil && len(decoded) == 32
	}
	if saveErr != nil || !joined || !validHash {
		fail(fmt.Errorf("evidence preservation failed"))
		r.Status = "BLOCKED"
	} else {
		r.EvidenceHash = hash
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(r.Errors) > 0 {
		c.state = "blocked"
		return r, fmt.Errorf("%w: %v", ErrBlocked, r.Errors)
	}
	c.state = "closed"
	r.Status = "PASS"
	return r, nil
}
