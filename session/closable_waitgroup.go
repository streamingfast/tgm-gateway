package session

import (
	"context"
	"sync"
)

// closableWaitGroup is a WaitGroup that stops accepting work once closed, so waiting after
// closing covers everything that was ever added.
type closableWaitGroup struct {
	mu     sync.Mutex
	closed bool
	wg     sync.WaitGroup
}

// TryAdd adds one unit of work, or reports false once the group is closed. Every successful
// TryAdd must be matched by a Done.
func (g *closableWaitGroup) TryAdd() bool {
	g.mu.Lock()
	defer g.mu.Unlock()

	if g.closed {
		return false
	}
	g.wg.Add(1)

	return true
}

func (g *closableWaitGroup) Done() {
	g.wg.Done()
}

// CloseAndWait closes the group and waits for the work already added, unless ctx ends first. In
// that case the waiting goroutine lingers until that work is done.
func (g *closableWaitGroup) CloseAndWait(ctx context.Context) error {
	g.mu.Lock()
	g.closed = true
	g.mu.Unlock()

	done := make(chan struct{})
	go func() {
		g.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
