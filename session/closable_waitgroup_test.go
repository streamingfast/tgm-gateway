package session

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestClosableWaitGroup(t *testing.T) {
	t.Parallel()

	var g closableWaitGroup
	if !g.TryAdd() {
		t.Fatalf("expected TryAdd to succeed before close")
	}

	closed := make(chan error, 1)
	go func() { closed <- g.CloseAndWait(context.Background()) }()

	select {
	case err := <-closed:
		t.Fatalf("CloseAndWait returned (%v) before the work added was done", err)
	case <-time.After(50 * time.Millisecond):
	}

	if g.TryAdd() {
		t.Fatalf("expected TryAdd to fail once closed")
	}

	g.Done()
	select {
	case err := <-closed:
		if err != nil {
			t.Fatalf("CloseAndWait failed: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatalf("CloseAndWait did not return once the work was done")
	}
}

func TestClosableWaitGroup_CloseAndWaitGivesUpAtContextDeadline(t *testing.T) {
	t.Parallel()

	var g closableWaitGroup
	if !g.TryAdd() {
		t.Fatalf("expected TryAdd to succeed before close")
	}
	defer g.Done()

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	if err := g.CloseAndWait(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected DeadlineExceeded, got %v", err)
	}
}
