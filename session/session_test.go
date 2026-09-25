package session

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/streamingfast/dsession"
	pbworker "github.com/streamingfast/worker-pool-protocol/pb/sf/worker/v1"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// fakeWorkerPoolClient is a thread-safe fake implementing pbworker.WorkerPoolClient
type fakeWorkerPoolClient struct {
	mu sync.Mutex

	nextSessionID int
	nextWorkerID  int

	// configuration for behavior
	keepAliveErrOnce error         // if set, first KeepAlive returns this error
	returnBlock      chan struct{} // if set, ReturnWorker waits until it is closed or its context ends

	// recordings
	borrowRequests []*pbworker.BorrowWorkerRequest
	keepAlives     []*pbworker.KeepAliveRequest
	returned       []*pbworker.ReturnWorkerRequest
}

func newFakeWorkerPoolClient() *fakeWorkerPoolClient {
	return &fakeWorkerPoolClient{nextSessionID: 1, nextWorkerID: 1}
}

func (f *fakeWorkerPoolClient) BorrowWorker(ctx context.Context, in *pbworker.BorrowWorkerRequest, _ ...grpc.CallOption) (*pbworker.BorrowWorkerResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.borrowRequests = append(f.borrowRequests, in)

	// Distinguish session vs worker by MaxWorkerForTraceId field (0 for session per our usage)
	if in.GetMaxWorkerForTraceId() == 0 {
		key := fmt.Sprintf("session-%d", f.nextSessionID)
		f.nextSessionID++
		return &pbworker.BorrowWorkerResponse{
			Status:    pbworker.BorrowWorkerResponse_borrowed,
			WorkerKey: key,
		}, nil
	}

	// Worker borrow
	key := fmt.Sprintf("worker-%d", f.nextWorkerID)
	f.nextWorkerID++
	return &pbworker.BorrowWorkerResponse{
		Status:    pbworker.BorrowWorkerResponse_borrowed,
		WorkerKey: key,
	}, nil
}

// KeepAlive simulates a keep alive, optionally failing once with configured error
func (f *fakeWorkerPoolClient) KeepAlive(ctx context.Context, in *pbworker.KeepAliveRequest, _ ...grpc.CallOption) (*pbworker.KeepAliveResponse, error) {
	f.mu.Lock()
	f.keepAlives = append(f.keepAlives, in)
	var err error
	if f.keepAliveErrOnce != nil {
		err = f.keepAliveErrOnce
		f.keepAliveErrOnce = nil
	}
	f.mu.Unlock()
	if err != nil {
		return nil, err
	}
	return &pbworker.KeepAliveResponse{}, nil
}

func (f *fakeWorkerPoolClient) ReturnWorker(ctx context.Context, in *pbworker.ReturnWorkerRequest, _ ...grpc.CallOption) (*pbworker.ReturnWorkerResponse, error) {
	if f.returnBlock != nil {
		select {
		case <-f.returnBlock:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}

	f.mu.Lock()
	defer f.mu.Unlock()
	f.returned = append(f.returned, in)
	return &pbworker.ReturnWorkerResponse{}, nil
}

func (f *fakeWorkerPoolClient) returnedKeys() map[string]int {
	f.mu.Lock()
	defer f.mu.Unlock()

	keys := make(map[string]int)
	for _, r := range f.returned {
		keys[r.WorkerKey]++
	}
	return keys
}

func (f *fakeWorkerPoolClient) returnedRequest(workerKey string) *pbworker.ReturnWorkerRequest {
	f.mu.Lock()
	defer f.mu.Unlock()

	for _, r := range f.returned {
		if r.WorkerKey == workerKey {
			return r
		}
	}
	return nil
}

// implement unused interface method to satisfy WorkerPoolClient
func (f *fakeWorkerPoolClient) WorkersState(ctx context.Context, in *pbworker.WorkersStateRequest, _ ...grpc.CallOption) (*pbworker.WorkersStateResponse, error) {
	return &pbworker.WorkersStateResponse{}, nil
}

// Ensure fake satisfies the interface at compile time
var _ pbworker.WorkerPoolClient = (*fakeWorkerPoolClient)(nil)

func TestSessionMutex_WithKeepAliveAndRelease_NoPanic(t *testing.T) {
	t.Parallel()

	cfg := &Config{RequestKeepAliveDelay: 10 * time.Millisecond, MinimalWorkerLifeDuration: 10 * time.Millisecond}
	fake := newFakeWorkerPoolClient()
	pool := &tgmSessionPool{
		config:                 cfg,
		logger:                 zap.NewNop(),
		remoteWorkerPoolClient: fake,
		sessions:               make(map[string]*sessionInfo),
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Borrow a session (worker) -> starts keepalive
	key, err := pool.Get(ctx, "svc", "org1", "api1", "trace-1", nil)
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}

	// Allow a couple of keepalive ticks
	time.Sleep(25 * time.Millisecond)

	// Concurrently release while keepalive may be running
	done := make(chan struct{})
	go func() {
		pool.Release(key)
		close(done)
	}()

	select {
	case <-done:
		// ok
	case <-time.After(500 * time.Millisecond):
		t.Fatalf("Release did not complete in time (possible deadlock)")
	}
}

func TestGetWorker_Tracking_AddRemove_UnderMutex(t *testing.T) {
	t.Parallel()

	cfg := &Config{RequestKeepAliveDelay: time.Hour, MinimalWorkerLifeDuration: 10 * time.Millisecond}
	fake := newFakeWorkerPoolClient()
	pool := &tgmSessionPool{
		config:                 cfg,
		logger:                 zap.NewNop(),
		remoteWorkerPoolClient: fake,
		sessions:               make(map[string]*sessionInfo),
	}

	ctx := context.Background()
	sessionKey, err := pool.Get(ctx, "svc", "org2", "api2", "trace-2", nil)
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}

	// Borrow several workers concurrently
	const n = 5
	var wg sync.WaitGroup
	workerKeys := make([]string, n)
	errs := make([]error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			wkey, err := pool.GetWorker(ctx, "svc", sessionKey, n)
			workerKeys[idx] = wkey
			errs[idx] = err
		}(i)
	}
	wg.Wait()

	for i, e := range errs {
		if e != nil {
			t.Fatalf("GetWorker %d failed: %v", i, e)
		}
		if workerKeys[i] == "" {
			t.Fatalf("GetWorker %d returned empty key", i)
		}
	}

	// Release some workers explicitly
	for i := 0; i < n/2; i++ {
		pool.ReleaseWorker(workerKeys[i])
	}

	// Release the session, which should release remaining workers
	pool.Release(sessionKey)

	// Wait until the fake observed returns for all workers and the session
	deadline := time.Now().Add(2 * time.Second)
	for {
		fake.mu.Lock()
		count := len(fake.returned)
		fake.mu.Unlock()
		if count >= n+1 { // n workers + 1 session
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for ReturnWorker calls, have %d want %d", count, n+1)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestKeepAlive_OnPermissionDenied_TriggersOnError(t *testing.T) {
	t.Parallel()

	cfg := &Config{RequestKeepAliveDelay: 5 * time.Millisecond, MinimalWorkerLifeDuration: 10 * time.Millisecond}
	fake := newFakeWorkerPoolClient()
	fake.keepAliveErrOnce = status.Error(codes.PermissionDenied, "nope")

	pool := &tgmSessionPool{
		config:                 cfg,
		logger:                 zap.NewNop(),
		remoteWorkerPoolClient: fake,
		sessions:               make(map[string]*sessionInfo),
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	onError := func(err error) {
		errCh <- err
	}

	_, err := pool.Get(ctx, "svc", "org3", "api3", "trace-3", onError)
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}

	select {
	case e := <-errCh:
		if !errors.Is(e, dsession.ErrPermissionDenied) {
			t.Fatalf("expected ErrPermissionDenied, got %v", e)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatalf("onError was not called in time")
	}
}

func newTestPool(fake *fakeWorkerPoolClient) *tgmSessionPool {
	return &tgmSessionPool{
		config:                 &Config{RequestKeepAliveDelay: time.Hour, MinimalWorkerLifeDuration: 5 * time.Second},
		logger:                 zap.NewNop(),
		remoteWorkerPoolClient: fake,
		sessions:               make(map[string]*sessionInfo),
	}
}

func TestClose_ReturnsHeldSessionsAndWorkers(t *testing.T) {
	t.Parallel()

	fake := newFakeWorkerPoolClient()
	pool := newTestPool(fake)
	ctx := context.Background()

	sessionA, err := pool.Get(ctx, "svc", "org", "api", "trace-a", nil)
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}
	sessionB, err := pool.Get(ctx, "svc", "org", "api", "trace-b", nil)
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}
	worker, err := pool.GetWorker(ctx, "svc", sessionA, 5)
	if err != nil {
		t.Fatalf("GetWorker failed: %v", err)
	}

	if err := pool.Close(ctx); err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	returned := fake.returnedKeys()
	for _, key := range []string{sessionA, sessionB, worker} {
		if returned[key] != 1 {
			t.Fatalf("expected %q returned exactly once when Close returns, got %d (all: %v)", key, returned[key], returned)
		}
	}

	// The process is going away, so the session server must free the slot immediately.
	if got := fake.returnedRequest(sessionA).GetMinimalWorkerLifeDuration().AsDuration(); got != 0 {
		t.Fatalf("expected no minimal lifetime on close, got %s", got)
	}

	pool.sessionsMutex.Lock()
	remaining := len(pool.sessions)
	pool.sessionsMutex.Unlock()
	if remaining != 0 {
		t.Fatalf("expected no tracked sessions after Close, got %d", remaining)
	}
}

func TestClose_WaitsForReleasesInFlight(t *testing.T) {
	t.Parallel()

	fake := newFakeWorkerPoolClient()
	pool := newTestPool(fake)
	ctx := context.Background()

	session, err := pool.Get(ctx, "svc", "org", "api", "trace", nil)
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}

	fake.returnBlock = make(chan struct{})
	pool.Release(session)

	// Wait until Release owns the return, so Close has nothing left to return itself and can only
	// finish by waiting for it.
	for deadline := time.Now().Add(time.Second); ; time.Sleep(time.Millisecond) {
		pool.sessionsMutex.Lock()
		remaining := len(pool.sessions)
		pool.sessionsMutex.Unlock()
		if remaining == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("Release did not take the session")
		}
	}

	closed := make(chan error, 1)
	go func() { closed <- pool.Close(ctx) }()

	select {
	case err := <-closed:
		t.Fatalf("Close returned (%v) before the in-flight Release reached the session server", err)
	case <-time.After(50 * time.Millisecond):
	}

	close(fake.returnBlock)

	select {
	case err := <-closed:
		if err != nil {
			t.Fatalf("Close failed: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatalf("Close did not return after the release completed")
	}

	if got := fake.returnedKeys()[session]; got != 1 {
		t.Fatalf("expected session returned exactly once, got %d", got)
	}
	// Released by the request itself, before Close, so the normal minimal lifetime applies.
	if got := fake.returnedRequest(session).GetMinimalWorkerLifeDuration().AsDuration(); got != 5*time.Second {
		t.Fatalf("expected the configured minimal lifetime on Release, got %s", got)
	}
}

func TestClose_ReleaseRacingCloseReturnsEachSessionOnce(t *testing.T) {
	t.Parallel()

	fake := newFakeWorkerPoolClient()
	pool := newTestPool(fake)
	ctx := context.Background()

	const n = 50
	sessions := make([]string, n)
	for i := range sessions {
		key, err := pool.Get(ctx, "svc", "org", "api", fmt.Sprintf("trace-%d", i), nil)
		if err != nil {
			t.Fatalf("Get failed: %v", err)
		}
		sessions[i] = key
	}

	var wg sync.WaitGroup
	for _, key := range sessions {
		wg.Add(1)
		go func() {
			defer wg.Done()
			pool.Release(key)
		}()
	}
	if err := pool.Close(ctx); err != nil {
		t.Fatalf("Close failed: %v", err)
	}
	wg.Wait()

	returned := fake.returnedKeys()
	for _, key := range sessions {
		if returned[key] != 1 {
			t.Fatalf("expected %q returned exactly once, got %d", key, returned[key])
		}
	}
}

func TestClose_RefusesNewSessionsAndReturnsTheBorrowedOne(t *testing.T) {
	t.Parallel()

	fake := newFakeWorkerPoolClient()
	pool := newTestPool(fake)
	ctx := context.Background()

	if err := pool.Close(ctx); err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	_, err := pool.Get(ctx, "svc", "org", "api", "trace", nil)
	if !errors.Is(err, dsession.ErrUnavailable) {
		t.Fatalf("expected ErrUnavailable after Close, got %v", err)
	}

	if got := fake.returnedKeys()["session-1"]; got != 1 {
		t.Fatalf("expected the session borrowed after Close to be returned, got %d", got)
	}
}

func TestClose_GivesUpAtContextDeadline(t *testing.T) {
	t.Parallel()

	fake := newFakeWorkerPoolClient()
	pool := newTestPool(fake)

	if _, err := pool.Get(context.Background(), "svc", "org", "api", "trace", nil); err != nil {
		t.Fatalf("Get failed: %v", err)
	}

	fake.returnBlock = make(chan struct{})
	defer close(fake.returnBlock)

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	if err := pool.Close(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected DeadlineExceeded, got %v", err)
	}
}
