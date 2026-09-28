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
	keepAliveErrOnce error // if set, first KeepAlive returns this error
	returnErr        error // if set, every ReturnWorker fails with it

	// Gates hold the calls they apply to until closed, or until the call's context ends.
	borrowGate    chan struct{}
	keepAliveGate chan struct{}
	returnGate    chan struct{}
	gateReturn    func(*pbworker.ReturnWorkerRequest) bool // which returns returnGate holds, all if nil

	// calls currently held at a gate, by method
	held map[string]int

	// recordings
	borrowRequests []*pbworker.BorrowWorkerRequest
	keepAlives     []*pbworker.KeepAliveRequest
	returned       []*pbworker.ReturnWorkerRequest
}

func newFakeWorkerPoolClient() *fakeWorkerPoolClient {
	return &fakeWorkerPoolClient{nextSessionID: 1, nextWorkerID: 1, held: make(map[string]int)}
}

func (f *fakeWorkerPoolClient) pass(ctx context.Context, method string, gate chan struct{}) error {
	if gate == nil {
		return nil
	}

	f.mu.Lock()
	f.held[method]++
	f.mu.Unlock()
	defer func() {
		f.mu.Lock()
		f.held[method]--
		f.mu.Unlock()
	}()

	select {
	case <-gate:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (f *fakeWorkerPoolClient) waitHeld(t *testing.T, method string, n int) {
	t.Helper()

	for deadline := time.Now().Add(time.Second); ; time.Sleep(time.Millisecond) {
		f.mu.Lock()
		held := f.held[method]
		f.mu.Unlock()
		if held == n {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("expected %d held %s calls, have %d", n, method, held)
		}
	}
}

// returnedLifetimes maps each returned key to the minimal lifetime of every return received for it.
func (f *fakeWorkerPoolClient) returnedLifetimes() map[string][]time.Duration {
	f.mu.Lock()
	defer f.mu.Unlock()

	lifetimes := make(map[string][]time.Duration)
	for _, r := range f.returned {
		lifetimes[r.WorkerKey] = append(lifetimes[r.WorkerKey], r.GetMinimalWorkerLifeDuration().AsDuration())
	}
	return lifetimes
}

func (f *fakeWorkerPoolClient) counts() (borrows, keepAlives, returns int) {
	f.mu.Lock()
	defer f.mu.Unlock()

	return len(f.borrowRequests), len(f.keepAlives), len(f.returned)
}

func (f *fakeWorkerPoolClient) BorrowWorker(ctx context.Context, in *pbworker.BorrowWorkerRequest, _ ...grpc.CallOption) (*pbworker.BorrowWorkerResponse, error) {
	if err := f.pass(ctx, "BorrowWorker", f.borrowGate); err != nil {
		return nil, err
	}

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
	if err := f.pass(ctx, "KeepAlive", f.keepAliveGate); err != nil {
		return nil, err
	}

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
	if f.gateReturn == nil || f.gateReturn(in) {
		if err := f.pass(ctx, "ReturnWorker", f.returnGate); err != nil {
			return nil, err
		}
	}

	f.mu.Lock()
	defer f.mu.Unlock()
	if f.returnErr != nil {
		return nil, f.returnErr
	}
	f.returned = append(f.returned, in)
	return &pbworker.ReturnWorkerResponse{}, nil
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

// gateSessionReleases holds the session returns sent by Release, recognizable by their non-zero
// minimal lifetime.
func gateSessionReleases(fake *fakeWorkerPoolClient) {
	fake.returnGate = make(chan struct{})
	fake.gateReturn = func(in *pbworker.ReturnWorkerRequest) bool {
		return in.GetMinimalWorkerLifeDuration().AsDuration() > 0
	}
}

func closeAsync(pool *tgmSessionPool, ctx context.Context) <-chan error {
	closed := make(chan error, 1)
	go func() { closed <- pool.Close(ctx) }()
	return closed
}

func requireBlocked(t *testing.T, closed <-chan error) {
	t.Helper()

	select {
	case err := <-closed:
		t.Fatalf("Close returned (%v) while work was still under way", err)
	case <-time.After(50 * time.Millisecond):
	}
}

func requireClosed(t *testing.T, closed <-chan error) {
	t.Helper()

	select {
	case err := <-closed:
		if err != nil {
			t.Fatalf("Close failed: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatalf("Close did not return")
	}
}

func TestClose_ReturnsTrackedSessionsAndWorkers(t *testing.T) {
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

	returned := fake.returnedLifetimes()
	if len(returned[worker]) != 1 {
		t.Fatalf("expected worker returned once, got %v", returned)
	}
	for _, key := range []string{sessionA, sessionB} {
		// The process is going away, so the session server must free the slot immediately.
		if got := returned[key]; len(got) != 1 || got[0] != 0 {
			t.Fatalf("expected %q returned once with no minimal lifetime, got %v", key, got)
		}
	}
}

func TestClose_WaitsForReleaseInFlight(t *testing.T) {
	t.Parallel()

	fake := newFakeWorkerPoolClient()
	gateSessionReleases(fake)
	pool := newTestPool(fake)

	session, err := pool.Get(context.Background(), "svc", "org", "api", "trace", nil)
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}

	pool.Release(session)
	fake.waitHeld(t, "ReturnWorker", 1)

	closed := closeAsync(pool, context.Background())
	requireBlocked(t, closed)

	close(fake.returnGate)
	requireClosed(t, closed)

	if got := fake.returnedLifetimes()[session]; len(got) != 1 || got[0] != 5*time.Second {
		t.Fatalf("expected the session returned once, by Release, got %v", got)
	}
}

func TestClose_WaitsForBorrowInFlight(t *testing.T) {
	t.Parallel()

	fake := newFakeWorkerPoolClient()
	fake.borrowGate = make(chan struct{})
	pool := newTestPool(fake)

	borrowed := make(chan string, 1)
	go func() {
		key, err := pool.Get(context.Background(), "svc", "org", "api", "trace", nil)
		if err != nil {
			t.Errorf("Get failed: %v", err)
		}
		borrowed <- key
	}()
	fake.waitHeld(t, "BorrowWorker", 1)

	closed := closeAsync(pool, context.Background())
	requireBlocked(t, closed)

	close(fake.borrowGate)
	requireClosed(t, closed)

	session := <-borrowed
	if got := fake.returnedLifetimes()[session]; len(got) != 1 || got[0] != 0 {
		t.Fatalf("expected the session borrowed during Close returned once by Close, got %v", got)
	}
}

func TestClose_RefusesNewBorrows(t *testing.T) {
	t.Parallel()

	fake := newFakeWorkerPoolClient()
	pool := newTestPool(fake)
	ctx := context.Background()

	session, err := pool.Get(ctx, "svc", "org", "api", "trace", nil)
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}
	if err := pool.Close(ctx); err != nil {
		t.Fatalf("Close failed: %v", err)
	}
	borrowsBefore, _, _ := fake.counts()

	if _, err := pool.Get(ctx, "svc", "org", "api", "trace-2", nil); !errors.Is(err, dsession.ErrUnavailable) {
		t.Fatalf("expected ErrUnavailable from Get after Close, got %v", err)
	}
	if _, err := pool.GetWorker(ctx, "svc", session, 5); !errors.Is(err, dsession.ErrSessionNotFound) {
		t.Fatalf("expected ErrSessionNotFound from GetWorker after Close, got %v", err)
	}

	if borrows, _, _ := fake.counts(); borrows != borrowsBefore {
		t.Fatalf("expected no borrow sent after Close, got %d more", borrows-borrowsBefore)
	}
}

func TestClose_LaterCallsWaitForTheFirst(t *testing.T) {
	t.Parallel()

	fake := newFakeWorkerPoolClient()
	pool := newTestPool(fake)

	session, err := pool.Get(context.Background(), "svc", "org", "api", "trace", nil)
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}

	fake.returnGate = make(chan struct{})
	first := closeAsync(pool, context.Background())
	fake.waitHeld(t, "ReturnWorker", 1)

	second := closeAsync(pool, context.Background())
	requireBlocked(t, second)

	close(fake.returnGate)
	requireClosed(t, first)
	requireClosed(t, second)

	if got := fake.returnedLifetimes()[session]; len(got) != 1 {
		t.Fatalf("expected the session returned once across Close calls, got %v", got)
	}
}

func TestClose_StopsKeepAlive(t *testing.T) {
	t.Parallel()

	fake := newFakeWorkerPoolClient()
	pool := newTestPool(fake)
	pool.config.RequestKeepAliveDelay = 5 * time.Millisecond

	if _, err := pool.Get(context.Background(), "svc", "org", "api", "trace", nil); err != nil {
		t.Fatalf("Get failed: %v", err)
	}
	if err := pool.Close(context.Background()); err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	// Allow a keep-alive that was already running when Close returned to finish.
	time.Sleep(10 * time.Millisecond)
	_, before, _ := fake.counts()
	time.Sleep(50 * time.Millisecond)
	if _, after, _ := fake.counts(); after != before {
		t.Fatalf("expected no keep-alive after Close, got %d more", after-before)
	}
}

func TestClose_ReportsFailedReturns(t *testing.T) {
	t.Parallel()

	fake := newFakeWorkerPoolClient()
	fake.returnErr = status.Error(codes.Unavailable, "down")
	pool := newTestPool(fake)

	if _, err := pool.Get(context.Background(), "svc", "org", "api", "trace", nil); err != nil {
		t.Fatalf("Get failed: %v", err)
	}

	if err := pool.Close(context.Background()); err == nil {
		t.Fatalf("expected Close to report the failed return")
	}
}

func TestClose_GivesUpAtContextDeadline(t *testing.T) {
	t.Parallel()

	fake := newFakeWorkerPoolClient()
	gateSessionReleases(fake)
	defer close(fake.returnGate)
	pool := newTestPool(fake)

	session, err := pool.Get(context.Background(), "svc", "org", "api", "trace", nil)
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}
	pool.Release(session)
	fake.waitHeld(t, "ReturnWorker", 1)

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	if err := pool.Close(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected DeadlineExceeded, got %v", err)
	}
}

func TestRelease_WaitsForKeepAliveInFlight(t *testing.T) {
	t.Parallel()

	fake := newFakeWorkerPoolClient()
	fake.keepAliveGate = make(chan struct{})
	pool := newTestPool(fake)
	pool.config.RequestKeepAliveDelay = 5 * time.Millisecond

	session, err := pool.Get(context.Background(), "svc", "org", "api", "trace", nil)
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}
	fake.waitHeld(t, "KeepAlive", 1)

	pool.Release(session)
	time.Sleep(50 * time.Millisecond)
	if _, _, returns := fake.counts(); returns != 0 {
		t.Fatalf("expected the return to wait for the keep-alive in flight")
	}

	close(fake.keepAliveGate)
	if err := pool.Close(context.Background()); err != nil {
		t.Fatalf("Close failed: %v", err)
	}
	if got := fake.returnedLifetimes()[session]; len(got) != 1 {
		t.Fatalf("expected the session returned once, got %v", got)
	}
}

func TestReleaseWorker_SkipsWorkerReturnedWithItsSession(t *testing.T) {
	t.Parallel()

	fake := newFakeWorkerPoolClient()
	pool := newTestPool(fake)
	ctx := context.Background()

	session, err := pool.Get(ctx, "svc", "org", "api", "trace", nil)
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}
	worker, err := pool.GetWorker(ctx, "svc", session, 5)
	if err != nil {
		t.Fatalf("GetWorker failed: %v", err)
	}

	pool.Release(session)
	pool.ReleaseWorker(worker)
	if err := pool.Close(ctx); err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	if got := fake.returnedLifetimes()[worker]; len(got) != 1 {
		t.Fatalf("expected the worker returned once, got %v", got)
	}
}

func TestGetWorker_RefusesReleasedSession(t *testing.T) {
	t.Parallel()

	fake := newFakeWorkerPoolClient()
	gateSessionReleases(fake)
	defer close(fake.returnGate)
	pool := newTestPool(fake)
	ctx := context.Background()

	session, err := pool.Get(ctx, "svc", "org", "api", "trace", nil)
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}
	pool.Release(session)
	fake.waitHeld(t, "ReturnWorker", 1)

	if _, err := pool.GetWorker(ctx, "svc", session, 5); !errors.Is(err, dsession.ErrSessionNotFound) {
		t.Fatalf("expected ErrSessionNotFound for a released session, got %v", err)
	}
}
