package session

import (
	"context"
	"crypto/tls"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/streamingfast/dsession"
	pbworker "github.com/streamingfast/worker-pool-protocol/pb/sf/worker/v1"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/durationpb"
)

// Register registers the TGM session pool with dauth
func Register() {
	dsession.Register("tgm", func(config string, logger *zap.Logger) (dsession.SessionPool, error) {
		configExpanded := os.ExpandEnv(config)

		c, err := newConfig(configExpanded)
		if err != nil {
			return nil, fmt.Errorf("failed to parse config string %s: %w", config, err)
		}
		return newTGMSessionPool(c, logger)
	})
}

type sessionInfo struct {
	organizationID string
	apiKeyID       string
	traceID        string
	workers        map[string]struct{} // Track worker keys for this session
	closer         chan struct{}       // Channel to signal session closure
	mutex          sync.Mutex
}

type tgmSessionPool struct {
	config                 *Config
	logger                 *zap.Logger
	remoteWorkerPoolClient pbworker.WorkerPoolClient
	conn                   *grpc.ClientConn
	sessions               map[string]*sessionInfo // Map sessionKey -> session info
	sessionsMutex          sync.Mutex

	// returns counts the returns running in the background, so Close can wait for them. Outside
	// Close, a return is only added to it while holding sessionsMutex and before closed is set.
	returns sync.WaitGroup
	closed  bool // guarded by sessionsMutex
}

func newTGMSessionPool(config *Config, logger *zap.Logger) (dsession.SessionPool, error) {
	logger = logger.Named("tgm-session-pool")

	// Create gRPC connection
	var opts []grpc.DialOption
	if config.Plaintext {
		opts = append(opts, grpc.WithTransportCredentials(insecure.NewCredentials()))
	} else {
		tlsConfig := &tls.Config{}
		if config.Insecure {
			tlsConfig.InsecureSkipVerify = true
		}
		opts = append(opts, grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)))
	}

	// Add unary interceptor for X-Api-Key header if API key is provided
	if config.IndexerApiKey != "" {
		opts = append(opts, grpc.WithUnaryInterceptor(createApiKeyInterceptor(config.IndexerApiKey)))
	}

	conn, err := grpc.Dial(config.Endpoint, opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to session endpoint %s: %w", config.Endpoint, err)
	}

	client := pbworker.NewWorkerPoolClient(conn)

	pool := &tgmSessionPool{
		config:                 config,
		logger:                 logger,
		remoteWorkerPoolClient: client,
		conn:                   conn,
		sessions:               make(map[string]*sessionInfo),
		sessionsMutex:          sync.Mutex{},
	}

	return pool, nil
}

func (t *tgmSessionPool) Get(ctx context.Context, serviceName string, organizationID string, apiKeyID string, traceID string, onError func(error)) (string, error) {
	resp, err := t.remoteWorkerPoolClient.BorrowWorker(ctx,
		&pbworker.BorrowWorkerRequest{
			Service:        serviceName,
			OrganizationId: organizationID,
			ApiKeyId:       apiKeyID,
			TraceId:        traceID,
		},
		grpc.WaitForReady(false),
	)

	if err != nil {
		// Map gRPC errors to dsession errors
		if grpcErr, ok := status.FromError(err); ok {
			switch grpcErr.Code() {
			case codes.Unavailable:
				return "", fmt.Errorf("%w: %s", dsession.ErrUnavailable, grpcErr.Message())
			case codes.PermissionDenied:
				return "", fmt.Errorf("%w: %s", dsession.ErrPermissionDenied, grpcErr.Message())
			case codes.ResourceExhausted:
				return "", fmt.Errorf("%w: %s", dsession.ErrQuotaExceeded, grpcErr.Message())
			}
		}
		return "", fmt.Errorf("failed to borrow session: %w", err)
	}

	key := resp.WorkerKey
	workerStatus := resp.Status

	details := ""
	if maxWorkers := resp.WorkerState.GetMaxWorkers(); maxWorkers != 0 {
		details = fmt.Sprintf(" (active sessions: %d/%d)", maxWorkers, maxWorkers)
	}

	if workerStatus == pbworker.BorrowWorkerResponse_resource_exhausted {
		t.logger.Debug("session pool is exhausted", zap.String("status", workerStatus.String()), zap.String("details", details))
		return "", fmt.Errorf("%w%s", dsession.ErrConcurrentStreamLimitExceeded, details)
	}

	// Start keep-alive for borrowed workers
	if workerStatus == pbworker.BorrowWorkerResponse_borrowed {

		done := make(chan struct{})
		t.sessionsMutex.Lock()
		if t.closed {
			t.sessionsMutex.Unlock()

			// Close has already returned everything this pool held and nothing would return this one.
			t.returnRemote(ctx, key, durationpb.New(0))
			return "", fmt.Errorf("%w: session pool is closed", dsession.ErrUnavailable)
		}
		// Store session info for worker management
		t.sessions[key] = &sessionInfo{
			organizationID: organizationID,
			apiKeyID:       apiKeyID,
			traceID:        traceID,
			workers:        make(map[string]struct{}),
			closer:         done,
		}
		t.sessionsMutex.Unlock()

		t.startKeepAlive(ctx, done, key, onError)
	}

	t.logger.Debug("borrowed request worker", zap.String("worker_key", key))

	return key, nil
}

func (t *tgmSessionPool) Release(sessionKey string) {
	if !t.trackReturn() {
		// Close has already returned every session this pool held.
		return
	}

	go func() {
		defer t.returns.Done()

		t.returnSession(context.Background(), sessionKey, &durationpb.Duration{Seconds: int64(t.config.MinimalWorkerLifeDuration.Seconds())})
	}()
}

// Close returns every session the pool still holds, with its workers, and waits for the returns
// already running in the background. Call it once, right before the process exits: returns are
// otherwise fire-and-forget, and a session whose return never reached the session server stays
// counted against the organization until its keep-alive TTL runs out, while the client that lost
// its stream is already reconnecting. The pool refuses new sessions afterwards.
func (t *tgmSessionPool) Close(ctx context.Context) error {
	t.sessionsMutex.Lock()
	if t.closed {
		t.sessionsMutex.Unlock()
		return nil
	}
	t.closed = true
	sessionKeys := make([]string, 0, len(t.sessions))
	for sessionKey := range t.sessions {
		sessionKeys = append(sessionKeys, sessionKey)
	}
	t.sessionsMutex.Unlock()

	// These requests end because this process is going away, not because the client left, so the
	// minimal lifetime that stops clients from cycling sessions does not apply.
	noMinimalLifetime := durationpb.New(0)
	for _, sessionKey := range sessionKeys {
		t.returns.Add(1)
		go func() {
			defer t.returns.Done()

			t.returnSession(ctx, sessionKey, noMinimalLifetime)
		}()
	}

	returned := make(chan struct{})
	go func() {
		t.returns.Wait()
		close(returned)
	}()

	select {
	case <-returned:
		t.logger.Info("returned sessions on close", zap.Int("session_count", len(sessionKeys)))
		return nil
	case <-ctx.Done():
		return fmt.Errorf("returning %d sessions on close: %w", len(sessionKeys), ctx.Err())
	}
}

// trackReturn registers a return about to run in the background so Close waits for it. It
// reports false once Close has started.
func (t *tgmSessionPool) trackReturn() bool {
	t.sessionsMutex.Lock()
	defer t.sessionsMutex.Unlock()

	if t.closed {
		return false
	}
	t.returns.Add(1)

	return true
}

// returnSession stops tracking a session and returns it and its workers to the session server.
// Only the first caller for a given session returns it; Release and Close can race on the same one.
func (t *tgmSessionPool) returnSession(ctx context.Context, sessionKey string, minimalLifetime *durationpb.Duration) {
	t.sessionsMutex.Lock()
	sessionInfo := t.sessions[sessionKey]
	if sessionInfo == nil {
		t.sessionsMutex.Unlock()
		return
	}

	sessionInfo.mutex.Lock()
	workersToRelease := make([]string, 0, len(sessionInfo.workers))
	for workerKey := range sessionInfo.workers {
		workersToRelease = append(workersToRelease, workerKey)
	}
	done := sessionInfo.closer
	delete(t.sessions, sessionKey)
	sessionInfo.mutex.Unlock()
	t.sessionsMutex.Unlock()

	close(done)

	for _, workerKey := range workersToRelease {
		t.releaseWorkerInternal(ctx, workerKey)
	}

	t.returnRemote(ctx, sessionKey, minimalLifetime)
}

func (t *tgmSessionPool) returnRemote(ctx context.Context, sessionKey string, minimalLifetime *durationpb.Duration) {
	resp, err := t.remoteWorkerPoolClient.ReturnWorker(ctx,
		&pbworker.ReturnWorkerRequest{
			WorkerKey:                 sessionKey,
			MinimalWorkerLifeDuration: minimalLifetime,
		},
		grpc.WaitForReady(false),
	)

	t.logger.Debug("returned request worker", zap.String("key", sessionKey), zap.Stringer("status", resp.GetStatus()), zap.Error(err))
}

func (t *tgmSessionPool) GetWorker(ctx context.Context, serviceName string, sessionKey string, maxWorkersPerSession int) (string, error) {
	// Look up session info
	t.sessionsMutex.Lock()
	sessionInfo := t.sessions[sessionKey]
	if sessionInfo == nil {
		t.sessionsMutex.Unlock()
		return "", fmt.Errorf("%w: session key %s not found", dsession.ErrSessionNotFound, sessionKey)
	}
	// Copy the values we need while holding the lock
	organizationID := sessionInfo.organizationID
	apiKeyID := sessionInfo.apiKeyID
	traceID := sessionInfo.traceID
	t.sessionsMutex.Unlock()

	resp, err := t.remoteWorkerPoolClient.BorrowWorker(ctx,
		&pbworker.BorrowWorkerRequest{
			Service:             serviceName,
			OrganizationId:      organizationID,
			ApiKeyId:            apiKeyID,
			TraceId:             traceID,
			MaxWorkerForTraceId: int64(maxWorkersPerSession),
		},
		grpc.WaitForReady(false),
	)

	if err != nil {
		// Map gRPC errors to dsession errors
		if grpcErr, ok := status.FromError(err); ok {
			switch grpcErr.Code() {
			case codes.NotFound:
				return "", fmt.Errorf("%w: session not found", dsession.ErrSessionNotFound)
			case codes.ResourceExhausted:
				return "", fmt.Errorf("%w: maximum workers per session exceeded", dsession.ErrWorkersLimitExceeded)
			}
		}
		return "", fmt.Errorf("failed to borrow worker: %w", err)
	}

	workerKey := resp.WorkerKey
	workerStatus := resp.Status

	details := ""
	if maxWorkers := resp.WorkerState.GetMaxWorkers(); maxWorkers != 0 {
		details = fmt.Sprintf(" (active workers: %d/%d)", maxWorkers, maxWorkers)
	}

	if workerStatus == pbworker.BorrowWorkerResponse_resource_exhausted {
		t.logger.Debug("worker limit exceeded", zap.String("worker_key", workerKey), zap.String("status", workerStatus.String()))
		return "", fmt.Errorf("%w%s", dsession.ErrWorkersLimitExceeded, details)
	}

	// Track this worker under the session
	t.sessionsMutex.Lock()
	sessionInfo = t.sessions[sessionKey]
	if sessionInfo == nil {
		t.sessionsMutex.Unlock()
		// Session was released, immediately release the newly acquired worker
		t.releaseWorkerAsync(workerKey)
		return "", fmt.Errorf("%w: session key %s was released", dsession.ErrSessionNotFound, sessionKey)
	}
	sessionInfo.workers[workerKey] = struct{}{}
	t.sessionsMutex.Unlock()

	t.logger.Debug("borrowed worker", zap.String("organization_id", organizationID), zap.String("api_key_id", apiKeyID), zap.String("service_name", serviceName), zap.String("trace_id", traceID), zap.String("worker_key", workerKey), zap.String("session_key", sessionKey), zap.Int("max_workers", maxWorkersPerSession))

	return workerKey, nil
}

func (t *tgmSessionPool) ReleaseWorker(workerKey string) {
	// Remove worker from session tracking
	t.sessionsMutex.Lock()
	for _, sessionInfo := range t.sessions {
		delete(sessionInfo.workers, workerKey)
	}
	t.sessionsMutex.Unlock()

	t.releaseWorkerAsync(workerKey)
}

// releaseWorkerAsync returns a worker in the background. Once Close has started nothing waits for
// a background return, so the worker is returned before this call completes instead.
func (t *tgmSessionPool) releaseWorkerAsync(workerKey string) {
	if !t.trackReturn() {
		t.releaseWorkerInternal(context.Background(), workerKey)
		return
	}

	go func() {
		defer t.returns.Done()

		t.releaseWorkerInternal(context.Background(), workerKey)
	}()
}

func (t *tgmSessionPool) releaseWorkerInternal(ctx context.Context, workerKey string) {
	resp, err := t.remoteWorkerPoolClient.ReturnWorker(ctx,
		&pbworker.ReturnWorkerRequest{
			WorkerKey: workerKey,
		},
		grpc.WaitForReady(false),
	)

	t.logger.Debug("returned worker", zap.String("key", workerKey), zap.Stringer("status", resp.GetStatus()), zap.Error(err))
}

// createApiKeyInterceptor creates a gRPC unary interceptor that adds the X-Api-Key header
func createApiKeyInterceptor(apiKey string) grpc.UnaryClientInterceptor {
	return func(ctx context.Context, method string, req, reply interface{}, cc *grpc.ClientConn, invoker grpc.UnaryInvoker, opts ...grpc.CallOption) error {
		// Add the X-Api-Key header to the outgoing metadata
		ctx = metadata.AppendToOutgoingContext(ctx, "X-Api-Key", apiKey)
		return invoker(ctx, method, req, reply, cc, opts...)
	}
}

// startKeepAlive starts the keep-alive goroutine for a borrowed session and its workers
func (t *tgmSessionPool) startKeepAlive(ctx context.Context, done <-chan struct{}, sessionKey string, onError func(error)) {
	go func() {
		// Use a ticker for consistent intervals regardless of operation duration
		// The ticker will fire at regular intervals from when it starts, not from when each tick is consumed
		ticker := time.NewTicker(t.config.RequestKeepAliveDelay)
		defer ticker.Stop()

		// Track if we're in error recovery mode with 1-second intervals
		errorMode := false

		for {
			select {
			case <-ctx.Done():
				return
			case <-done:
				return
			case <-ticker.C:
				// The ticker ensures consistent intervals - it ticks at regular intervals
				// regardless of how long the keep-alive operations take

				// Get session info and workers to keep alive
				t.sessionsMutex.Lock()
				sessionInfo := t.sessions[sessionKey]
				if sessionInfo == nil {
					t.sessionsMutex.Unlock()
					return // Session was released
				}
				sessionInfo.mutex.Lock()
				apiKeyID := sessionInfo.apiKeyID
				workerKeys := make([]string, 0, len(sessionInfo.workers))
				for workerKey := range sessionInfo.workers {
					workerKeys = append(workerKeys, workerKey)
				}
				t.sessionsMutex.Unlock()

				hadError := false

				// Keep session alive
				_, err := t.remoteWorkerPoolClient.KeepAlive(
					ctx,
					&pbworker.KeepAliveRequest{
						WorkerKey: sessionKey,
						ApiKeyId:  apiKeyID,
					},
					grpc.WaitForReady(false),
				)

				if err != nil {
					hadError = true
					t.logger.Error("failed to call keep session alive", zap.String("session_key", sessionKey), zap.Error(err))
					if onError != nil {
						// Map gRPC errors to dsession errors
						if grpcErr, ok := status.FromError(err); ok {
							switch grpcErr.Code() {
							case codes.PermissionDenied:
								onError(fmt.Errorf("%w: %s", dsession.ErrPermissionDenied, grpcErr.Message()))
								sessionInfo.mutex.Unlock()
								return
							case codes.ResourceExhausted:
								onError(fmt.Errorf("%w: %s", dsession.ErrQuotaExceeded, grpcErr.Message()))
								sessionInfo.mutex.Unlock()
								return
							}
						}
					}
				}

				// Keep workers alive
				for _, workerKey := range workerKeys {
					_, err := t.remoteWorkerPoolClient.KeepAlive(
						ctx,
						&pbworker.KeepAliveRequest{
							WorkerKey: workerKey,
							ApiKeyId:  apiKeyID,
						},
						grpc.WaitForReady(false),
					)
					if err != nil {
						hadError = true
						t.logger.Error("failed to call keep worker alive", zap.String("worker_key", workerKey), zap.Error(err))
					}
				}
				sessionInfo.mutex.Unlock()

				// On error, switch to 1-second retry interval
				// On success after error, switch back to normal interval
				if hadError && !errorMode {
					ticker.Reset(time.Second)
					errorMode = true
					t.logger.Info("switched to error recovery mode with 1 second interval", zap.String("session_key", sessionKey))
				} else if !hadError && errorMode {
					ticker.Reset(t.config.RequestKeepAliveDelay)
					errorMode = false
					t.logger.Info("recovered from error, switched back to normal interval", zap.String("session_key", sessionKey))
				}
			}
		}
	}()
}
