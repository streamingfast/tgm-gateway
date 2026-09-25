package session

import (
	"context"
	"crypto/tls"
	"errors"
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

	// mutex is held by the keep-alive for the whole of its calls, so a return can wait for a
	// keep-alive in flight. The workers map is guarded by the pool's sessionsMutex instead.
	mutex sync.Mutex
}

// workerKeys must be called with the pool's sessionsMutex held.
func (s *sessionInfo) workerKeys() []string {
	workerKeys := make([]string, 0, len(s.workers))
	for workerKey := range s.workers {
		workerKeys = append(workerKeys, workerKey)
	}
	return workerKeys
}

// returnTimeout bounds each return sent in the background.
const returnTimeout = 10 * time.Second

type tgmSessionPool struct {
	config                 *Config
	logger                 *zap.Logger
	remoteWorkerPoolClient pbworker.WorkerPoolClient
	conn                   *grpc.ClientConn
	sessions               map[string]*sessionInfo // Map sessionKey -> session info
	sessionsMutex          sync.Mutex

	// inFlight counts the borrows and returns under way, which Close waits for before returning
	// what is left. It is only added to under sessionsMutex while closed is false.
	inFlight sync.WaitGroup
	closed   bool // guarded by sessionsMutex

	closeOnce sync.Once
	closeErr  error
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
	if !t.track() {
		return "", fmt.Errorf("%w: session pool is closed", dsession.ErrUnavailable)
	}
	defer t.inFlight.Done()

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
	if !t.track() {
		// Close returns every session still tracked.
		return
	}

	go func() {
		defer t.inFlight.Done()

		t.sessionsMutex.Lock()
		sessionInfo := t.sessions[sessionKey]
		if sessionInfo == nil {
			t.sessionsMutex.Unlock()
			return
		}
		delete(t.sessions, sessionKey)
		workerKeys := sessionInfo.workerKeys()
		t.sessionsMutex.Unlock()

		close(sessionInfo.closer)

		// A keep-alive landing after the return would push a session still inside its minimal
		// lifetime back up to the full keep-alive TTL on the session server.
		sessionInfo.mutex.Lock()
		sessionInfo.mutex.Unlock()

		ctx, cancel := context.WithTimeout(context.Background(), returnTimeout)
		defer cancel()

		if err := t.returnSession(ctx, sessionKey, workerKeys, &durationpb.Duration{Seconds: int64(t.config.MinimalWorkerLifeDuration.Seconds())}); err != nil {
			t.logger.Warn("failed to return session", zap.String("session_key", sessionKey), zap.Error(err))
		}
	}()
}

// Close returns every session the pool still tracks, with its workers, to the session server.
// Call it right before the process exits, once requests have ended: returns are otherwise sent
// in the background, and one the process exits before sending leaves its session counted against
// the organization until it expires on the session server. Close first waits for the borrows and
// returns under way, and the pool refuses new sessions and workers from then on. Only the first
// call does the work; later calls return its result.
func (t *tgmSessionPool) Close(ctx context.Context) error {
	t.closeOnce.Do(func() {
		t.closeErr = t.close(ctx)
	})

	return t.closeErr
}

func (t *tgmSessionPool) close(ctx context.Context) error {
	t.sessionsMutex.Lock()
	t.closed = true
	t.sessionsMutex.Unlock()

	if err := waitOrDone(ctx, &t.inFlight); err != nil {
		return fmt.Errorf("waiting for borrows and returns under way: %w", err)
	}

	t.sessionsMutex.Lock()
	sessions := t.sessions
	t.sessions = make(map[string]*sessionInfo)
	workerKeys := make(map[string][]string, len(sessions))
	for sessionKey, sessionInfo := range sessions {
		workerKeys[sessionKey] = sessionInfo.workerKeys()
	}
	t.sessionsMutex.Unlock()

	// These requests end because this process is going away, not because the client left, so the
	// minimal lifetime that stops clients from cycling sessions does not apply. The session server
	// deletes the key outright, so a keep-alive still in flight cannot extend it afterwards.
	noMinimalLifetime := durationpb.New(0)

	var wg sync.WaitGroup
	errs := make([]error, 0, len(sessions))
	var errsLock sync.Mutex
	for sessionKey, sessionInfo := range sessions {
		close(sessionInfo.closer)

		wg.Add(1)
		go func() {
			defer wg.Done()

			if err := t.returnSession(ctx, sessionKey, workerKeys[sessionKey], noMinimalLifetime); err != nil {
				errsLock.Lock()
				errs = append(errs, err)
				errsLock.Unlock()
			}
		}()
	}
	wg.Wait()

	if err := errors.Join(errs...); err != nil {
		return fmt.Errorf("returning %d sessions on close: %w", len(sessions), err)
	}

	t.logger.Info("returned sessions on close", zap.Int("session_count", len(sessions)))
	return nil
}

// track registers a borrow or return under way so Close waits for it. It reports false once Close
// has started: nothing may be borrowed anymore, and Close returns what is still tracked itself.
func (t *tgmSessionPool) track() bool {
	t.sessionsMutex.Lock()
	defer t.sessionsMutex.Unlock()

	if t.closed {
		return false
	}
	t.inFlight.Add(1)

	return true
}

// waitOrDone waits for wg unless ctx ends first. The waiting goroutine then lingers until the
// operations under way end, each bounded by returnTimeout or by its request.
func waitOrDone(ctx context.Context, wg *sync.WaitGroup) error {
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (t *tgmSessionPool) returnSession(ctx context.Context, sessionKey string, workerKeys []string, minimalLifetime *durationpb.Duration) error {
	errs := make([]error, 0, len(workerKeys)+1)
	for _, workerKey := range workerKeys {
		if err := t.returnWorker(ctx, workerKey); err != nil {
			errs = append(errs, err)
		}
	}

	resp, err := t.remoteWorkerPoolClient.ReturnWorker(ctx,
		&pbworker.ReturnWorkerRequest{
			WorkerKey:                 sessionKey,
			MinimalWorkerLifeDuration: minimalLifetime,
		},
		grpc.WaitForReady(false),
	)
	if err != nil {
		errs = append(errs, fmt.Errorf("returning session %s: %w", sessionKey, err))
	} else {
		t.logger.Debug("returned request worker", zap.String("key", sessionKey), zap.Stringer("status", resp.GetStatus()))
	}

	return errors.Join(errs...)
}

func (t *tgmSessionPool) GetWorker(ctx context.Context, serviceName string, sessionKey string, maxWorkersPerSession int) (string, error) {
	if !t.track() {
		return "", fmt.Errorf("%w: session pool is closed", dsession.ErrSessionNotFound)
	}
	defer t.inFlight.Done()

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
		returnCtx, cancel := context.WithTimeout(context.Background(), returnTimeout)
		defer cancel()
		if err := t.returnWorker(returnCtx, workerKey); err != nil {
			t.logger.Warn("failed to return worker of a released session", zap.String("worker_key", workerKey), zap.Error(err))
		}
		return "", fmt.Errorf("%w: session key %s was released", dsession.ErrSessionNotFound, sessionKey)
	}
	sessionInfo.workers[workerKey] = struct{}{}
	t.sessionsMutex.Unlock()

	t.logger.Debug("borrowed worker", zap.String("organization_id", organizationID), zap.String("api_key_id", apiKeyID), zap.String("service_name", serviceName), zap.String("trace_id", traceID), zap.String("worker_key", workerKey), zap.String("session_key", sessionKey), zap.Int("max_workers", maxWorkersPerSession))

	return workerKey, nil
}

func (t *tgmSessionPool) ReleaseWorker(workerKey string) {
	if !t.track() {
		// Close returns every worker still tracked.
		return
	}

	t.sessionsMutex.Lock()
	tracked := false
	for _, sessionInfo := range t.sessions {
		if _, found := sessionInfo.workers[workerKey]; found {
			delete(sessionInfo.workers, workerKey)
			tracked = true
		}
	}
	t.sessionsMutex.Unlock()

	if !tracked {
		// Every worker handed out is tracked under its session until returned, so this one was
		// already returned with its session.
		t.inFlight.Done()
		return
	}

	go func() {
		defer t.inFlight.Done()

		ctx, cancel := context.WithTimeout(context.Background(), returnTimeout)
		defer cancel()

		if err := t.returnWorker(ctx, workerKey); err != nil {
			t.logger.Warn("failed to return worker", zap.String("worker_key", workerKey), zap.Error(err))
		}
	}()
}

func (t *tgmSessionPool) returnWorker(ctx context.Context, workerKey string) error {
	resp, err := t.remoteWorkerPoolClient.ReturnWorker(ctx,
		&pbworker.ReturnWorkerRequest{
			WorkerKey: workerKey,
		},
		grpc.WaitForReady(false),
	)
	if err != nil {
		return fmt.Errorf("returning worker %s: %w", workerKey, err)
	}

	t.logger.Debug("returned worker", zap.String("key", workerKey), zap.Stringer("status", resp.GetStatus()))
	return nil
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
