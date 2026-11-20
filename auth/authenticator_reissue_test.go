package auth

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jwt"
	"github.com/streamingfast/dauth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestAuthenticator_Authenticate_ReissueFailure(t *testing.T) {
	privateKey, publicKey, err := generateTestKeyPair()
	require.NoError(t, err)

	jwkSet, err := createTestJWKSet(publicKey)
	require.NoError(t, err)

	oldToken := jwt.New()
	require.NoError(t, oldToken.Set(jwt.IssuedAtKey, time.Now().Add(-time.Hour)))
	require.NoError(t, oldToken.Set(jwt.ExpirationKey, time.Now().Add(time.Hour)))
	require.NoError(t, oldToken.Set("uid", "old-user"))

	key, err := jwk.Import(privateKey)
	require.NoError(t, err)
	signedOld, err := jwt.Sign(oldToken, jwt.WithKey(jwa.ES256(), key))
	require.NoError(t, err)

	respond := func(statusCode int, body string) func() (string, *http.Client) {
		return func() (string, *http.Client) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(statusCode)
				_, _ = w.Write([]byte(body))
			}))
			t.Cleanup(server.Close)
			return server.URL, &http.Client{Timeout: 5 * time.Second}
		}
	}

	tests := []struct {
		name     string
		setup    func() (reissueURL string, client *http.Client)
		wantCode codes.Code // codes.OK means the request is accepted with the existing token
		wantMsg  string
	}{
		{
			name:     "401 rejects",
			setup:    respond(401, `{"code":"unauthorized","message":"JWT is expired"}`),
			wantCode: codes.Unauthenticated,
			wantMsg:  "JWT is expired",
		},
		{
			name:     "403 revoked key rejects",
			setup:    respond(403, `{"code":"auth_revoked_api_key_error","message":"The provided API key has been revoked and cannot be used anymore.","details":{"api_key":"secret-id"}}`),
			wantCode: codes.PermissionDenied,
			wantMsg:  "The provided API key has been revoked and cannot be used anymore.",
		},
		{
			name:     "403 disabled organization rejects",
			setup:    respond(403, `{"code":"auth_disabled_organization_account_error","message":"The provided API key belongs to an organization account which has been disabled. Please contact support."}`),
			wantCode: codes.PermissionDenied,
			wantMsg:  "organization account which has been disabled",
		},
		{
			name:     "400 rejects",
			setup:    respond(400, `{"code":"invalid_request","message":"unable to validate JWT"}`),
			wantCode: codes.Unauthenticated,
			wantMsg:  "unable to validate JWT",
		},
		{
			name:     "403 with unparseable body rejects with generic reason",
			setup:    respond(403, `<html>nope</html>`),
			wantCode: codes.PermissionDenied,
			wantMsg:  "JWT validation denied",
		},
		{
			name:     "429 fails open",
			setup:    respond(429, `{"code":"too_many_requests_error","message":"slow down"}`),
			wantCode: codes.OK,
		},
		{
			name:     "500 fails open",
			setup:    respond(500, `boom`),
			wantCode: codes.OK,
		},
		{
			name:     "503 fails open",
			setup:    respond(503, `unavailable`),
			wantCode: codes.OK,
		},
		{
			name:     "malformed 200 fails open",
			setup:    respond(200, `{"token":"not-a-jwt"}`),
			wantCode: codes.OK,
		},
		{
			name: "timeout fails open",
			setup: func() (string, *http.Client) {
				release := make(chan struct{})
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					select {
					case <-release:
					case <-r.Context().Done():
					}
				}))
				t.Cleanup(func() {
					close(release)
					server.Close()
				})
				return server.URL, &http.Client{Timeout: 50 * time.Millisecond}
			},
			wantCode: codes.OK,
		},
		{
			name: "connection refused fails open",
			setup: func() (string, *http.Client) {
				listener, err := net.Listen("tcp", "127.0.0.1:0")
				require.NoError(t, err)
				url := "http://" + listener.Addr().String()
				require.NoError(t, listener.Close())
				return url, &http.Client{Timeout: 5 * time.Second}
			},
			wantCode: codes.OK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reissueURL, client := tt.setup()
			auth := &authenticator{
				config:     &Config{ReissueJWTAgeSecs: 300, ReissueURL: reissueURL},
				logger:     zap.NewNop(),
				jwkSet:     jwkSet,
				httpClient: client,
			}

			headers := map[string][]string{"Authorization": {"Bearer " + string(signedOld)}}
			ctx, err := auth.Authenticate(context.Background(), "/test", headers, "10.0.0.1")

			if tt.wantCode == codes.OK {
				require.NoError(t, err)
				// Existing token claims are used
				assert.Equal(t, "old-user", dauth.FromContext(ctx)[dauth.HeaderOrganizationID])
				return
			}

			require.Error(t, err)
			assert.Equal(t, tt.wantCode, status.Code(err))
			assert.Contains(t, status.Convert(err).Message(), tt.wantMsg)
			assert.NotContains(t, err.Error(), "secret-id")
		})
	}
}
