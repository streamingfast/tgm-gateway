package auth

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
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
)

// Test helper functions
func generateTestKeyPair() (*ecdsa.PrivateKey, *ecdsa.PublicKey, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	return privateKey, &privateKey.PublicKey, nil
}

func createTestJWKSet(publicKey *ecdsa.PublicKey) (jwk.Set, error) {
	key, err := jwk.Import(publicKey)
	if err != nil {
		return nil, err
	}
	key.Set(jwk.AlgorithmKey, jwa.ES256())
	key.Set(jwk.KeyIDKey, "test-key-id")

	set := jwk.NewSet()
	set.AddKey(key)
	return set, nil
}

func createTestJWT(privateKey *ecdsa.PrivateKey, claims map[string]any) (string, error) {
	token := jwt.New()

	// Set standard claims
	token.Set(jwt.IssuedAtKey, time.Now())
	token.Set(jwt.ExpirationKey, time.Now().Add(time.Hour))

	// Set custom claims
	for key, value := range claims {
		token.Set(key, value)
	}

	key, err := jwk.Import(privateKey)
	if err != nil {
		return "", err
	}

	signed, err := jwt.Sign(token, jwt.WithKey(jwa.ES256(), key))
	if err != nil {
		return "", err
	}

	return string(signed), nil
}

func TestRegister(t *testing.T) {
	// Test that Register function properly registers the authenticator
	Register()

	// This test mainly ensures Register doesn't panic
	// The actual registration is tested through integration with dauth
}

func TestNew(t *testing.T) {
	logger := zap.NewNop()

	tests := []struct {
		name      string
		config    *Config
		wantError bool
		errorMsg  string
	}{
		{
			name: "valid config with PubKeyURL",
			config: &Config{
				PubKeyURL:         "https://example.com/jwks",
				ReissueJWTAgeSecs: 600,
				ReissueURL:        "https://auth.example.com/v1/auth/reissue",
				IssueURL:          "https://auth.example.com/v1/auth/issue",
			},
			wantError: false,
		},
		{
			name: "valid config with PubKeyBase64",
			config: &Config{
				PubKeyBase64:      base64.StdEncoding.EncodeToString([]byte(`{"keys":[]}`)),
				ReissueJWTAgeSecs: 600,
				ReissueURL:        "https://auth.example.com/v1/auth/reissue",
				IssueURL:          "https://auth.example.com/v1/auth/issue",
			},
			wantError: false,
		},
		{
			name: "missing both PubKeyURL and PubKeyBase64",
			config: &Config{
				ReissueJWTAgeSecs: 600,
				ReissueURL:        "https://auth.example.com/v1/auth/reissue",
				IssueURL:          "https://auth.example.com/v1/auth/issue",
			},
			wantError: true,
			errorMsg:  "no JWK URL or public key URL provided",
		},
		{
			name: "invalid PubKeyBase64",
			config: &Config{
				PubKeyBase64:      "invalid-base64!@#",
				ReissueJWTAgeSecs: 600,
				ReissueURL:        "https://auth.example.com/v1/auth/reissue",
				IssueURL:          "https://auth.example.com/v1/auth/issue",
			},
			wantError: true,
			errorMsg:  "failed to fetch JWK set",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// For PubKeyURL test, create a test server
			if tt.config.PubKeyURL != "" {
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.Header().Set("Content-Type", "application/json")
					w.Write([]byte(`{"keys":[]}`))
				}))
				defer server.Close()
				tt.config.PubKeyURL = server.URL
			}

			auth, err := new(tt.config, logger)

			if tt.wantError {
				assert.Error(t, err)
				if tt.errorMsg != "" {
					assert.Contains(t, err.Error(), tt.errorMsg)
				}
				assert.Nil(t, auth)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, auth)
			}
		})
	}
}

func TestAuthenticator_Authenticate(t *testing.T) {
	logger := zap.NewNop()
	privateKey, publicKey, err := generateTestKeyPair()
	require.NoError(t, err)

	jwkSet, err := createTestJWKSet(publicKey)
	require.NoError(t, err)

	// Create test JWT with various claims
	validJWT, err := createTestJWT(privateKey, map[string]any{
		"uid":                  "test-user-123",
		"aki":                  "api-key-456",
		"substreams_plan_tier": "pro",
		"cfg": map[string]any{
			"max_requests": "1000",
			"enable_beta":  "true",
		},
	})
	require.NoError(t, err)

	// Create old JWT that needs reissue
	oldToken := jwt.New()
	oldToken.Set(jwt.IssuedAtKey, time.Now().Add(-time.Hour))
	oldToken.Set(jwt.ExpirationKey, time.Now().Add(time.Hour))
	oldToken.Set("uid", "old-user")

	key, _ := jwk.Import(privateKey)
	signedOld, _ := jwt.Sign(oldToken, jwt.WithKey(jwa.ES256(), key))
	oldJWT := string(signedOld)

	tests := []struct {
		name            string
		headers         map[string][]string
		setupMockServer func() *httptest.Server
		wantError       bool
		errorMsg        string
		checkContext    func(t *testing.T, ctx context.Context)
	}{
		{
			name: "valid JWT in Authorization header with Bearer prefix",
			headers: map[string][]string{
				"Authorization": {fmt.Sprintf("Bearer %s", validJWT)},
			},
			wantError: false,
			checkContext: func(t *testing.T, ctx context.Context) {
				headers := dauth.FromContext(ctx)
				assert.Equal(t, "test-user-123", headers[dauth.HeaderOrganizationID])
				assert.Equal(t, "api-key-456", headers[dauth.HeaderApiKeyID])
				assert.Equal(t, "pro", headers[dauth.HeaderSubstreamsPlanTier])
				assert.Equal(t, "1000", headers["x-max-requests"])
				assert.Equal(t, "true", headers["x-enable-beta"])
			},
		},
		{
			name: "valid JWT in Authorization header without Bearer prefix",
			headers: map[string][]string{
				"authorization": {validJWT},
			},
			wantError: false,
			checkContext: func(t *testing.T, ctx context.Context) {
				headers := dauth.FromContext(ctx)
				assert.Equal(t, "test-user-123", headers[dauth.HeaderOrganizationID])
			},
		},
		{
			name: "invalid JWT in Authorization header",
			headers: map[string][]string{
				"Authorization": {"Bearer invalid-jwt-token"},
			},
			wantError: true,
			errorMsg:  "invalid JWT token",
		},
		{
			name: "API key authentication",
			headers: map[string][]string{
				"X-API-Key": {"test-api-key"},
			},
			setupMockServer: func() *httptest.Server {
				return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					// Verify request
					assert.Equal(t, "POST", r.Method)
					assert.Equal(t, "/v1/auth/issue", r.URL.Path)

					var body map[string]string
					json.NewDecoder(r.Body).Decode(&body)
					assert.Equal(t, "test-api-key", body["api_key"])

					// Return JWT
					response := map[string]string{
						"token": validJWT,
					}
					json.NewEncoder(w).Encode(response)
				}))
			},
			wantError: false,
			checkContext: func(t *testing.T, ctx context.Context) {
				headers := dauth.FromContext(ctx)
				assert.Equal(t, "test-user-123", headers[dauth.HeaderOrganizationID])
			},
		},
		{
			name: "API key authentication failure",
			headers: map[string][]string{
				"X-API-Key": {"invalid-api-key"},
			},
			setupMockServer: func() *httptest.Server {
				return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.WriteHeader(http.StatusUnauthorized)
					w.Write([]byte("Invalid API key"))
				}))
			},
			wantError: true,
			errorMsg:  "failed to authenticate with API key",
		},
		{
			name:      "missing authentication headers",
			headers:   map[string][]string{},
			wantError: true,
			errorMsg:  "required authorization token not found",
		},
		{
			name: "JWT reissue on old token",
			headers: map[string][]string{
				"Authorization": {fmt.Sprintf("Bearer %s", oldJWT)},
			},
			setupMockServer: func() *httptest.Server {
				return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.URL.Path == "/v1/auth/reissue" {
						// Return new JWT
						response := map[string]string{
							"token": validJWT,
						}
						json.NewEncoder(w).Encode(response)
					}
				}))
			},
			wantError: false,
			checkContext: func(t *testing.T, ctx context.Context) {
				headers := dauth.FromContext(ctx)
				// Should have claims from the new reissued token
				assert.Equal(t, "test-user-123", headers[dauth.HeaderOrganizationID])
			},
		},
		{
			name: "case insensitive header lookup",
			headers: map[string][]string{
				"AUTHORIZATION": {fmt.Sprintf("Bearer %s", validJWT)},
			},
			wantError: false,
			checkContext: func(t *testing.T, ctx context.Context) {
				headers := dauth.FromContext(ctx)
				assert.Equal(t, "test-user-123", headers[dauth.HeaderOrganizationID])
			},
		},
		{
			name: "invalid Bearer format",
			headers: map[string][]string{
				"Authorization": {"NotBearer " + validJWT},
			},
			wantError: true,
			errorMsg:  "authorization header format",
		},
		{
			name: "multiple authorization parts",
			headers: map[string][]string{
				"Authorization": {"Bearer token extra parts"},
			},
			wantError: true,
			errorMsg:  "authorization header format",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := &Config{
				ReissueJWTAgeSecs: 300, // 5 minutes
				ReissueURL:        "https://auth.example.com/v1/auth/reissue",
				IssueURL:          "https://auth.example.com/v1/auth/issue",
			}

			// Setup mock server if needed
			if tt.setupMockServer != nil {
				server := tt.setupMockServer()
				defer server.Close()
				config.IssueURL = server.URL + "/v1/auth/issue"
				config.ReissueURL = server.URL + "/v1/auth/reissue"
			}

			auth := &authenticator{
				config:     config,
				logger:     logger,
				jwkSet:     jwkSet,
				httpClient: &http.Client{Timeout: 15 * time.Second},
			}

			ctx := context.Background()
			newCtx, err := auth.Authenticate(ctx, "/test/path", tt.headers, "192.168.1.1")

			if tt.wantError {
				assert.Error(t, err)
				if tt.errorMsg != "" {
					assert.Contains(t, err.Error(), tt.errorMsg)
				}
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, newCtx)

				if tt.checkContext != nil {
					tt.checkContext(t, newCtx)
				}

				// Check IP address is always added
				headers := dauth.FromContext(newCtx)
				assert.Equal(t, "192.168.1.1", headers[dauth.HeaderIP])
			}
		})
	}
}

func TestAuthenticator_ParseJWT(t *testing.T) {
	logger := zap.NewNop()
	privateKey, publicKey, err := generateTestKeyPair()
	require.NoError(t, err)

	jwkSet, err := createTestJWKSet(publicKey)
	require.NoError(t, err)

	validJWT, err := createTestJWT(privateKey, map[string]any{
		"uid": "test-user",
	})
	require.NoError(t, err)

	// Create JWT with different key
	differentKey, _, _ := generateTestKeyPair()
	invalidJWT, _ := createTestJWT(differentKey, map[string]any{
		"uid": "test-user",
	})

	auth := &authenticator{
		config: &Config{},
		logger: logger,
		jwkSet: jwkSet,
	}

	tests := []struct {
		name      string
		token     string
		wantError bool
	}{
		{
			name:      "valid JWT",
			token:     validJWT,
			wantError: false,
		},
		{
			name:      "invalid JWT signature",
			token:     invalidJWT,
			wantError: true,
		},
		{
			name:      "malformed JWT",
			token:     "not.a.jwt",
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token, err := auth.ParseJWT(tt.token)

			if tt.wantError {
				assert.Error(t, err)
				assert.Nil(t, token)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, token)
			}
		})
	}
}

func TestAuthenticator_needsReissue(t *testing.T) {
	auth := &authenticator{
		config: &Config{
			ReissueJWTAgeSecs: 600, // 10 minutes
		},
	}

	tests := []struct {
		name          string
		issuedAt      time.Time
		expectReissue bool
	}{
		{
			name:          "token within reissue age",
			issuedAt:      time.Now().Add(-5 * time.Minute),
			expectReissue: false,
		},
		{
			name:          "token exceeds reissue age",
			issuedAt:      time.Now().Add(-15 * time.Minute),
			expectReissue: true,
		},
		{
			name:          "token at exact reissue age",
			issuedAt:      time.Now().Add(-10 * time.Minute),
			expectReissue: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token := jwt.New()
			token.Set(jwt.IssuedAtKey, tt.issuedAt)

			result := auth.needsReissue(token)
			assert.Equal(t, tt.expectReissue, result)
		})
	}
}

func TestAuthenticator_addClaimsToContext(t *testing.T) {
	auth := &authenticator{
		config: &Config{},
		logger: zap.NewNop(),
	}

	tests := []struct {
		name      string
		claims    map[string]any
		ipAddress string
		expected  map[string]string
	}{
		{
			name: "standard claims",
			claims: map[string]any{
				"uid":                  "user123",
				"aki":                  "key456",
				"substreams_plan_tier": "pro",
			},
			ipAddress: "10.0.0.1",
			expected: map[string]string{
				dauth.HeaderOrganizationID:     "user123",
				dauth.HeaderApiKeyID:           "key456",
				dauth.HeaderSubstreamsPlanTier: "pro",
				dauth.HeaderIP:                 "10.0.0.1",
			},
		},
		{
			name: "legacy subject with uid prefix",
			claims: map[string]any{
				jwt.SubjectKey: "uid:legacy-user",
			},
			ipAddress: "10.0.0.2",
			expected: map[string]string{
				dauth.HeaderOrganizationID: "legacy-user",
				dauth.HeaderIP:             "10.0.0.2",
			},
		},
		{
			name: "feature configs",
			claims: map[string]any{
				"cfg": map[string]any{
					"max_requests":     "1000",
					"enable_feature_x": "true",
					"rate_limit":       "500",
				},
			},
			ipAddress: "10.0.0.3",
			expected: map[string]string{
				"x-max-requests":     "1000",
				"x-enable-feature-x": "true",
				"x-rate-limit":       "500",
				dauth.HeaderIP:       "10.0.0.3",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token := jwt.New()
			for key, value := range tt.claims {
				token.Set(key, value)
			}

			ctx := context.Background()
			newCtx := auth.addClaimsToContext(ctx, token, tt.ipAddress, "", nil)

			headers := dauth.FromContext(newCtx)

			for key, expectedValue := range tt.expected {
				assert.Equal(t, expectedValue, headers[key], "header %s mismatch", key)
			}
		})
	}
}

func TestJwtFeatureConfigKeyToHeader(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{
			input:    "max_requests",
			expected: "x-max-requests",
		},
		{
			input:    "ENABLE_FEATURE",
			expected: "x-enable-feature",
		},
		{
			input:    "rate_limit_per_second",
			expected: "x-rate-limit-per-second",
		},
		{
			input:    "simple",
			expected: "x-simple",
		},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := jwtFeatureConfigKeyToHeader(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestAuthenticator_Ready(t *testing.T) {
	auth := &authenticator{
		config: &Config{},
		logger: zap.NewNop(),
	}

	ctx := context.Background()
	assert.True(t, auth.Ready(ctx))
}

func TestAuthenticator_issueJWTFromAPIKey(t *testing.T) {
	logger := zap.NewNop()
	privateKey, publicKey, err := generateTestKeyPair()
	require.NoError(t, err)

	jwkSet, err := createTestJWKSet(publicKey)
	require.NoError(t, err)

	validJWT, err := createTestJWT(privateKey, map[string]any{
		"uid": "api-user",
	})
	require.NoError(t, err)

	tests := []struct {
		name       string
		apiKey     string
		mockServer func() *httptest.Server
		wantError  bool
		errorMsg   string
	}{
		{
			name:   "successful API key exchange",
			apiKey: "valid-api-key",
			mockServer: func() *httptest.Server {
				return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					assert.Equal(t, "POST", r.Method)
					assert.Equal(t, "application/json", r.Header.Get("Content-Type"))

					var body map[string]string
					json.NewDecoder(r.Body).Decode(&body)
					assert.Equal(t, "valid-api-key", body["api_key"])

					response := map[string]string{
						"token": validJWT,
					}
					json.NewEncoder(w).Encode(response)
				}))
			},
			wantError: false,
		},
		{
			name:   "API key rejection",
			apiKey: "invalid-api-key",
			mockServer: func() *httptest.Server {
				return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.WriteHeader(http.StatusUnauthorized)
					w.Write([]byte("Invalid API key"))
				}))
			},
			wantError: true,
			errorMsg:  "issue endpoint returned status 401",
		},
		{
			name:   "server error",
			apiKey: "any-key",
			mockServer: func() *httptest.Server {
				return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.WriteHeader(http.StatusInternalServerError)
					w.Write([]byte("Server error"))
				}))
			},
			wantError: true,
			errorMsg:  "issue endpoint returned status 500",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := tt.mockServer()
			defer server.Close()

			auth := &authenticator{
				config: &Config{
					IssueURL: server.URL,
				},
				logger:     logger,
				jwkSet:     jwkSet,
				httpClient: &http.Client{Timeout: 15 * time.Second},
			}

			ctx := context.Background()
			token, err := auth.issueJWTFromAPIKey(ctx, tt.apiKey)

			if tt.wantError {
				assert.Error(t, err)
				if tt.errorMsg != "" {
					assert.Contains(t, err.Error(), tt.errorMsg)
				}
				assert.Nil(t, token)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, token)
			}
		})
	}
}

func TestAuthenticator_reissueJWT(t *testing.T) {
	logger := zap.NewNop()
	privateKey, publicKey, err := generateTestKeyPair()
	require.NoError(t, err)

	jwkSet, err := createTestJWKSet(publicKey)
	require.NoError(t, err)

	oldJWT, err := createTestJWT(privateKey, map[string]any{
		"uid": "old-user",
	})
	require.NoError(t, err)

	newJWT, err := createTestJWT(privateKey, map[string]any{
		"uid": "refreshed-user",
	})
	require.NoError(t, err)

	tests := []struct {
		name        string
		tokenString string
		configKey   string
		mockServer  func() *httptest.Server
		wantError   bool
		errorMsg    string
	}{
		{
			name:        "successful reissue with JSON response",
			tokenString: oldJWT,
			configKey:   "test-key",
			mockServer: func() *httptest.Server {
				return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					assert.Equal(t, "POST", r.Method)
					assert.Equal(t, "application/json", r.Header.Get("Content-Type"))
					assert.Equal(t, "test-key", r.Header.Get("X-Api-Key"))

					var body map[string]string
					json.NewDecoder(r.Body).Decode(&body)
					assert.Equal(t, oldJWT, body["jwt"])

					response := map[string]string{
						"token": newJWT,
					}
					json.NewEncoder(w).Encode(response)
				}))
			},
			wantError: false,
		},
		{
			name:        "successful reissue with raw token response",
			tokenString: oldJWT,
			configKey:   "",
			mockServer: func() *httptest.Server {
				return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					// No Authorization header when key is empty
					assert.Empty(t, r.Header.Get("Authorization"))

					w.Header().Set("Content-Type", "text/plain")
					w.Write([]byte(newJWT))
				}))
			},
			wantError: false,
		},
		{
			name:        "reissue rejection",
			tokenString: oldJWT,
			configKey:   "test-key",
			mockServer: func() *httptest.Server {
				return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.WriteHeader(http.StatusUnauthorized)
					w.Write([]byte("Token expired"))
				}))
			},
			wantError: true,
			errorMsg:  "reissue endpoint returned status 401",
		},
		{
			name:        "server error during reissue",
			tokenString: oldJWT,
			configKey:   "test-key",
			mockServer: func() *httptest.Server {
				return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.WriteHeader(http.StatusInternalServerError)
					w.Write([]byte("Internal server error"))
				}))
			},
			wantError: true,
			errorMsg:  "reissue endpoint returned status 500",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := tt.mockServer()
			defer server.Close()

			auth := &authenticator{
				config: &Config{
					ReissueURL:    server.URL,
					IndexerAPIKey: tt.configKey,
				},
				logger:     logger,
				jwkSet:     jwkSet,
				httpClient: &http.Client{Timeout: 15 * time.Second},
			}

			ctx := context.Background()
			token, err := auth.reissueJWT(ctx, tt.tokenString)

			if tt.wantError {
				assert.Error(t, err)
				if tt.errorMsg != "" {
					assert.Contains(t, err.Error(), tt.errorMsg)
				}
				assert.Nil(t, token)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, token)
			}
		})
	}
}

func TestAuthenticator_extractAndParseJWT(t *testing.T) {
	logger := zap.NewNop()
	privateKey, publicKey, err := generateTestKeyPair()
	require.NoError(t, err)

	jwkSet, err := createTestJWKSet(publicKey)
	require.NoError(t, err)

	validJWT, err := createTestJWT(privateKey, map[string]any{
		"uid": "test-user",
	})
	require.NoError(t, err)

	auth := &authenticator{
		config: &Config{},
		logger: logger,
		jwkSet: jwkSet,
	}

	tests := []struct {
		name       string
		authHeader string
		wantError  bool
		errorMsg   string
	}{
		{
			name:       "valid Bearer token",
			authHeader: fmt.Sprintf("Bearer %s", validJWT),
			wantError:  false,
		},
		{
			name:       "valid Bearer token with lowercase",
			authHeader: fmt.Sprintf("bearer %s", validJWT),
			wantError:  false,
		},
		{
			name:       "token without Bearer prefix",
			authHeader: validJWT,
			wantError:  false,
		},
		{
			name:       "invalid Bearer prefix",
			authHeader: fmt.Sprintf("Basic %s", validJWT),
			wantError:  true,
			errorMsg:   "authorization header format",
		},
		{
			name:       "too many parts in header",
			authHeader: "Bearer token extra",
			wantError:  true,
			errorMsg:   "authorization header format",
		},
		{
			name:       "empty header",
			authHeader: "",
			wantError:  true,
			errorMsg:   "authorization header format",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token, err := auth.extractAndParseJWT(tt.authHeader)

			if tt.wantError {
				assert.Error(t, err)
				if tt.errorMsg != "" {
					assert.Contains(t, err.Error(), tt.errorMsg)
				}
				assert.Nil(t, token)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, token)
			}
		})
	}
}
