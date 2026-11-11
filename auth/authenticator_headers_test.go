package auth

import (
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
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

func signTestJWT(t *testing.T, privateKey *ecdsa.PrivateKey, iat, exp *time.Time) string {
	t.Helper()

	token := jwt.New()
	require.NoError(t, token.Set("uid", "org-1"))
	if iat != nil {
		require.NoError(t, token.Set(jwt.IssuedAtKey, *iat))
	}
	if exp != nil {
		require.NoError(t, token.Set(jwt.ExpirationKey, *exp))
	}

	key, err := jwk.Import(privateKey)
	require.NoError(t, err)

	signed, err := jwt.Sign(token, jwt.WithKey(jwa.ES256(), key))
	require.NoError(t, err)
	return string(signed)
}

func TestJWTLifetimeBucket(t *testing.T) {
	now := time.Now()
	tests := []struct {
		name     string
		lifetime time.Duration
		expected string
	}{
		{"15m boundary", 15 * time.Minute, dauth.AuthJWTLifetimeBucketLE15m},
		{"just over 15m", 15*time.Minute + time.Second, dauth.AuthJWTLifetimeBucketLE24h},
		{"24h boundary", 24 * time.Hour, dauth.AuthJWTLifetimeBucketLE24h},
		{"just over 24h", 24*time.Hour + time.Second, dauth.AuthJWTLifetimeBucketGT24h},
		{"just under 10y", 3650*24*time.Hour - time.Second, dauth.AuthJWTLifetimeBucketGT24h},
		{"10y boundary", 3650 * 24 * time.Hour, dauth.AuthJWTLifetimeBucketGTE10y},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, jwtLifetimeBucket(now, true, now.Add(tt.lifetime), true))
		})
	}

	assert.Equal(t, dauth.AuthJWTLifetimeBucketUnknown, jwtLifetimeBucket(time.Time{}, false, now, true))
	assert.Equal(t, dauth.AuthJWTLifetimeBucketUnknown, jwtLifetimeBucket(now, true, time.Time{}, false))
}

func TestAuthenticator_Authenticate_AuthHeaders(t *testing.T) {
	privateKey, publicKey, err := generateTestKeyPair()
	require.NoError(t, err)

	jwkSet, err := createTestJWKSet(publicKey)
	require.NoError(t, err)

	now := time.Now().Truncate(time.Second)
	at := func(d time.Duration) *time.Time { t := now.Add(d); return &t }

	// What the issue/reissue endpoints hand back: always a short-lived, fresh token
	internalJWT := signTestJWT(t, privateKey, at(0), at(10*time.Minute))
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{"token": internalJWT})
	}))
	defer server.Close()

	jwtHeader := func(token string) map[string][]string {
		return map[string][]string{"Authorization": {"Bearer " + token}}
	}

	tests := []struct {
		name     string
		headers  map[string][]string
		expected map[string]string
		absent   []string
	}{
		{
			name:    "api key reports method only",
			headers: map[string][]string{"X-Api-Key": {"my-key"}},
			expected: map[string]string{
				dauth.HeaderAuthMethod: dauth.AuthMethodAPIKey,
			},
			absent: []string{dauth.HeaderAuthJWTIssuedAt, dauth.HeaderAuthJWTExpiresAt, dauth.HeaderAuthJWTLifetimeBucket},
		},
		{
			name:    "short lived jwt",
			headers: jwtHeader(signTestJWT(t, privateKey, at(0), at(10*time.Minute))),
			expected: map[string]string{
				dauth.HeaderAuthMethod:            dauth.AuthMethodJWT,
				dauth.HeaderAuthJWTIssuedAt:       strconv.FormatInt(now.Unix(), 10),
				dauth.HeaderAuthJWTExpiresAt:      strconv.FormatInt(now.Add(10*time.Minute).Unix(), 10),
				dauth.HeaderAuthJWTLifetimeBucket: dauth.AuthJWTLifetimeBucketLE15m,
				dauth.HeaderOrganizationID:        "org-1",
			},
		},
		{
			name:    "ten year jwt",
			headers: jwtHeader(signTestJWT(t, privateKey, at(0), at(3650*24*time.Hour))),
			expected: map[string]string{
				dauth.HeaderAuthMethod:            dauth.AuthMethodJWT,
				dauth.HeaderAuthJWTLifetimeBucket: dauth.AuthJWTLifetimeBucketGTE10y,
			},
		},
		{
			name: "reissued jwt reports original token",
			// Issued 2h ago, so older than the reissue age; lifetime of the original is 10y
			headers: jwtHeader(signTestJWT(t, privateKey, at(-2*time.Hour), at(-2*time.Hour+3650*24*time.Hour))),
			expected: map[string]string{
				dauth.HeaderAuthMethod:            dauth.AuthMethodJWT,
				dauth.HeaderAuthJWTIssuedAt:       strconv.FormatInt(now.Add(-2*time.Hour).Unix(), 10),
				dauth.HeaderAuthJWTExpiresAt:      strconv.FormatInt(now.Add(-2*time.Hour+3650*24*time.Hour).Unix(), 10),
				dauth.HeaderAuthJWTLifetimeBucket: dauth.AuthJWTLifetimeBucketGTE10y,
			},
		},
		{
			name:    "missing iat and exp",
			headers: jwtHeader(signTestJWT(t, privateKey, nil, nil)),
			expected: map[string]string{
				dauth.HeaderAuthMethod:            dauth.AuthMethodJWT,
				dauth.HeaderAuthJWTLifetimeBucket: dauth.AuthJWTLifetimeBucketUnknown,
			},
			absent: []string{dauth.HeaderAuthJWTIssuedAt, dauth.HeaderAuthJWTExpiresAt},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := &authenticator{
				config: &Config{
					IssueURL:          server.URL + "/v1/auth/issue",
					ReissueURL:        server.URL + "/v1/auth/reissue",
					ReissueJWTAgeSecs: 3600,
				},
				logger:     zap.NewNop(),
				jwkSet:     jwkSet,
				httpClient: server.Client(),
			}

			ctx, err := a.Authenticate(context.Background(), "/test", tt.headers, "10.0.0.1")
			require.NoError(t, err)

			headers := dauth.FromContext(ctx)
			for key, value := range tt.expected {
				assert.Equal(t, value, headers[key], "header %s mismatch", key)
			}
			for _, key := range tt.absent {
				assert.NotContains(t, headers, key)
			}
		})
	}
}
