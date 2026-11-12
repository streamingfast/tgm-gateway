package auth

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jwt"
	"github.com/streamingfast/dauth"
	"go.uber.org/zap"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

var printBadTokenInLogs = os.Getenv("PRINT_BAD_TOKEN_IN_LOGS") == "true"

// Register registers the payment gateway authenticator with dauth
func Register() {
	dauth.Register("tgm", func(config string, logger *zap.Logger) (dauth.Authenticator, error) {
		configExpanded := os.ExpandEnv(config)

		c, err := newConfig(configExpanded)
		if err != nil {
			return nil, fmt.Errorf("failed to parse config string %s: %w", config, err)
		}
		return new(c, logger)
	})
}

func new(config *Config, logger *zap.Logger) (dauth.Authenticator, error) {
	var jwkSet jwk.Set
	switch {
	case config.PubKeyURL != "":
		set, err := jwkSetFromURL(config.PubKeyURL)
		if err != nil {
			return nil, fmt.Errorf("failed to fetch JWK set from %s: %w", config.PubKeyURL, err)
		}
		jwkSet = set
	case config.PubKeyBase64 != "":
		set, err := jwkSetFromBase64(config.PubKeyBase64)
		if err != nil {
			return nil, fmt.Errorf("failed to fetch JWK set from %s: %w", config.PubKeyBase64, err)
		}
		jwkSet = set
	default:
		return nil, fmt.Errorf("no JWK URL or public key URL provided")
	}

	httpClient := &http.Client{Timeout: 15 * time.Second}
	if config.Insecure {
		httpClient.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		}
	}

	a := &authenticator{
		config:     config,
		logger:     logger,
		jwkSet:     jwkSet,
		httpClient: httpClient,
	}
	if config.IndexerAPIKey == "" {
		logger.Warn("You have not set an API key in your auth configuration (`&indexer-api-key=<your_api_key>`). Under heavy load, you may get blacklisted by the '/issue' or '/reissue' endpoints")
	} else {
		jwt, err := a.issueJWTFromAPIKey(context.TODO(), config.IndexerAPIKey)
		if err != nil {
			logger.Error("Failed to issue JWT from the provided API key in your auth configuration (`&indexer-api-key=<your_api_key>`). Under heavy load, you may get blacklisted by the '/issue' or '/reissue' endpoints", zap.Error(err))
		} else {
			var hasIndexerIdentifier bool

			featureConfigs := make(map[string]any)
			if err := jwt.Get("cfg", &featureConfigs); err == nil {
				if _, ok := featureConfigs["INDEXER_IDENTIFIER"]; ok {
					hasIndexerIdentifier = true
				}
			}

			if !hasIndexerIdentifier {
				logger.Error("The provided API key in your auth configuration (`&indexer-api-key=<your_api_key>`) does **NOT** have the required INDEXER_IDENTIFIER claim. Under heavy load, you may get blacklisted by the '/issue' or '/reissue' endpoints", zap.Error(err))
			}
		}
	}
	return a, nil
}

type authenticator struct {
	config     *Config
	logger     *zap.Logger
	jwkSet     jwk.Set
	httpClient *http.Client
}

func (a *authenticator) Authenticate(ctx context.Context, path string, headers map[string][]string, ipAddress string) (context.Context, error) {
	// Convert headers to lowercase for case-insensitive lookup
	lowerHeaders := make(map[string][]string)
	for k, v := range headers {
		lowerHeaders[strings.ToLower(k)] = v
	}

	var token jwt.Token
	var err error

	// Auth info about what the client presented, never about the reissued/issued internal JWT
	var authMethod string
	var clientToken jwt.Token

	// Check for JWT in Authorization header
	if authHeaders, found := lowerHeaders["authorization"]; found && len(authHeaders) > 0 {
		token, err = a.extractAndParseJWT(authHeaders[0])
		if err != nil {
			// Info() here because there won't be any other trace from the handler function
			a.logger.Info("failed to parse JWT from authorization header", zap.Error(err), zap.String("ip_address", ipAddress))
			if errors.Is(err, ErrAuthorizationHeaderFormat) {
				return ctx, status.Error(codes.Unauthenticated, ErrAuthorizationHeaderFormat.Error())
			}
			if strings.Contains(err.Error(), "token is expired") {
				return ctx, status.Errorf(codes.Unauthenticated, "JWT token has expired")
			}
			return ctx, status.Errorf(codes.Unauthenticated, "invalid JWT token")
		}

		authMethod = dauth.AuthMethodJWT
		clientToken = token

		needsReissue := a.needsReissue(token)
		a.logger.Debug("authorization from token", zap.Bool("needsReissue", needsReissue), zap.String("ip_address", ipAddress))

		if needsReissue {
			// Extract the actual JWT string from the authorization header
			tokenString := authHeaders[0]
			if strings.HasPrefix(strings.ToLower(tokenString), "bearer ") {
				tokenString = tokenString[7:] // Remove "Bearer " prefix
			}

			newToken, err := a.reissueJWT(ctx, tokenString)
			if err != nil {
				a.logger.Warn("failed to reissue JWT, continuing with existing token", zap.Error(err))
			} else {
				token = newToken
			}
		}
	} else if apiKeyHeaders, found := lowerHeaders["x-api-key"]; found && len(apiKeyHeaders) > 0 {
		// Handle API key by issuing a new JWT
		token, err = a.issueJWTFromAPIKey(ctx, apiKeyHeaders[0])
		if err != nil {
			// Info() here because there won't be any other trace from the handler function
			a.logger.Info("failed to issue JWT from API key", zap.Error(err), zap.String("ip_address", ipAddress))
			return ctx, status.Errorf(codes.Unauthenticated, "failed to authenticate with API key: %q", err)
		}
		authMethod = dauth.AuthMethodAPIKey
		a.logger.Debug("authorization from api key", zap.String("ip_address", ipAddress))
	} else {
		// Info() here because there won't be any other trace from the handler function
		a.logger.Info("invalid unauthenticated request", zap.Error(err), zap.String("ip_address", ipAddress))
		return ctx, status.Error(codes.Unauthenticated, "required authorization token not found. Please provide a valid JWT token via 'authorization' header or an API key via 'x-api-key' header")
	}

	// Extract claims from JWT and add to context
	ctx = a.addClaimsToContext(ctx, token, ipAddress, authMethod, clientToken)

	return ctx, nil
}

var ErrAuthorizationHeaderFormat = errors.New("authorization header format must be 'Bearer {token}'")

func (a *authenticator) extractAndParseJWT(authHeader string) (jwt.Token, error) {
	authHeaderParts := strings.Fields(authHeader)

	var tokenString string
	switch len(authHeaderParts) {
	case 1:
		tokenString = authHeaderParts[0]
	case 2:
		if strings.ToLower(authHeaderParts[0]) != "bearer" {
			return nil, ErrAuthorizationHeaderFormat
		}
		tokenString = authHeaderParts[1]
	default:
		return nil, ErrAuthorizationHeaderFormat
	}

	return a.ParseJWT(tokenString)
}

func (a *authenticator) ParseJWT(tokenString string) (jwt.Token, error) {
	var lastErr error
	var token jwt.Token

	for i := range a.jwkSet.Len() {
		key, ok := a.jwkSet.Key(i)
		if !ok {
			break
		}

		tok, err := jwt.Parse([]byte(tokenString), jwt.WithKey(jwa.ES256(), key), jwt.WithValidate(true))
		if err != nil {
			if printBadTokenInLogs {
				a.logger.Debug("failed to parse JWT token", zap.String("token", tokenString), zap.Error(err))
			}
			lastErr = err
			continue
		}
		token = tok
	}
	return token, lastErr
}

func (a *authenticator) issueJWTFromAPIKey(ctx context.Context, apiKey string) (jwt.Token, error) {
	// Prepare the request body
	requestBody := map[string]string{
		"api_key": apiKey,
	}
	jsonData, err := json.Marshal(requestBody)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	// Create the HTTP request
	req, err := http.NewRequestWithContext(ctx, "POST", a.config.IssueURL, bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if a.config.IndexerAPIKey != "" {
		req.Header.Set("X-Api-Key", a.config.IndexerAPIKey)
	}

	// Send the request
	resp, err := a.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to call issue endpoint: %w", err)
	}
	defer resp.Body.Close()

	// Read the response
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("issue endpoint returned status %d: %s", resp.StatusCode, string(body))
	}

	// Parse the response to get the JWT
	var issueResponse struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(body, &issueResponse); err != nil {
		return nil, fmt.Errorf("failed to parse issue response: %w", err)
	}

	// Parse and return the JWT
	return a.ParseJWT(issueResponse.Token)
}

func (a *authenticator) reissueJWT(ctx context.Context, tokenString string) (jwt.Token, error) {
	// Prepare the request body with the JWT string
	requestBody := map[string]string{
		"jwt": tokenString,
	}
	jsonData, err := json.Marshal(requestBody)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal reissue request: %w", err)
	}

	// Prepare the request
	req, err := http.NewRequestWithContext(ctx, "POST", a.config.ReissueURL, bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, fmt.Errorf("failed to create reissue request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if a.config.IndexerAPIKey != "" {
		req.Header.Set("X-Api-Key", a.config.IndexerAPIKey)
	}

	// Send the request
	resp, err := a.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to call reissue endpoint: %w", err)
	}
	defer resp.Body.Close()

	// Read the response
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read reissue response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("reissue endpoint returned status %d: %s", resp.StatusCode, string(body))
	}

	// Parse the response to get the new JWT
	var reissueResponse struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(body, &reissueResponse); err != nil {
		// If parsing as JSON fails, assume the response is the raw token
		return a.ParseJWT(string(body))
	}

	// Parse and return the new JWT
	return a.ParseJWT(reissueResponse.Token)
}

func (a *authenticator) needsReissue(token jwt.Token) bool {
	issuedAt, _ := token.IssuedAt()
	return uint64(time.Since(issuedAt).Seconds()) > a.config.ReissueJWTAgeSecs
}

// addClaimsToContext sets the trusted headers from the claims of `token`. `authMethod` is how the client
// authenticated and `clientToken` the JWT it presented (nil for API key), which can differ from `token`
// when the JWT was reissued or issued from an API key.
func (a *authenticator) addClaimsToContext(ctx context.Context, token jwt.Token, ipAddress string, authMethod string, clientToken jwt.Token) context.Context {

	// Create trusted headers map
	trustedHeaders := make(dauth.TrustedHeaders)

	// Add standard headers
	var organizationID string
	if err := token.Get("uid", &organizationID); err == nil {
		trustedHeaders[dauth.HeaderOrganizationID] = organizationID
	} else if subject, ok := token.Subject(); ok {
		// Legacy support: extract organization ID from subject if it starts with "uid:"
		if after, cut := strings.CutPrefix(subject, "uid:"); cut {
			trustedHeaders[dauth.HeaderOrganizationID] = after
		}
	}

	var apiKeyID string
	if err := token.Get("aki", &apiKeyID); err == nil {
		trustedHeaders[dauth.HeaderApiKeyID] = apiKeyID
	}

	// Add IP address
	trustedHeaders[dauth.HeaderIP] = ipAddress

	// Add feature configs from JWT claims
	var featureConfigs map[string]any
	if err := token.Get("cfg", &featureConfigs); err == nil {
		for key, value := range featureConfigs {
			headerKey := jwtFeatureConfigKeyToHeader(key)
			if strValue, ok := value.(string); ok {
				trustedHeaders[headerKey] = strValue
			}
		}
	}

	// Plan tier is not in feature_configs, but given as claim anyway
	var substreamsPlanTier string
	if err := token.Get("substreams_plan_tier", &substreamsPlanTier); err == nil {
		trustedHeaders[dauth.HeaderSubstreamsPlanTier] = substreamsPlanTier
	}

	if authMethod != "" {
		trustedHeaders[dauth.HeaderAuthMethod] = authMethod
		AuthCounter.Inc(authMethod, jwtLifetimeBucketOf(authMethod, clientToken))
	}

	if authMethod == dauth.AuthMethodJWT && clientToken != nil {
		issuedAt, hasIat := clientToken.IssuedAt()
		expiresAt, hasExp := clientToken.Expiration()
		if hasIat {
			trustedHeaders[dauth.HeaderAuthJWTIssuedAt] = strconv.FormatInt(issuedAt.Unix(), 10)
		}
		if hasExp {
			trustedHeaders[dauth.HeaderAuthJWTExpiresAt] = strconv.FormatInt(expiresAt.Unix(), 10)
		}
		trustedHeaders[dauth.HeaderAuthJWTLifetimeBucket] = jwtLifetimeBucket(issuedAt, hasIat, expiresAt, hasExp)
	}

	a.logger.Debug("added claims", zap.Any("headers", trustedHeaders))

	// Add trusted headers to context
	return dauth.WithTrustedHeaders(ctx, trustedHeaders)
}

// jwtLifetimeBucketOf returns the bucket label used for the [AuthCounter] metric only (it has no
// effect on trusted headers). Non-JWT methods have no lifetime bucket, so they get the explicit
// "none" label value rather than an empty string, which would be easy to mistake for a missing label
// on the metric dimension.
func jwtLifetimeBucketOf(authMethod string, clientToken jwt.Token) string {
	if authMethod != dauth.AuthMethodJWT || clientToken == nil {
		return "none"
	}

	issuedAt, hasIat := clientToken.IssuedAt()
	expiresAt, hasExp := clientToken.Expiration()
	return jwtLifetimeBucket(issuedAt, hasIat, expiresAt, hasExp)
}

// jwtLifetimeBucket must stay in sync with the sf-saas authenticator bucket values.
func jwtLifetimeBucket(issuedAt time.Time, hasIat bool, expiresAt time.Time, hasExp bool) string {
	if !hasIat || !hasExp {
		return dauth.AuthJWTLifetimeBucketUnknown
	}

	lifetime := expiresAt.Sub(issuedAt)
	switch {
	case lifetime <= 15*time.Minute:
		return dauth.AuthJWTLifetimeBucketLE15m
	case lifetime <= 24*time.Hour:
		return dauth.AuthJWTLifetimeBucketLE24h
	case lifetime >= 3650*24*time.Hour:
		return dauth.AuthJWTLifetimeBucketGTE10y
	default:
		return dauth.AuthJWTLifetimeBucketGT24h
	}
}

func jwtFeatureConfigKeyToHeader(featureConfigKey string) string {
	return "x-" + strings.Replace(strings.ToLower(featureConfigKey), "_", "-", -1)
}

func (a *authenticator) Ready(ctx context.Context) bool {
	return true
}
