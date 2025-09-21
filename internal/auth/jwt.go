// Package auth provides authentication and authorization utilities
package auth

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/brandon/cotex-backend/internal/logger"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/rs/zerolog"
)

// Define the context key for user claims
type contextKey string

const UserContextKey contextKey = "user"

var (
	// ErrNoAuthHeader is returned when no Authorization header is present
	ErrNoAuthHeader = errors.New("no authorization header present")
	// ErrInvalidAuthHeader is returned when Authorization header is malformed
	ErrInvalidAuthHeader = errors.New("invalid authorization header format")
	// ErrInvalidToken is returned when JWT token validation fails
	ErrInvalidToken = errors.New("invalid token")
)

// Config stores auth-related configuration
type Config struct {
	SupabaseURL string
	JWKSPath    string
}

// Authenticator handles JWT validation from Supabase
type Authenticator struct {
	jwksURL   string
	keySet    jwk.Set
	lastFetch time.Time
	cacheTTL  time.Duration
	jwtSecret string
	log       zerolog.Logger
}

// UserClaims represents user information from the JWT token
type UserClaims struct {
	UserID    string `json:"sub"`
	Email     string `json:"email"`
	Role      string `json:"role"`
	ExpiresAt int64  `json:"exp"`
}

// NewAuthenticator creates a new Authenticator instance
func NewAuthenticator(supabaseURL, jwtSecret string) *Authenticator {
	// Default JWKS path for Supabase
	jwksURL := fmt.Sprintf("%s/auth/v1/jwks", supabaseURL)

	log := logger.Logger(map[string]interface{}{"component": "authenticator"})

	auth := &Authenticator{
		jwksURL:   jwksURL,
		cacheTTL:  12 * time.Hour, // Cache keys for 12 hours
		jwtSecret: jwtSecret,
		log:       log,
	}

	// Initial fetch of keys
	err := auth.refreshKeys()
	if err != nil {
		auth.log.Warn().Err(err).Msg("Failed to fetch initial JWKS")
	} else {
		auth.log.Info().Int("keys", auth.keySet.Len()).Msg("Initial JWKS fetched successfully")
	}

	return auth
}

// refreshKeys fetches the latest JWKS from Supabase
func (a *Authenticator) refreshKeys() error {
	a.log.Debug().Str("url", a.jwksURL).Msg("Fetching JWKS")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	set, err := jwk.Fetch(ctx, a.jwksURL)
	if err != nil {
		return err
	}

	a.keySet = set
	a.lastFetch = time.Now()
	a.log.Debug().Int("keys", set.Len()).Msg("JWKS refreshed successfully")
	return nil
}

// checkAndRefreshKeys refreshes the key set if cache has expired
func (a *Authenticator) checkAndRefreshKeys() error {
	if time.Since(a.lastFetch) > a.cacheTTL {
		return a.refreshKeys()
	}
	return nil
}

// ExtractToken gets the token from the Authorization header
func ExtractToken(r *http.Request) (string, error) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return "", ErrNoAuthHeader
	}

	parts := strings.Split(authHeader, " ")
	if len(parts) != 2 || parts[0] != "Bearer" {
		return "", ErrInvalidAuthHeader
	}

	return parts[1], nil
}

// ValidateToken validates a JWT token against Supabase JWKS, with HS256 fallback
func (a *Authenticator) ValidateToken(tokenString string) (*UserClaims, error) {
	// Check if we need to refresh keys (best-effort)
	if err := a.checkAndRefreshKeys(); err != nil {
		a.log.Warn().Err(err).Msg("Failed to refresh JWKS, continuing with existing keys")
	}

	var (
		token jwt.Token
		err   error
	)

	// Accept small clock skew to avoid strict iat/nbf issues
	const skew = 5 * time.Minute
	a.log.Debug().Dur("acceptable_skew", skew).Msg("JWT validation using acceptable skew for claims")

	// 1) Try HS256 with SUPABASE_JWT_SECRET first if configured
	if a.jwtSecret != "" {
		a.log.Debug().Msg("Attempting HS256 token validation with SUPABASE_JWT_SECRET")
		token, err = jwt.Parse(
			[]byte(tokenString),
			jwt.WithKey(jwa.HS256, []byte(a.jwtSecret)),
			jwt.WithValidate(true),
			jwt.WithAcceptableSkew(skew),
		)
		if err == nil {
			return a.extractClaims(token)
		}
		a.log.Debug().Err(err).Msg("HS256 validation failed; will try JWKS if available")
	}

	// 2) Try RS*/EC* via JWKS if we have keys
	if a.keySet != nil && a.keySet.Len() > 0 {
		a.log.Debug().Int("jwks_keys", a.keySet.Len()).Msg("Attempting JWKS-based token validation")
		token, err = jwt.Parse(
			[]byte(tokenString),
			jwt.WithKeySet(a.keySet),
			jwt.WithValidate(true),
			jwt.WithAcceptableSkew(skew),
		)
		if err == nil {
			return a.extractClaims(token)
		}
		a.log.Debug().Err(err).Msg("JWKS validation failed")
	} else {
		a.log.Debug().Msg("No JWKS keys available; skipping JWKS validation")
	}

	return nil, fmt.Errorf("%w: token validation failed with both HS256 and JWKS", ErrInvalidToken)
}

// extractClaims builds UserClaims from a validated token
func (a *Authenticator) extractClaims(token jwt.Token) (*UserClaims, error) {
	userClaims := &UserClaims{
		UserID: token.Subject(),
	}

	if email, ok := token.Get("email"); ok {
		if emailStr, ok := email.(string); ok {
			userClaims.Email = emailStr
		}
	}

	if role, ok := token.Get("role"); ok {
		if roleStr, ok := role.(string); ok {
			userClaims.Role = roleStr
		}
	}

	if exp := token.Expiration(); !exp.IsZero() {
		userClaims.ExpiresAt = exp.Unix()
	}

	a.log.Debug().
		Str("user_id", userClaims.UserID).
		Str("email", userClaims.Email).
		Str("role", userClaims.Role).
		Msg("Token validated successfully")

	return userClaims, nil
}

// Middleware creates an http middleware for JWT authentication
func (a *Authenticator) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token, err := ExtractToken(r)
		if err != nil {
			a.log.Warn().
				Err(err).
				Str("path", r.URL.Path).
				Msg("Authentication failed: no token")
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		claims, err := a.ValidateToken(token)
		if err != nil {
			a.log.Warn().
				Err(err).
				Str("path", r.URL.Path).
				Msg("Authentication failed: invalid token")
			http.Error(w, "Invalid token", http.StatusUnauthorized)
			return
		}

		// Store user info in context using the proper context key
		ctx := context.WithValue(r.Context(), UserContextKey, claims)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// GetUserFromContext extracts user claims from the request context
func GetUserFromContext(ctx context.Context) (*UserClaims, bool) {
	user, ok := ctx.Value(UserContextKey).(*UserClaims)
	return user, ok
}
