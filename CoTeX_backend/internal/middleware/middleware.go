// Package middleware provides HTTP middleware functionality
package middleware

import (
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/brandon/cotex-backend/internal/logger"
	"github.com/rs/zerolog"
)

// RateLimiter implements rate limiting for API endpoints
type RateLimiter struct {
	// requests tracks the number of requests by IP address
	requests map[string][]time.Time
	// requestsPerMinute defines the maximum number of requests allowed per minute
	requestsPerMinute int
	// mutex for thread safety
	mu sync.Mutex
	// logger instance
	log zerolog.Logger
}

// NewRateLimiter creates a new rate limiter with the specified limit
func NewRateLimiter(requestsPerMinute int) *RateLimiter {
	return &RateLimiter{
		requests:          make(map[string][]time.Time),
		requestsPerMinute: requestsPerMinute,
		log:               logger.Logger(map[string]interface{}{"component": "rate_limiter"}),
	}
}

// cleanupOldRequests removes requests older than one minute
func (rl *RateLimiter) cleanupOldRequests() {
	now := time.Now()
	for ip, times := range rl.requests {
		var newTimes []time.Time
		for _, t := range times {
			if now.Sub(t) < time.Minute {
				newTimes = append(newTimes, t)
			}
		}
		if len(newTimes) == 0 {
			delete(rl.requests, ip)
		} else {
			rl.requests[ip] = newTimes
		}
	}
}

// getClientIP extracts the client IP address from the request
func getClientIP(r *http.Request) string {
	// Check for X-Forwarded-For header
	if xForwardedFor := r.Header.Get("X-Forwarded-For"); xForwardedFor != "" {
		// X-Forwarded-For can contain multiple IPs, use the first one
		ips := splitCommaList(xForwardedFor)
		if len(ips) > 0 {
			return ips[0]
		}
	}

	// Check for X-Real-IP header
	if xRealIP := r.Header.Get("X-Real-IP"); xRealIP != "" {
		return xRealIP
	}

	// Fall back to RemoteAddr
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr // Return unsplit if there's an error
	}
	return ip
}

// splitCommaList splits a comma-separated string into a slice
func splitCommaList(s string) []string {
	var result []string
	current := ""
	for i := 0; i < len(s); i++ {
		if s[i] == ',' {
			if current != "" {
				result = append(result, current)
				current = ""
			}
		} else if s[i] == ' ' && current == "" {
			// Skip leading spaces after commas
			continue
		} else {
			current += string(s[i])
		}
	}
	if current != "" {
		result = append(result, current)
	}
	return result
}

// Middleware returns an HTTP middleware function that implements rate limiting
func (rl *RateLimiter) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := getClientIP(r)

		rl.mu.Lock()
		defer rl.mu.Unlock()

		// Clean up old requests periodically
		rl.cleanupOldRequests()

		// Get the current time
		now := time.Now()

		// Add the current request to the list
		rl.requests[ip] = append(rl.requests[ip], now)

		// Check if the number of requests exceeds the limit
		if len(rl.requests[ip]) > rl.requestsPerMinute {
			rl.log.Warn().
				Str("ip", ip).
				Int("count", len(rl.requests[ip])).
				Int("limit", rl.requestsPerMinute).
				Msg("Rate limit exceeded")

			w.Header().Set("Retry-After", "60")
			http.Error(w, "Rate limit exceeded", http.StatusTooManyRequests)
			return
		}

		// Call the next handler
		next.ServeHTTP(w, r)
	})
}

// LoggingMiddleware adds request logging
func LoggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		// Create request info for logging
		reqInfo := &logger.RequestInfo{
			Method:    r.Method,
			Path:      r.URL.Path,
			IP:        getClientIP(r),
			UserAgent: r.UserAgent(),
		}

		// Log the request
		log := logger.WithRequest(reqInfo)
		log.Info().Msg("Request received")

		// Call the next handler
		next.ServeHTTP(w, r)

		// Log the response time
		log.Info().
			Dur("duration", time.Since(start)).
			Msg("Request completed")
	})
}

// OriginCheckMiddleware validates Origin header for WebSocket connections
func OriginCheckMiddleware(allowedOrigins []string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			origin := r.Header.Get("Origin")
			if origin == "" {
				// No Origin header, might be a non-browser request
				next.ServeHTTP(w, r)
				return
			}

			// Check if the origin is allowed
			allowed := false
			for _, allowedOrigin := range allowedOrigins {
				if origin == allowedOrigin || allowedOrigin == "*" {
					allowed = true
					break
				}
			}

			if !allowed {
				log := logger.Logger(map[string]interface{}{"component": "origin_check"})
				log.Warn().
					Str("origin", origin).
					Strs("allowed_origins", allowedOrigins).
					Msg("Origin not allowed")

				http.Error(w, "Origin not allowed", http.StatusForbidden)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// CORSMiddleware sets CORS headers to allow cross-origin requests
func CORSMiddleware(allowedOrigins []string) func(http.Handler) http.Handler {
	// Convert slice to map for faster lookup
	allowed := make(map[string]bool)
	for _, origin := range allowedOrigins {
		allowed[origin] = true
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			origin := r.Header.Get("Origin")

			// Set CORS headers for allowed origins
			originAllowed := false
			if origin != "" {
				originAllowed = allowed[origin] || allowed["*"]
			} else {
				// If no origin header, allow if wildcard is enabled
				originAllowed = allowed["*"]
			}

			if originAllowed {
				if origin != "" {
					w.Header().Set("Access-Control-Allow-Origin", origin)
				} else if allowed["*"] {
					w.Header().Set("Access-Control-Allow-Origin", "*")
				}
				w.Header().Set("Vary", "Origin")
				w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS")
				w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, Accept, X-Requested-With")
				w.Header().Set("Access-Control-Allow-Credentials", "true")
				w.Header().Set("Access-Control-Max-Age", "86400")
			}

			// Handle preflight OPTIONS requests
			if r.Method == http.MethodOptions {
				w.WriteHeader(http.StatusNoContent)
				return
			}

			// Continue to next middleware/handler - CORS headers are already set
			next.ServeHTTP(w, r)
		})
	}
}
