// Package logger provides structured logging functionality
package logger

import (
	"os"
	"time"

	"github.com/brandon/cotex-backend/internal/config"
	"github.com/rs/zerolog"
)

var log zerolog.Logger

// Setup initializes the logger with the appropriate configuration
func Setup(cfg *config.Config) {
	// Configure time format
	zerolog.TimeFieldFormat = time.RFC3339

	// Set global log level based on environment
	level := zerolog.InfoLevel
	if cfg.Environment == "development" {
		level = zerolog.DebugLevel
	}
	zerolog.SetGlobalLevel(level)

	// Create console writer for development environment
	var output zerolog.ConsoleWriter
	if cfg.Environment == "development" {
		output = zerolog.ConsoleWriter{
			Out:        os.Stdout,
			TimeFormat: "15:04:05",
		}
		log = zerolog.New(output).With().Timestamp().Caller().Logger()
	} else {
		// For production, use JSON format for better log processing
		log = zerolog.New(os.Stdout).With().Timestamp().Logger()
	}
}

// Logger returns a zerolog logger with the specified fields
func Logger(fields map[string]interface{}) zerolog.Logger {
	ctx := log.With()
	for k, v := range fields {
		ctx = ctx.Interface(k, v)
	}
	return ctx.Logger()
}

// WithUserID returns a logger with user_id field
func WithUserID(userID string) zerolog.Logger {
	return log.With().Str("user_id", userID).Logger()
}

// WithRepoID returns a logger with repo_id field
func WithRepoID(repoID string) zerolog.Logger {
	return log.With().Str("repo_id", repoID).Logger()
}

// WithRequest returns a logger with request-related fields
func WithRequest(r *RequestInfo) zerolog.Logger {
	return log.With().
		Str("method", r.Method).
		Str("path", r.Path).
		Str("ip", r.IP).
		Str("user_agent", r.UserAgent).
		Logger()
}

// RequestInfo contains HTTP request information for logging
type RequestInfo struct {
	Method    string
	Path      string
	IP        string
	UserAgent string
}
