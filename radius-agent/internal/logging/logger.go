package logging

import (
	"context"
	"log/slog"
	"os"

	"github.com/google/uuid"
)

type ctxKey string

const requestIDKey ctxKey = "request_id"

// Setup initializes the global slog logger based on config.
func Setup(level, format string) {
	var lvl slog.Level
	switch level {
	case "debug":
		lvl = slog.LevelDebug
	case "warn":
		lvl = slog.LevelWarn
	case "error":
		lvl = slog.LevelError
	default:
		lvl = slog.LevelInfo
	}

	opts := &slog.HandlerOptions{Level: lvl}
	var handler slog.Handler
	if format == "text" {
		handler = slog.NewTextHandler(os.Stdout, opts)
	} else {
		handler = slog.NewJSONHandler(os.Stdout, opts)
	}
	slog.SetDefault(slog.New(handler))
}

// WithRequestID adds a new request ID to the context.
func WithRequestID(ctx context.Context) context.Context {
	return context.WithValue(ctx, requestIDKey, uuid.New().String())
}

// RequestID retrieves the request ID from context.
func RequestID(ctx context.Context) string {
	if id, ok := ctx.Value(requestIDKey).(string); ok {
		return id
	}
	return ""
}

// Logger returns a slog.Logger enriched with the request ID from context.
func Logger(ctx context.Context) *slog.Logger {
	l := slog.Default()
	if id := RequestID(ctx); id != "" {
		l = l.With("request_id", id)
	}
	return l
}
