package logging

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"vectorcore-epdg/internal/config"
)

type Logger struct {
	*slog.Logger
	close func() error
}

func New(cfg config.LoggingConfig, debugConsole bool) (*Logger, error) {
	level := parseLevel(cfg.Level)
	var handlers []slog.Handler
	var closeFns []func() error

	if cfg.File != "" {
		if err := os.MkdirAll(filepath.Dir(cfg.File), 0o755); err != nil {
			if !debugConsole {
				return nil, fmt.Errorf("create log directory for %q: %w", cfg.File, err)
			}
			fmt.Fprintf(os.Stderr, "VectorCore ePDG: cannot open log file %q: %v\n", cfg.File, err)
		} else {
			f, err := os.OpenFile(cfg.File, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
			if err != nil {
				if !debugConsole {
					return nil, fmt.Errorf("open log file %q: %w", cfg.File, err)
				}
				fmt.Fprintf(os.Stderr, "VectorCore ePDG: cannot open log file %q: %v\n", cfg.File, err)
			} else {
				handlers = append(handlers, jsonHandler(f, level))
				closeFns = append(closeFns, f.Close)
			}
		}
	}

	if debugConsole {
		handlers = append(handlers, jsonHandler(os.Stderr, slog.LevelDebug))
	}
	if len(handlers) == 0 {
		return nil, fmt.Errorf("no logging sink configured")
	}

	return &Logger{
		Logger: slog.New(multiHandler{handlers: handlers}),
		close: func() error {
			var errs []error
			for _, fn := range closeFns {
				if err := fn(); err != nil {
					errs = append(errs, err)
				}
			}
			return errors.Join(errs...)
		},
	}, nil
}

func jsonHandler(w io.Writer, level slog.Leveler) slog.Handler {
	return slog.NewJSONHandler(w, &slog.HandlerOptions{
		AddSource: true,
		Level:     level,
	})
}

type multiHandler struct {
	handlers []slog.Handler
}

func (h multiHandler) Enabled(ctx context.Context, level slog.Level) bool {
	for _, handler := range h.handlers {
		if handler.Enabled(ctx, level) {
			return true
		}
	}
	return false
}

func (h multiHandler) Handle(ctx context.Context, record slog.Record) error {
	var errs []error
	for _, handler := range h.handlers {
		if !handler.Enabled(ctx, record.Level) {
			continue
		}
		if err := handler.Handle(ctx, record.Clone()); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func (h multiHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	handlers := make([]slog.Handler, 0, len(h.handlers))
	for _, handler := range h.handlers {
		handlers = append(handlers, handler.WithAttrs(attrs))
	}
	return multiHandler{handlers: handlers}
}

func (h multiHandler) WithGroup(name string) slog.Handler {
	handlers := make([]slog.Handler, 0, len(h.handlers))
	for _, handler := range h.handlers {
		handlers = append(handlers, handler.WithGroup(name))
	}
	return multiHandler{handlers: handlers}
}

func (l *Logger) Close() error {
	if l == nil || l.close == nil {
		return nil
	}
	return l.close()
}

func parseLevel(level string) slog.Level {
	switch strings.ToLower(strings.TrimSpace(level)) {
	case "debug":
		return slog.LevelDebug
	case "warn", "warning":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}
