package slogc

import (
	"context"
	"fmt"
	"log/slog"
	"os"
)

const LevelFine = slog.LevelDebug - 4

func New(level string, format string) (*slog.Logger, error) {
	var logLevel slog.Level
	switch level {
	case "fine":
		logLevel = LevelFine
	case "debug":
		logLevel = slog.LevelDebug
	case "warn":
		logLevel = slog.LevelWarn
	case "error":
		logLevel = slog.LevelError
	case "info", "":
		logLevel = slog.LevelInfo
	default:
		return nil, fmt.Errorf("invalid level '%s' (fine|debug|info|warn|error)", level)
	}

	switch format {
	case "json":
		return slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{
			Level:       logLevel,
			ReplaceAttr: levelReplacer,
		})), nil
	case "text", "":
		return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
			Level:       logLevel,
			ReplaceAttr: levelReplacer,
		})), nil
	default:
		return nil, fmt.Errorf("invalid format '%s' (json|text)", format)
	}
}

func levelReplacer(_ []string, attr slog.Attr) slog.Attr {
	if attr.Key == slog.LevelKey && attr.Value.Any() == LevelFine {
		return slog.String(attr.Key, "FINE")
	}
	return attr
}

func Fine(logger *slog.Logger, msg string, args ...any) {
	logger.Log(context.Background(), LevelFine, msg, args...)
}
