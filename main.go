package main

import (
	"log/slog"
	"net/http"
	"os"
	"testovoe_medods/app"
	"testovoe_medods/config"
	"testovoe_medods/infra/server"
	"testovoe_medods/infra/storage"
)

func main() {
	cfg := config.MustLoadConfig()
	logger := MustConfigureLogging(cfg.LogLevel, cfg.Env)
	db := storage.MustStorageInit(cfg, logger)
	mux := http.NewServeMux()
	app.InitAuthApp(db, logger, cfg, mux)
	server.MustRunServer(cfg, logger, mux, db)
}

func MustConfigureLogging(logLevel string, env string) *slog.Logger {
	var opts slog.HandlerOptions
	switch logLevel {
	case "DEBUG":
		opts = slog.HandlerOptions{
			Level: slog.LevelDebug,
		}
	case "INFO":
		opts = slog.HandlerOptions{
			Level: slog.LevelInfo,
		}
	case "ERROR":
		opts = slog.HandlerOptions{
			Level: slog.LevelError,
		}
	}

	if opts.Level == nil {
		panic("You didn' provide correct log level")
	}

	if env == "local" {
		return slog.New(slog.NewTextHandler(os.Stderr, &opts))
	}
	return slog.New(slog.NewJSONHandler(os.Stderr, &opts))
}
