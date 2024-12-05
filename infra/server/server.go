package server

import (
	"context"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"testovoe_medods/config"
	"time"

	"github.com/jmoiron/sqlx"
)

func NewServer(addr string, readTimeout time.Duration, writeTimeout time.Duration, mux *http.ServeMux) *http.Server {
	return &http.Server{
		Addr:         addr,
		Handler: mux,
		ReadTimeout:  readTimeout,
		WriteTimeout: writeTimeout,
	}
}

func MustRunServer(cfg *config.Config, logger *slog.Logger, mux *http.ServeMux, db *sqlx.DB) {
	httpSrv := NewServer(
		cfg.HTTPServer.Addr,
		cfg.HTTPServer.ReadTimeout,
		cfg.HTTPServer.WriteTimeout,
		mux,
	)

	go func() {
		logger.Info("Starting http server . . .")
		if err := httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		panic("Failed to start http server")
		}
	}()
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGTERM, syscall.SIGINT)
	signal := <-stop
	logger.Info("Received signal", slog.String("signal: ", signal.String()))
	GracefulShutDown(httpSrv, logger, db)
}

func GracefulShutDown(srv *http.Server, logger *slog.Logger, db *sqlx.DB) {
	logger.Info("Shutting down the server . . .")
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		panic("Failed to shutdown http server")
	}
	logger.Info("Shutting down the database connection . . .")
	db.Close()
}