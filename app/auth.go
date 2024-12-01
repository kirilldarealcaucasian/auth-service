package app

import (
	"log/slog"
	"net/http"
	"testovoe_medods/api/handlers"
	"testovoe_medods/api/routes"
	"testovoe_medods/config"
	auth "testovoe_medods/repository"
	auths "testovoe_medods/service"

	"github.com/jmoiron/sqlx"
)


func InitAuthApp(db *sqlx.DB, log *slog.Logger, cfg *config.Config, mux *http.ServeMux) {
	authRepo := auth.NewUserAuthRepository(db)
	authService := auths.NewUserAuthService(
		log,
		cfg,
		authRepo,
	)
	authHandler := handlers.NewAuthHandler(cfg, authService)
	routes.RegisterAuthRoutes(mux, authHandler)
}