package storage

import (
	"fmt"
	"log/slog"
	"strconv"
	"testovoe_medods/config"

	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/jmoiron/sqlx"
)




func MustStorageInit(cfg *config.Config, logger *slog.Logger) *sqlx.DB {
	dsn := fmt.Sprintf("user=%s password=%s host=%s port=%s dbname=%s sslmode=disable", cfg.Database.PostgresUser, cfg.Database.PostgresPassword, cfg.Database.PostgresHostname, strconv.Itoa(cfg.Database.PostgresPort), cfg.Database.PostgresDBName)
	db, err := sqlx.Connect("pgx", dsn)

	if err != nil {
		panic(err)
	}

  if err := db.Ping(); err != nil {
      panic(err)
    }
		
  logger.Info("Successfully connected to db")
	return db
}