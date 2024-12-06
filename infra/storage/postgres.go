package storage

import (
	"fmt"
	"log/slog"
	"strconv"
	"testovoe_medods/config"

	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/jmoiron/sqlx"
)

func setUpDBData(con *sqlx.DB) error {
	q := `
	CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

	CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    email VARCHAR(255) UNIQUE NOT NULL);

	CREATE TABLE IF NOT EXISTS users_auth_info (
				id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
				user_guid UUID,
				refresh_token_hash VARCHAR,
				ip_address VARCHAR NOT NULL,
			  UNIQUE (user_guid, refresh_token_hash),
				FOREIGN KEY (user_guid) REFERENCES users(id) ON DELETE CASCADE);
	
	INSERT INTO users (email) VALUES ('test@gmail.com') ON CONFLICT (email) DO NOTHING;
				
				`
	_, err := con.Exec(q)
	if err != nil {
		return err
	}
	return nil
}


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

	err = setUpDBData(db)
	if err != nil {
		panic(err)
	}
	logger.Info("Tables have been created")
	return db
}