package config

import (
	"fmt"
	"time"

	"github.com/ilyakaznacheev/cleanenv"
)


type Config struct {
	Env            string        `yaml:"env" env-default:"local"`
	LogLevel     string `yaml:"log_level" env-required:"true"`
	AccessTokenTTL string `yaml:"access_token_ttl" env-required:"true"`
	RefreshTokenTTL string `yaml:"refresh_token_ttl" env-required:"true"`
	Database Database `yaml:"database" env-required:"true"`
	HTTPServer Server `yaml:"http_server" env-required:"true"`
	Token Token `yaml:"token" env-required:"true"`
}

type Token struct {
	AccessTokenTTL time.Duration `yaml:"access_token_ttl" env-required:"true"`
	RefreshTokenTTL time.Duration `yaml:"refresh_token_ttl" env-required:"true"`
}

type Database struct {
	PostgresUser string `yaml:"postgres_user" env-required:"true"`
	PostgresPassword string `yaml:"postgres_password" env-required:"true"`
	PostgresHostname string `yaml:"postgres_hostname" env-required:"true"`
	PostgresPort int `yaml:"postgres_port" env-required:"true"`
	PostgresDBName string `yaml:"postgres_db_name" env-required:"true"`
	Timeout time.Duration `yaml:"timeout" env-defailt:"1"`
}

type Server struct {
	Addr string   `yaml:"addr" env-required:"true"`
	ReadTimeout time.Duration `yaml:"read_timeout" env-required:"true"`
	WriteTimeout time.Duration `yaml:"write_timeout" env-required:"true"`
}

func MustLoadConfig() *Config {
	var cfg Config

	config_path := "суда конфиг"
	// err := fetchConfigByPath(&cfg, os.Getenv("CONFIG_PATH"))
	err := fetchConfigByPath(&cfg, config_path)

	if err != nil {
		panic(err)
	}

	return &cfg
}

func fetchConfigByPath(cfg *Config, path string ) error {
	const op = "config.fetchConfigByPath"
	err := cleanenv.ReadConfig(path, cfg)
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}
	return nil
}