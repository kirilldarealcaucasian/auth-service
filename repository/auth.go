package repo

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net"
	"testovoe_medods/entities"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
)

var ErrEntityNotExists = errors.New("entity doesn't exist")

type AuthRepository interface {
	StoreAuthData(ctx context.Context, guid, token string, ip_address net.IP) error
	UpdateAuthInfo(ctx context.Context, data *entities.UserAuthInfo) error
	UpdateRefreshTokenHash(ctx context.Context, data *entities.UserAuthInfo) error
	CreateAuthInfo(ctx context.Context, data *entities.UserAuthInfo) (string, error)
	GetRefreshTokenHash(ctx context.Context, tokenId string) (string, error)
	GetAuthInfoByUserGuid(ctx context.Context, guid string) (*entities.UserWithAuthCreds, error)
	GetRefreshTokenId(ctx context.Context, tHash string) (*int64, error)
}

type userAuthRepository struct {
	db *sqlx.DB
}

func NewUserAuthRepository(db *sqlx.DB) AuthRepository {
	return &userAuthRepository{
		db: db,
	}
}

func (s *userAuthRepository) StoreAuthData(ctx context.Context, guid, tokenHash string, ip_address net.IP) error {
	const op = "auth.StoreToken"

	var authInfo entities.UserAuthInfo
	q := "SELECT * FROM refresh_tokens WHERE guid = $1;"
	err := s.db.Get(&authInfo, q, guid)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			query := "INSERT INTO refresh_tokens (guid, refresh_token_hash, ip_address) VALUES ($1, $2, $3);"
			_, err := s.db.ExecContext(ctx, query, guid, tokenHash, ip_address.String())
			if err != nil {
				return fmt.Errorf("%s, %w", op, err)
			}
		}
		return fmt.Errorf("%s, %w", op, err)
	}

	updateQ := "UPDATE refresh_tokens SET refresh_token_hash=$1 WHERE guid=$2"
	_, err = s.db.ExecContext(ctx, updateQ, tokenHash, guid)
	if err != nil {
		return fmt.Errorf("%s, %w", op, err)
	}
	return nil
}

func (s *userAuthRepository) GetRefreshTokenHash(ctx context.Context, tokenId string) (string, error) {
	const op = "auth.GetRefreshTokenHash"

	q := "SELECT refresh_token_hash FROM users_auth_info WHERE id = $1"

	var tokenHash string
	err := s.db.GetContext(ctx, &tokenHash, q, tokenId)

	if err != nil {
		return "", fmt.Errorf("%s, %w", op, err)
	}
	return tokenHash, nil
}

func (s *userAuthRepository) GetAuthInfoByUserGuid(ctx context.Context, guid string) (*entities.UserWithAuthCreds, error) {
	const op = "repo.GetAuthInfo"

	q := "SELECT users.id, email, refresh_token_hash, ip_address FROM users LEFT JOIN users_auth_info ON users.id = users_auth_info.user_guid WHERE users.id = $1"
	var authInfo entities.UserWithAuthCreds
	err := s.db.GetContext(ctx, &authInfo, q, guid)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrEntityNotExists
	}
	if err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}
	return &authInfo, nil
}

func(s *userAuthRepository)  GetAuthInfoByRefreshTokenHash(ctx context.Context, tHash string) (*entities.UserWithAuthCreds, error) {
	const op = "repo.GetAuthInfoByRefreshTokenHash"

	q := "SELECT users.id, email, refresh_token_hash, ip_address FROM users LEFT JOIN users_auth_info ON users.id = users_auth_info.user_guid WHERE refresh_token_hash = $1"

	var authInfo entities.UserWithAuthCreds
	err := s.db.GetContext(ctx, &authInfo, q, tHash)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrEntityNotExists
	}
	if err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}
	return &authInfo, nil
}

func (s *userAuthRepository) GetRefreshTokenId(ctx context.Context, tHash string) (*int64, error) {
	const op = "repo.GetRefreshTokenId"

	var tokenId int64 
	q := "SELECT id FROM users_auth_info WHERE refresh_token_hash = $1"

	err := s.db.GetContext(ctx, &tokenId, q, tHash)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrEntityNotExists
	}

	if err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}
	return &tokenId, nil
}

func (s *userAuthRepository) UpdateAuthInfo(ctx context.Context, data *entities.UserAuthInfo) error {
	const op = "repo.UpdateAuthInfo"

	updateQ := `UPDATE users_auth_info SET refresh_token_hash=$1, ip_adrress=$2 WHERE guid=$3;`
	_, err := s.db.ExecContext(ctx, updateQ, data.RefreshTokenHash,data.IpAddress, data.UserGuid)
	if err != nil {
		return fmt.Errorf("%s, %w", op, err)
	}
	return nil
}

func (s *userAuthRepository) UpdateRefreshTokenHash(ctx context.Context, data *entities.UserAuthInfo) error {
	const op = "repo.UpdateRefreshTokenHash"

	updateQ := "UPDATE users_auth_info SET refresh_token_hash=$1 WHERE id=$2"
	_, err := s.db.ExecContext(ctx, updateQ, *data.RefreshTokenHash, *data.RefreshId)

	if err != nil {
		return fmt.Errorf("%s, %w", op, err)
	}

	return nil
}

func (s *userAuthRepository) CreateAuthInfo(ctx context.Context, data *entities.UserAuthInfo) (string, error)  {
	const op = "repo.CreateAuthInfo"
	createQ := `INSERT INTO users_auth_info (user_guid,
	ip_address) VALUES ($1, $2) RETURNING users_auth_info.id`

	var recordID uuid.UUID
	err := s.db.QueryRowContext(ctx, createQ, *data.UserGuid, *data.IpAddress).Scan(&recordID)

	if err != nil {
		return "", fmt.Errorf("%s, %w", op, err)
	}
	
	return recordID.String(), nil
}