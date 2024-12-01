package service

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"testovoe_medods/config"
	"testovoe_medods/entities"
	crypt "testovoe_medods/lib/bcrypt"
	"testovoe_medods/lib/jwt"
	repo "testovoe_medods/repository"
)

var ErrNoUserFound = errors.New("user with provided guid wasn't found")

type AuthService interface {
	ReleaseTokens(ctx context.Context, authReq *entities.AuthenticateRequest) (*entities.TokenPair, error)
	RefreshToken(ctx context.Context, user_guid, refresh_token string) *entities.TokenPair
}

type userAuthService struct {
	cfg  *config.Config
	log  *slog.Logger
	repo repo.AuthRepository
}

func NewUserAuthService(log *slog.Logger, cfg *config.Config, repo repo.AuthRepository) AuthService  {
	return &userAuthService{
		cfg:  cfg,
		log:  log,
		repo: repo,
	}
}

// creates a pair of access, refresh tokens
func (as *userAuthService) ReleaseTokens(ctx context.Context, authReq *entities.AuthenticateRequest) (*entities.TokenPair, error) {
	const op = "service.ReleaseTokens"
	as.log.Info(op, slog.String("msg", "Release tokens"))


	//check if user with guid exists
	authInfo, err := as.repo.GetAuthInfo(ctx, authReq.Guid)
	fmt.Printf("RES: %+v", authInfo)

	if errors.Is(err, repo.ErrEntityNotExists) { 
		return nil, ErrNoUserFound
	}

	if err != nil {
		as.log.Info(op, slog.String("error", err.Error()))
		return nil, fmt.Errorf("%s: %w", op, err)
	}

	//generate refresh token
	refreshT, err := jwt.GenerateToken(authReq.Guid, authReq.IpAddr, as.cfg.Token.RefreshTokenTTL, true, nil)

	if err != nil {
		as.log.Error(op, slog.String("error", err.Error()))
		return nil, err
	}

	//encrypt part of refresh token
	bcryptHash, err := crypt.TokenBcrypt(refreshT)
	if err != nil {
		as.log.Error(op, slog.String("\nfailed to hashify refresh token", err.Error()))
		return nil, err
	}

	data := entities.UserAuthInfo{
		UserGuid: &authInfo.ID,
		RefreshTokenHash: &bcryptHash,
		IpAddress: authInfo.IpAddress,
	}

	// store hashed refresh token & other info
	refreshTID, err := as.repo.CreateAuthInfo(ctx, &data)
	if err != nil {
		as.log.Error(op, slog.String("error", err.Error()))
		return nil, fmt.Errorf("%s: %w", op, err)
	}

	//generate access token
	accessT, err := jwt.GenerateToken(authReq.Guid, authReq.IpAddr, as.cfg.Token.RefreshTokenTTL, false, &refreshTID)
	if err != nil {
		as.log.Error("failed to generate refresh token", slog.String("error", err.Error()))
		return nil, err
		}

	return &entities.TokenPair{
		AccessToken: accessT,
		RefreshToken: refreshT,
		}, nil
	}

func (as *userAuthService) RefreshToken(ctx context.Context, user_guid, refresh_token string) *entities.TokenPair {
	return &entities.TokenPair{}
}
