package service

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"testovoe_medods/config"
	"testovoe_medods/entities"
	crypt "testovoe_medods/lib/bcrypt"
	jwtp "testovoe_medods/lib/jwt"
	repo "testovoe_medods/repository"

	"github.com/golang-jwt/jwt/v5"
)

var ErrNoUserFound = errors.New("user with provided guid wasn't found")

type AuthService interface {
	ReleaseTokens(ctx context.Context, authReq *entities.AuthenticateRequest) (*entities.TokenPair, error)
	RefreshToken(ctx context.Context, token string) (*entities.TokenPair, error)
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

	if errors.Is(err, repo.ErrEntityNotExists) { 
		return nil, ErrNoUserFound
	}

	if err != nil {
		as.log.Info(op, slog.String("error", err.Error()))
		return nil, fmt.Errorf("%s: %w", op, err)
	}

	//generate refresh token
	refreshT, err := jwtp.GenerateToken(authReq.Guid, authReq.IpAddr, as.cfg.Token.RefreshTokenTTL, true, nil)

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
		IpAddress: &authReq.IpAddr,
	}

	// store hashed refresh token & other info
	refreshTID, err := as.repo.CreateAuthInfo(ctx, &data)
	if err != nil {
		as.log.Error(op, slog.String("error", err.Error()))
		return nil, fmt.Errorf("%s: %w", op, err)
	}

	//generate access token
	accessT, err := jwtp.GenerateToken(authReq.Guid, authReq.IpAddr, as.cfg.Token.AccessTokenTTL, false, &refreshTID)
	if err != nil {
		as.log.Error(op, slog.String("error", err.Error()))
		return nil, err
		}

	return &entities.TokenPair{
		AccessToken: accessT,
		RefreshToken: refreshT,
		}, nil
	}

func (as *userAuthService) RefreshToken(ctx context.Context, token string) (*entities.TokenPair, error) {
	const op = "service.RefreshToken"
	as.log.Info(op, slog.String("msg", "Refreshing tokens"))

	claims, err := jwtp.GetRefreshTokenClaims(token)
	if err != nil {
		if errors.Is(err, jwt.ErrTokenExpired) || errors.Is(err, jwt.ErrTokenMalformed) {
			return nil, err
	}
		as.log.Error(op, slog.String("error", err.Error()))
		return nil, fmt.Errorf("%s: %w", op, err)
	}
	
	tHash, err := crypt.TokenBcrypt(token)

	// crypt.VerifyToken()

	if err != nil {
		as.log.Error(op, slog.String("\nfailed to hashify refresh token", err.Error()))
		return nil, fmt.Errorf("%s: %w", op, err)
	}

	authInfo, err := as.repo.GetAuthInfoByRefreshTokenHash(ctx, tHash)

	if err != nil {
		as.log.Error(op, slog.String("\nfailed to get auth information by refresh token", err.Error()))
		return nil, fmt.Errorf("%s: %w", op, err)
	}

	if claims.IpAddr != *authInfo.IpAddress {
		as.log.Info("ОТОСЛАТЬ ПИСЬМО НА ПОЧТУ")
	}

	//generate new refresh token
	refreshT, err := jwtp.GenerateToken(claims.Subject, *authInfo.IpAddress, as.cfg.Token.RefreshTokenTTL, true, nil)

	if err != nil {
		as.log.Error(op, slog.String("\nfailed to generate new refresh token", err.Error()))
		return nil, fmt.Errorf("%s: %w", op, err)
	}

	newRefreshTHash, err := crypt.TokenBcrypt(refreshT)

	if err != nil {
		as.log.Error(op, slog.String("\nfailed to hashify new refresh token", err.Error()))
		return nil, fmt.Errorf("\n %s: %w", op, err)
	}

	updateInfo := entities.UserAuthInfo{
		UserGuid: authInfo.UserGuid,
		RefreshTokenHash: &newRefreshTHash,
		IpAddress: authInfo.IpAddress,
	}

	err = as.repo.UpdateAuthInfo(ctx, &updateInfo)

	if err != nil {
		as.log.Error(op, slog.String("\nfailed to update authentication data", err.Error()))
		return nil, fmt.Errorf("\n %s: %w", op, err)
	}

	refreshTokenId, err := as.repo.GetRefreshTokenId(ctx, newRefreshTHash)
	if err != nil {
			as.log.Error(op, slog.String("\nfailed to retrieve token hash", err.Error()))
			return nil, fmt.Errorf("%s: %w", op, err)
	}

	//generate access token
	accessT, err := jwtp.GenerateToken(authInfo.UserGuid.String(), *authInfo.IpAddress, as.cfg.Token.AccessTokenTTL, false, refreshTokenId)
	if err != nil {
		as.log.Error(op, slog.String("error", err.Error()))
		return nil, err
		}

	return &entities.TokenPair{
		AccessToken: accessT,
		RefreshToken: refreshT,
		}, nil
}
