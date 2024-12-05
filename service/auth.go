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
	"github.com/google/uuid"
)

var ErrNoUserFound = errors.New("user with provided guid wasn't found")
var ErrInvalidTokenClaims = errors.New("invalid refresh token claims")

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
	authInfo, err := as.repo.GetAuthInfoByUserGuid(ctx, authReq.Guid)

	if errors.Is(err, repo.ErrEntityNotExists) { 
		return nil, ErrNoUserFound
	}

	if err != nil {
		as.log.Error(op, slog.String("error", err.Error()))
		return nil, err
	}

	userGuid, _ := uuid.Parse(authReq.Guid)
	createData := entities.UserAuthInfo{
		UserGuid: &userGuid,
		IpAddress: &authReq.IpAddr,
	}

	// store user auth info
	refreshTID, err := as.repo.CreateAuthInfo(ctx, &createData)

	if err != nil {
		as.log.Error(op, slog.String("error", err.Error()))
		return nil, fmt.Errorf("%s: %w", op, err)
	}

	//generate refresh token
	refreshT, err := jwtp.GenerateToken(refreshTID, authReq.IpAddr, as.cfg.Token.RefreshTokenTTL, true)

	if err != nil {
		as.log.Info(op, slog.String("error", err.Error()))
		return nil, fmt.Errorf("%s: %w", op, err)
	}

	// hashify part of token
	refeshTokenHash ,err := crypt.TokenBcrypt(refreshT)

	if err != nil {
		as.log.Info(op, slog.String("error", err.Error()))
		return nil, fmt.Errorf("%s: %w", op, err)
	}

	tokenIdToUuuid, err := uuid.Parse(refreshTID)

	if err != nil {
		as.log.Info(op, slog.String("error", err.Error()))
		return nil, fmt.Errorf("%s: %w", op, err)
	}

	updateData := entities.UserAuthInfo{
		RefreshId: &tokenIdToUuuid,
		RefreshTokenHash: &refeshTokenHash,
	}

	// add token hash to user auth data
	as.repo.UpdateRefreshTokenHash(ctx, &updateData)

	//generate access token
	accessT, err := jwtp.GenerateToken(authInfo.RefreshId.String(), authReq.IpAddr, as.cfg.Token.AccessTokenTTL, false)

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

	claims, err := jwtp.GetAndValidateTokenClaims(token, true)
	
	if errors.Is(err, jwt.ErrTokenExpired) {
		return nil, jwt.ErrTokenExpired
	} else if errors.Is(err, jwt.ErrTokenInvalidSubject) || errors.Is(err, jwt.ErrTokenInvalidClaims) {
		return nil, ErrInvalidTokenClaims
	}

	if err != nil {
		as.log.Error(op, slog.String("error", err.Error()))
		return nil, fmt.Errorf("%s: %w", op, err)
	}
	
	tokenHash, err := as.repo.GetRefreshTokenHash(ctx, claims.Subject)

	if err != nil {
		as.log.Error(op, slog.String("error", err.Error()))
		return nil, err
	}

	if isTokenValid := crypt.VerifyToken(token, tokenHash); !isTokenValid {
		as.log.Error(op, slog.String("err", "token hash and db token hash don't match"))
		return nil, fmt.Errorf("%s: %s", op, "token hash and db token hash don't match")
	}

	//generate new refresh token
	refreshT, err := jwtp.GenerateToken(claims.Subject, claims.IpAddr, as.cfg.Token.RefreshTokenTTL, true)

	if err != nil {
		as.log.Error(op, slog.String("\nfailed to generate new refresh token", err.Error()))
		return nil, fmt.Errorf("%s: %w", op, err)
	}

	newRefreshTHash, err := crypt.TokenBcrypt(refreshT)

	if err != nil {
		as.log.Error(op, slog.String("\nfailed to hashify new refresh token", err.Error()))
		return nil, fmt.Errorf("\n %s: %w", op, err)
	}

	TokenidToUuid, err := uuid.Parse(claims.Subject)

	if err != nil {
		as.log.Error(op, slog.String("\nfailed to hashify new refresh token", err.Error()))
		return nil, fmt.Errorf("\n %s: %w", op, err)
	}

	data := entities.UserAuthInfo{
		RefreshId: &TokenidToUuid,
		RefreshTokenHash: &newRefreshTHash,
	}

	fmt.Printf("DATA: %+v", data)

	err = as.repo.UpdateRefreshTokenHash(ctx, &data)

	if err != nil {
		as.log.Error(op, slog.String("err", err.Error()))
		return nil, fmt.Errorf("\n %s: %w", op, err)
	}

	//generate access token
	accessT, err := jwtp.GenerateToken(claims.Subject, claims.IpAddr, as.cfg.Token.AccessTokenTTL, false)
	if err != nil {
		as.log.Error(op, slog.String("error", err.Error()))
		return nil, err
		}

	return &entities.TokenPair{
		AccessToken: accessT,
		RefreshToken: refreshT,
		}, nil
	}
