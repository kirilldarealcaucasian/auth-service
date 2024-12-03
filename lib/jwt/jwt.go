package jwtp

import (
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type RefreshTokenClaims struct {
	IsRefresh bool 
	IpAddr string  
	jwt.RegisteredClaims
}

type AccessTokenClaims struct {
	RefreshId int64
	RefreshTokenClaims
}

func accessTokenClaims(guid string, exp *jwt.NumericDate, ipAddr string, refreshId int64) *AccessTokenClaims {
	return &AccessTokenClaims{
		refreshId,
		RefreshTokenClaims{
			false,
			ipAddr,
			jwt.RegisteredClaims{
				ExpiresAt: exp,
				IssuedAt: jwt.NewNumericDate(time.Now()),
				Subject: guid,
			},
		},
	}
}

func refreshTokenClaims(guid string, exp *jwt.NumericDate, ipAddr string, tokenId int64) *RefreshTokenClaims {
	return &RefreshTokenClaims{
			IsRefresh: true,
			IpAddr: ipAddr,
			RegisteredClaims: jwt.RegisteredClaims{
				ExpiresAt: exp,
				IssuedAt: jwt.NewNumericDate(time.Now()),
				Subject: guid,
			},
		}
}

type Claims interface {
	GetAudience() (jwt.ClaimStrings, error)
	GetExpirationTime() (*jwt.NumericDate, error)
	GetNotBefore() (*jwt.NumericDate, error)
	GetIssuedAt() (*jwt.NumericDate, error)
	GetIssuer() (string, error)
	GetSubject() (string, error)
}

// Generates new jwt token
func GenerateToken(guid, ipAddr string, exp time.Duration, isRefresh bool, refreshId *int64) (string, error) {
	const op = "jwt.GenerateToken"

	secret := []byte("secret")
	expTime := jwt.NewNumericDate(time.Now().Add(exp))
	
	var claims Claims

	if isRefresh {
		claims = refreshTokenClaims(guid, expTime, ipAddr, *refreshId)
	} else {
		claims = accessTokenClaims(guid, expTime, ipAddr, *refreshId)
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	tokenStr, err := token.SignedString(secret)

  if err != nil {
      return "", fmt.Errorf("\n%s: %w", op, err)
  }

	return tokenStr, nil
}

func GetToken(claims Claims, tokenStr string) (*jwt.Token, error) {
	const op = "jwt.GetToken"

	token, err := jwt.ParseWithClaims(tokenStr, claims, func(token *jwt.Token) (any, error) {
		return []byte("secret"), nil
	})

	if err != nil {
		return nil, fmt.Errorf("\n%s: %w", op, err)
	}
	return token, nil
}

func GetRefreshTokenClaims(tokenStr string) (*RefreshTokenClaims, error) {
	const op = "jwt.GetRefreshTokenClaims"

	token, err := GetToken(&RefreshTokenClaims{}, tokenStr)

	if err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}

	claims, ok := token.Claims.(*RefreshTokenClaims) 
	if !ok || !token.Valid{
		return nil, fmt.Errorf("%s: %w", op, err)
	}

	if claims.ExpiresAt.Time.Before(time.Now())  {
		return nil, jwt.ErrTokenExpired
	}

	return claims, nil
}

func GetAccessToken(tokenStr string) (*AccessTokenClaims, error){
	const op = "jwt.GetAccessToken"

	token, err := GetToken(&AccessTokenClaims{}, tokenStr)

	claims, ok := token.Claims.(*AccessTokenClaims) 
	if !ok || !token.Valid{
		return nil, fmt.Errorf("%s: %w", op, err)
	}

	if claims.ExpiresAt.Time.After(time.Now())  {
		return nil, jwt.ErrTokenExpired
	}

	return claims, nil
}
