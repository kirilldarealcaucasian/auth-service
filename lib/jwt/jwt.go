package jwtp

import (
	"fmt"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type CustomTokenClaims struct {
	IsRefresh bool
	IpAddr    string
	jwt.RegisteredClaims
}

type Claims interface {
	GetAudience() (jwt.ClaimStrings, error)
	GetExpirationTime() (*jwt.NumericDate, error)
	GetNotBefore() (*jwt.NumericDate, error)
	GetIssuedAt() (*jwt.NumericDate, error)
	GetIssuer() (string, error)
	GetSubject() (string, error)
}

func (c *CustomTokenClaims) ValidateTokenClaims(refresh bool) error {
	if refresh && !c.IsRefresh {
			return jwt.ErrTokenInvalidClaims
	} else if !refresh && c.IsRefresh {
			return jwt.ErrTokenInvalidClaims
	}

	if c.Subject == "" {
		return jwt.ErrTokenInvalidSubject
	}

	if c.ExpiresAt.Time.Before(time.Now()) {
		return jwt.ErrTokenExpired
	}

	return nil
}

func tokenClaims(tokenId string, exp *jwt.NumericDate, ipAddr string, isRefresh bool) Claims {
	return &CustomTokenClaims{
		IsRefresh: isRefresh,
		IpAddr:    ipAddr,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: exp,
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Subject:   tokenId,
		},
	}
}

// Generates new jwt token
func GenerateToken(tokenId, ipAddr string, exp time.Duration, isRefresh bool) (string, error) {
	const op = "jwt.GenerateToken"

	secret := []byte(os.Getenv("SECRET"))
	expTime := jwt.NewNumericDate(time.Now().Add(exp))
	var claims Claims

	if isRefresh {
		claims = tokenClaims(tokenId, expTime, ipAddr, true)
	} else {
		claims = tokenClaims(tokenId, expTime, ipAddr, false)
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenStr, err := token.SignedString(secret)

	if err != nil {
		return "", fmt.Errorf("\n%s: %w", op, err)
	}

	return tokenStr, nil
}

func GetToken(claims Claims, tokenStr string) (*jwt.Token, error) {
	token, err := jwt.ParseWithClaims(tokenStr, claims, func(token *jwt.Token) (any, error) {
		return []byte(os.Getenv("SECRET")), nil
	})

	if err != nil {
		return nil, err
	}
	return token, nil
}

func GetAndValidateTokenClaims(tokenStr string, isRefresh bool) (*CustomTokenClaims, error) {
	const op = "jwt.GetTokenClaims"

	token, err := GetToken(&CustomTokenClaims{}, tokenStr)

	if err != nil {
		return nil, err
	}

	claims, ok := token.Claims.(*CustomTokenClaims)

	if !ok || !token.Valid {
		return nil, fmt.Errorf("%s: %w", op, err)
	}

	err = claims.ValidateTokenClaims(isRefresh)

	return claims, err
}
