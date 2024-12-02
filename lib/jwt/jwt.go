package jwt

import (
	"crypto/sha512"
	"encoding/json"
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

func refreshTokenClaims(guid string, exp *jwt.NumericDate, ipAddr string) *RefreshTokenClaims {
	return &RefreshTokenClaims{
			true,
			ipAddr,
			jwt.RegisteredClaims{
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

	secret := "abc"
	expTime := jwt.NewNumericDate(time.Now().Add(exp))
	
	var claims Claims

	if isRefresh {
		claims = refreshTokenClaims(guid, expTime, ipAddr)
	} else {
		claims = accessTokenClaims(guid, expTime, ipAddr, *refreshId)
	}

	hash := sha512.New()
	jsonData, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("%s: %w", op, err)
	}

	_, err = hash.Write(jsonData)
	if err != nil {
		return "", err
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	tokenStr, err := token.SignedString([]byte(secret))
    if err != nil {
        return "", fmt.Errorf("%s: %w", op, err)
    }
	return tokenStr, nil
}


func DecodeRefreshToken(token string) (*RefreshTokenClaims, error) {
	const op = "jwt.ValidateRefreshToken"

	claims := RefreshTokenClaims{}
	
	tokenStr, err := jwt.ParseWithClaims(token, &claims, func(token *jwt.Token) (any, error) {
		return []byte("AllYourBase"), nil
	})

	if err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	} else if claims, ok := tokenStr.Claims.(*RefreshTokenClaims); ok {
		return &RefreshTokenClaims{
			claims.IsRefresh,
			claims.IpAddr,
			jwt.RegisteredClaims{
				ExpiresAt: claims.ExpiresAt,
				IssuedAt: claims.IssuedAt,
				Subject: claims.Subject,
			},
		}, nil
	} else {
		return nil, fmt.Errorf("%s: %w", op, err)
	}
}
