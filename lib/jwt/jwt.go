package jwt

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

	secret := []byte("secret")
	expTime := jwt.NewNumericDate(time.Now().Add(exp))
	
	var claims Claims

	if isRefresh {
		claims = refreshTokenClaims(guid, expTime, ipAddr)
	} else {
		claims = accessTokenClaims(guid, expTime, ipAddr, *refreshId)
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	tokenStr, err := token.SignedString(secret)
  if err != nil {
      return "", fmt.Errorf("\n%s: %w", op, err)
  }

	t, err := jwt.ParseWithClaims(tokenStr, &RefreshTokenClaims{}, func(token *jwt.Token) (any, error) {
        return secret, nil
    })
	
	if err != nil {
		return "", fmt.Errorf("\n%s: %w", op, err)
	}

	fmt.Printf("CHECKED TOKEN AFTER GENERATION: %+v", &t)

	return tokenStr, nil
}

func GetToken(claims Claims, tokenStr string) (*jwt.Token, error) {
	const op = "jwt.GetToken"
	secret := []byte("secret")
	token, err := jwt.ParseWithClaims(tokenStr, claims, func(tokenStr *jwt.Token) (any, error) {
		return secret, nil
	})
	if err != nil {
		return nil, fmt.Errorf("\n%s: %w", op, err)
	}
	return token, nil
}

func DecodeRefreshToken(tokenStr string) (*RefreshTokenClaims, error) {
	const op = "jwt.DecodeRefreshToken"

	_, err := jwt.ParseWithClaims(tokenStr, &RefreshTokenClaims{}, func(token *jwt.Token) (interface{}, error) {
        return []byte("secret"), nil
    })

	if err != nil {
		return nil, fmt.Errorf("\n %s: %w", op, err)
	}
	
	// claims, ok := jwtToken.Claims.(RefreshTokenClaims) 
	
	// if ok && jwtToken.Valid {
	// 	return &RefreshTokenClaims{
	// 			claims.IsRefresh,
	// 			claims.IpAddr,
	// 			jwt.RegisteredClaims{
	// 				ExpiresAt: claims.ExpiresAt,
	// 				IssuedAt: claims.IssuedAt,
	// 				Subject: claims.Subject,
	// 			},
	// 		}, nil
	// }
	// return nil, fmt.Errorf("\n%s: %w", op, err)
	return &RefreshTokenClaims{}, nil
}

// func DecodeAccessToken(token string) (*AccessTokenClaims, error){
// 	const op = "jwt.DecodeAccessToken"

// 	var claims AccessTokenClaims

// 	tokenStr, err := GetToken(claims, token)
// 	if err != nil {
// 		return nil, fmt.Errorf("\n%s: %w", op, err)
// 	} else if claims, ok := tokenStr.Claims.(*AccessTokenClaims); ok && tokenStr.Valid {
// 		return &AccessTokenClaims{
// 			claims.RefreshId,
// 			RefreshTokenClaims{
// 			claims.IsRefresh,
// 			claims.IpAddr,
// 			jwt.RegisteredClaims{
// 				ExpiresAt: claims.ExpiresAt,
// 				IssuedAt: claims.IssuedAt,
// 				Subject: claims.Subject,
// 			},
// 		},
// 		}, nil
// 	} else {
// 		return nil, fmt.Errorf("\n%s: %w", op, err)
// 	}
// }
