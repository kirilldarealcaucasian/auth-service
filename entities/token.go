package entities

import (
	"github.com/google/uuid"
)

type User struct {
	ID uuid.UUID `db:"id"`
	Email string `db:"email"`
}

type UserAuthInfo struct {
	UserGuid         *uuid.UUID `db:"user_guid"`
	RefreshTokenHash *string `db:"refresh_token_hash"`
	IpAddress        *string `db:"ip_address"`
}

type UserWithAuthCreds struct {
	User
	UserAuthInfo
}

type AuthenticateRequest struct {
	Guid string
	IpAddr string
}

type TokenPair struct {
	AccessToken string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}