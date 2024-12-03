package crypt

import (
	"fmt"

	"golang.org/x/crypto/bcrypt"
)


func TokenBcrypt(tokenStr string) (string, error) {
	const op = "crypt.BcryptTokenPayload"
	hash, err := bcrypt.GenerateFromPassword([]byte(tokenStr[:72]), bcrypt.DefaultCost)

	if err != nil {
		return "", fmt.Errorf("%s: %w", op, err)
	}
	hashToStr := string(hash)
	return hashToStr, nil
}

func VerifyToken(token, hash string) bool {
	 err := bcrypt.CompareHashAndPassword([]byte(token[:72]), []byte(hash))
    return err == nil
}
