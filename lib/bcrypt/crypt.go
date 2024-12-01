package crypt

import (
	"crypto/sha512"
	"encoding/base64"
	"fmt"

	"golang.org/x/crypto/bcrypt"
)


func EncryptTokenPayload(claimsEncoded []byte) (string, error) {
	const op = "crypt.EncryptTokenPayload"
	hash := sha512.New()

	_, err := hash.Write(claimsEncoded)
	if err != nil {
		return "", fmt.Errorf("%s: %w", op, err)
	}

	return base64.StdEncoding.EncodeToString(hash.Sum(nil)), nil
}

func CompareHash(hash1 []byte, hash2 []byte) bool {
	err := bcrypt.CompareHashAndPassword(hash1, hash2)
	return err == nil
}

func TokenBcrypt(tokenStr string) (string, error) {
	const op = "crypt.BcryptTokenPayload"
	hash, err := bcrypt.GenerateFromPassword([]byte(tokenStr[:72]), bcrypt.DefaultCost)

	if err != nil {
		return "", fmt.Errorf("%s: %w", op, err)
	}
	hashToStr := string(hash)
	return hashToStr, nil
}
