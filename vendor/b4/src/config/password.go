package config

import (
	"strings"

	"golang.org/x/crypto/bcrypt"
)

const webPasswordCost = 12

func HashPassword(plain string) (string, error) {
	h, err := bcrypt.GenerateFromPassword([]byte(plain), webPasswordCost)
	if err != nil {
		return "", err
	}
	return string(h), nil
}

func CheckPassword(hash, plain string) bool {
	if hash == "" {
		return false
	}
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(plain)) == nil
}

func IsHashedPassword(s string) bool {
	return strings.HasPrefix(s, "$2a$") ||
		strings.HasPrefix(s, "$2b$") ||
		strings.HasPrefix(s, "$2y$")
}
