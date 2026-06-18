package password

import (
	"errors"
	"strings"

	"golang.org/x/crypto/bcrypt"
)

const MinLength = 10

var ErrWeakPassword = errors.New("password must be at least 10 characters")

func Hash(plain string) (string, error) {
	plain = strings.TrimSpace(plain)
	if len(plain) < MinLength {
		return "", ErrWeakPassword
	}
	out, err := bcrypt.GenerateFromPassword([]byte(plain), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(out), nil
}

func Verify(hash string, plain string) bool {
	if hash == "" || plain == "" {
		return false
	}
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(plain)) == nil
}
