package security

import (
	"golang.org/x/crypto/bcrypt"
)

const bcryptCost = 12

// HashPassword returns the bcrypt hash of a plaintext password using cost
// factor 12.
//
// Parameters:
//   - password: the plaintext password to hash.
//
// Returns:
//   - string: the bcrypt hash string.
//   - error: nil on success; otherwise an error from the bcrypt library.
func HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), bcryptCost)
	if err != nil {
		return "", err
	}
	return string(bytes), nil
}

// CheckPassword compares a bcrypt hash against a plaintext password in
// constant time.
//
// Parameters:
//   - hash: the stored bcrypt hash string.
//   - password: the plaintext password to compare.
//
// Returns:
//   - bool: true if the password matches the hash.
func CheckPassword(hash, password string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}
