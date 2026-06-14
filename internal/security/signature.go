package security

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
)

func ComputeCodeChallenge(verifier string) string {
	hash := sha256.Sum256([]byte(verifier))

	return base64.RawURLEncoding.EncodeToString(hash[:])
}

func ValidateCodeVerifier(storedChallenge, receivedVerifier string) bool {
	hash := sha256.Sum256([]byte(receivedVerifier))
	computedChallenge := base64.RawURLEncoding.EncodeToString(hash[:])

	return subtle.ConstantTimeCompare([]byte(computedChallenge), []byte(storedChallenge)) == 1
}
