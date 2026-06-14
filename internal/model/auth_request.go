package model

type EmailPasswordAuthRequest struct {
	Username       string  `json:"username"`
	Password       string  `json:"password"`
	PhoneNumber    *string `json:"phone_number"`
	CodeChallenger string  `json:"code_challenger"`
}
