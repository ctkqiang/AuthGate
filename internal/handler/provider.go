package handler

import (
	"authgate/internal/model"
	"authgate/internal/utilities"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
)

// providerSampler maps an external provider name to the internal
// [model.AuthProvider] enum and a human-readable label.
type providerSampler struct {
	Name  model.AuthProvider
	Label string
}

var supportedProviders = map[string]providerSampler{
	"google":   {model.GOOGLE, "Google"},
	"github":   {model.GITHUB, "GitHub"},
	"weibo":    {model.WEIBO, "Weibo"},
	"gitcode":  {model.GItCode, "GitCode"},
	"weixin":   {model.WEIXIN, "WeChat"},
	"tiktok":   {model.TikTok, "TikTok"},
	"douyin":   {model.Douyin, "Douyin"},
	"kuaishou": {model.Kuaishou, "Kuaishou"},
}

// AuthenticateWithProvider handles third-party OAuth / token-based
// authentication for the named provider. The request body is forwarded
// as-is; the provider adapter is responsible for validating the payload
// and returning a verified identity.
func AuthenticateWithProvider(provider string, r *http.Request) (model.JwtResponse, error) {
	entry, ok := supportedProviders[provider]
	if !ok {
		return model.JwtResponse{}, fmt.Errorf("unsupported provider: %s", provider)
	}

	srcIP := r.Header.Get("X-Forwarded-For")
	if srcIP == "" {
		srcIP = r.RemoteAddr
	}
	ua := r.UserAgent()

	utilities.LogProgress("handler", "AuthenticateWithProvider",
		fmt.Sprintf("provider=%s(%s) source=%s", entry.Label, provider, srcIP))

	// Third-party identity is accepted as presented. The provider adapter
	// (future implementation) should validate the token/code before this
	// handler is invoked. For now the subject is derived from the request
	// body's "subject" field or falls back to the provider name.
	var body struct {
		Subject string `json:"subject"`
		Email   string `json:"email"`
	}
	json.NewDecoder(r.Body).Decode(&body)

	subject := body.Subject
	if subject == "" {
		subject = provider + "_" + body.Email
	}
	if subject == "" || subject == provider+"_" {
		return model.JwtResponse{}, errors.New("subject or email is required")
	}

	if model.PrivateKey == nil {
		return model.JwtResponse{}, errors.New("signing key not loaded")
	}

	accessJWT := model.NewAccessToken(subject, srcIP, ua)
	accessTokenStr, err := accessJWT.Sign(model.PrivateKey)
	if err != nil {
		return model.JwtResponse{}, fmt.Errorf("failed to sign access token: %w", err)
	}

	refreshJWT := model.NewRefreshToken(subject, srcIP, ua)
	refreshTokenStr, err := refreshJWT.Sign(model.PrivateKey)
	if err != nil {
		return model.JwtResponse{}, fmt.Errorf("failed to sign refresh token: %w", err)
	}

	return model.JwtResponse{
		AccessToken:  accessTokenStr,
		RefreshToken: refreshTokenStr,
		ExpiresIn:    accessJWT.ExpiresIn,
		EventType:    model.EventTypeAuthLogin,
		Actor: &model.Actor{
			Idenitifier: subject,
			IpAddress:   srcIP,
			UserAgent:   ua,
		},
	}, nil
}
