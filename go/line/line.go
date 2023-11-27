package line

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand"
	"net/http"
	"net/url"
)

type Config struct {
	ClientID     string
	ClientSecret string
}

type IDToken struct {
	Iss      string   `json:"iss"`
	Sub      string   `json:"sub"`
	Aud      string   `json:"aud"`
	Exp      int64    `json:"exp"`
	Iat      int64    `json:"iat"`
	Nonce    string   `json:"nonce"`
	AuthTime int64    `json:"auth_time"`
	Amr      []string `json:"amr"`
	Name     string   `json:"name"`
	Picture  string   `json:"picture"`
	Email    string   `json:"email"`
}

type TokenInfo struct {
	AccessToken  string `json:"access_token"`
	ExpiresIn    int64  `json:"expires_in"`
	IDToken      string `json:"id_token"`
	RefreshToken string `json:"refresh_token"`
	Scope        string `json:"scope"`
	TokenType    string `json:"token_type"`
}

func (c *Config) VerifyIDToken(ctx context.Context, idToken string) (*IDToken, error) {
	return c.verifyIDToken(ctx, idToken)
}

func (c *Config) verifyIDToken(ctx context.Context, idToken string) (*IDToken, error) {
	p := url.Values{}
	p.Add("id_token", idToken)
	p.Add("client_id", c.ClientID)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://api.line.me/oauth2/v2.1/verify", bytes.NewBufferString(p.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	client := http.DefaultClient
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, errors.New("invalid status code")
	}

	var t *IDToken
	if err := json.NewDecoder(resp.Body).Decode(&t); err != nil {
		return nil, err
	}

	return t, nil
}

func (c *Config) WebAuthorization(ctx context.Context, redirectURI string) (string, error) {
	return c.webAuthorization(ctx, redirectURI)
}

func (c *Config) webAuthorization(ctx context.Context, redirectURI string) (string, error) {
	const authorizationBaseURL = "https://access.line.me/oauth2/v2.1/authorize?"
	p := url.Values{}
	p.Add("response_type", "code")
	p.Add("client_id", c.ClientID)
	p.Add("redirect_uri", redirectURI)
	p.Add("state", generateRandomString(32))
	p.Add("scope", "openid profile")

	url := authorizationBaseURL + p.Encode()
	return url, nil
}

const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

func generateRandomString(length int) string {
	b := make([]byte, length)
	for i := range b {
		b[i] = charset[rand.Intn(len(charset))]
	}

	return string(b)
}

func (c *Config) RetiriveLineToken(ctx context.Context, code string, redirectURI string) (string, error) {
	return c.retiriveLineToken(ctx, code, redirectURI)
}

func (c *Config) retiriveLineToken(ctx context.Context, code string, redirectURI string) (string, error) {
	p := url.Values{}
	p.Add("grant_type", "authorization_code")
	p.Add("code", code)
	p.Add("redirect_uri", redirectURI)
	p.Add("client_id", c.ClientID)
	p.Add("client_secret", c.ClientSecret)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://api.line.me/oauth2/v2.1/token", bytes.NewBufferString(p.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	client := http.DefaultClient
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", errors.New("invalid status code")
	}

	var t *TokenInfo
	if err := json.NewDecoder(resp.Body).Decode(&t); err != nil {
		return "", err
	}

	fmt.Printf("TokenInfo: %+v\n", t)
	return t.IDToken, nil
}
