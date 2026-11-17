package authguard

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	pathpkg "path"
	"strings"
)

// FromFile reads the application's dedicated integration configuration. The
// application supplies a live, typed settings reader, never its root API key.
func FromFile(path string, policy func(context.Context) (Policy, error)) (*Guard, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, ErrUnavailable
	}
	defer file.Close()
	var config struct {
		Realm        string            `json:"realm"`
		KeyFile      string            `json:"key_file"`
		PasswordFile string            `json:"password_file"`
		Nodes        map[string]string `json:"nodes"`
	}
	decoder := json.NewDecoder(io.LimitReader(file, 65537))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&config) != nil || decoder.Decode(new(any)) != io.EOF {
		return nil, ErrUnavailable
	}
	key, err := ReadKey(config.KeyFile)
	if err != nil {
		return nil, err
	}
	return New(Config{Realm: config.Realm, Key: key, PasswordFile: config.PasswordFile, Nodes: config.Nodes, Policy: policy})
}

// RequireCreate belongs immediately before the application's actual account
// insert, after that application has verified ownership of this exact mailbox.
func RequireCreate(ctx context.Context, email, password string, verifiedMailbox bool) error {
	a := get(ctx)
	if a == nil {
		return ErrContext
	}
	return a.guard.CheckCreate(ctx, email, password, verifiedMailbox)
}

// CheckInsert is a second fence for repositories shared by public auth and
// trusted admin/CLI operations. Auth routes must always install Attach first;
// an authenticated auth request may only insert its admitted mailbox. This
// deliberately blocks OAuth auto-creation without a verified-mailbox hook.
func CheckInsert(ctx context.Context, email string) error {
	a := get(ctx)
	if a == nil {
		return nil
	}
	a.mu.Lock()
	admitted := a.precreated && a.createSubject == Subject(a.guard.config.Key, email)
	a.mu.Unlock()
	if !admitted {
		return ErrVerifiedEmail
	}
	return nil
}

// ClientIP uses the edge's verified address on admitted requests. Existing
// application trust rules remain the fallback outside the wrapped routes.
func ClientIP(ctx context.Context, fallback string) string {
	if value := TrustedClientIP(ctx); value != "" {
		return value
	}
	return fallback
}

func Matches(adapter string, request *http.Request) bool {
	// Match the canonical path even if the application enables Gin's fixed
	// path/extra slash routing. The body MAC still binds the original raw URI.
	path := strings.TrimSuffix(pathpkg.Clean(request.URL.Path), "/")
	if adapter == "sub2api" {
		if strings.HasPrefix(path, "/api/v1/auth/oauth/") {
			return request.Method == "GET" || request.Method == "POST"
		}
		if request.Method != "POST" {
			return false
		}
		switch path {
		case "/api/v1/auth/login", "/api/v1/auth/register", "/api/v1/auth/send-verify-code", "/api/v1/auth/login/2fa",
			"/api/v1/auth/passkey/login/begin", "/api/v1/auth/passkey/login/finish", "/api/v1/auth/forgot-password",
			"/api/v1/auth/reset-password", "/api/v1/auth/refresh", "/api/v1/auth/validate-promo-code", "/api/v1/auth/validate-invitation-code":
			return true
		}
	} else if adapter == "newapi" {
		if strings.HasPrefix(path, "/api/oauth/") {
			return request.Method == "GET" || request.Method == "POST"
		}
		if request.Method == "GET" {
			return path == "/api/verification" || path == "/api/reset_password"
		}
		if request.Method != "POST" {
			return false
		}
		switch path {
		case "/api/user/login", "/api/user/register", "/api/user/login/2fa", "/api/user/login/verify",
			"/api/user/login/passkey/begin", "/api/user/login/passkey/finish", "/api/user/passkey/login/begin",
			"/api/user/passkey/login/finish", "/api/user/reset", "/api/user/auth/refresh":
			return true
		}
	}
	return false
}
