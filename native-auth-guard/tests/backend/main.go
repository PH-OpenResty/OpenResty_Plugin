// Isolated fixture: no database, mail delivery, real accounts or provider APIs.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	guard "scdn.local/authguard"
	"strings"
	"sync/atomic"
	"time"
)

type realm struct {
	ID      string       `json:"id"`
	KeyFile string       `json:"key_file"`
	Policy  guard.Policy `json:"policy"`
}
type config struct {
	Address      string  `json:"address"`
	PasswordFile string  `json:"password_file"`
	Control      string  `json:"control"`
	Realms       []realm `json:"realms"`
}

var created, seen, active, maximum atomic.Int64

func main() {
	path := flag.String("config", "", "private fixture config")
	flag.Parse()
	raw, err := os.ReadFile(*path)
	if err != nil {
		panic("fixture config unavailable")
	}
	var cfg config
	if json.Unmarshal(raw, &cfg) != nil {
		panic("fixture config invalid")
	}
	mux := http.NewServeMux()
	for _, item := range cfg.Realms {
		item := item
		key, err := guard.ReadKey(item.KeyFile)
		if err != nil {
			panic("fixture key unavailable")
		}
		g, err := guard.New(guard.Config{Realm: item.ID, Key: key, PasswordFile: cfg.PasswordFile, Nodes: map[string]string{"edge-a": "unix://" + cfg.Control}, Policy: func(_ctx context.Context) (guard.Policy, error) { return item.Policy, nil }})
		if err != nil {
			panic("fixture guard unavailable")
		}
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			seen.Add(1)
			n := active.Add(1)
			defer active.Add(-1)
			for n > maximum.Load() {
				if maximum.CompareAndSwap(maximum.Load(), n) {
					break
				}
			}
			var body struct {
				Email             string `json:"email"`
				Username          string `json:"username"`
				Password          string `json:"password"`
				PasswordEncrypted string `json:"password_encrypted"`
				VerifyCode        string `json:"verify_code"`
				VerificationCode  string `json:"verification_code"`
				Simulate          string `json:"simulate"`
			}
			data, _ := io.ReadAll(r.Body)
			_ = json.Unmarshal(data, &body)
			w.Header().Set("Content-Type", "application/json")
			if body.Simulate == "hold" {
				select {
				case <-time.After(2 * time.Second):
				case <-r.Context().Done():
					return
				}
			}
			if body.Simulate == "timeout" {
				select {
				case <-time.After(20 * time.Second):
				case <-r.Context().Done():
					return
				}
			}
			if body.Simulate == "dependency" {
				guard.Report(r.Context(), "dependency_error")
				w.WriteHeader(500)
				_, _ = w.Write([]byte(`{"error":"dependency unavailable"}`))
				return
			}
			if body.Simulate == "limited" {
				guard.Report(r.Context(), "rate_limited")
				w.WriteHeader(429)
				_, _ = w.Write([]byte(`{"error":"rate limited"}`))
				return
			}
			if body.Simulate == "forged" {
				w.Header().Set("X-SCDN-Auth-Result", "v1.invalid.invalid")
				_, _ = w.Write([]byte(`{"success":false}`))
				return
			}
			if body.Simulate == "factor-invalid" {
				guard.Report(r.Context(), "invalid_second_factor")
				w.WriteHeader(400)
				_, _ = w.Write([]byte(`{"reason":"INVALID_FACTOR"}`))
				return
			}
			if strings.HasSuffix(strings.TrimSuffix(r.URL.Path, "/"), "/register") || body.Simulate == "oauth-create" {
				verified := body.VerifyCode == "verified" || body.VerificationCode == "verified"
				if !verified {
					guard.Report(r.Context(), "invalid_email_code")
					w.WriteHeader(400)
					_, _ = w.Write([]byte(`{"reason":"INVALID_EMAIL_CODE"}`))
					return
				}
				if err := g.CheckCreate(r.Context(), body.Email, body.Password, verified); err != nil {
					w.WriteHeader(403)
					_, _ = w.Write([]byte(`{"reason":"CREATION_DENIED"}`))
					return
				}
				created.Add(1)
				guard.Report(r.Context(), "registration_complete")
				_, _ = w.Write([]byte(`{"success":true}`))
				return
			}
			if strings.HasSuffix(strings.TrimSuffix(r.URL.Path, "/"), "/login") {
				valid := body.Password == "a-unique-fixture-password" || body.Password == "123456" || body.PasswordEncrypted == "fixture-encrypted-valid"
				if !valid {
					guard.Report(r.Context(), "invalid_credentials")
					if item.Policy.Adapter == "sub2api" {
						w.WriteHeader(401)
					}
					_, _ = w.Write([]byte(`{"success":false,"reason":"INVALID_CREDENTIALS"}`))
					return
				}
				if body.Simulate == "factor" {
					guard.Report(r.Context(), "primary_ok_requires_verification")
					_, _ = w.Write([]byte(`{"requires_2fa":true}`))
					return
				}
				guard.Report(r.Context(), "login_complete")
				_, _ = w.Write([]byte(`{"success":true}`))
				return
			}
			guard.Report(r.Context(), "business_rejected")
			_, _ = w.Write([]byte(`{"success":false}`))
		})
		wrapped := g.Wrap(handler, func(*http.Request) bool { return true })
		if item.Policy.Adapter == "sub2api" {
			mux.Handle("/api/v1/auth/", wrapped)
		} else {
			mux.Handle("/api/user/", wrapped)
			mux.Handle("/api/oauth/", wrapped)
			mux.Handle("/api/verification", wrapped)
			mux.Handle("/api/reset_password", wrapped)
		}
		mux.HandleFunc("/__fixture/policy/"+item.ID, g.ExportPolicy)
	}
	mux.HandleFunc("/__fixture/stats", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]int64{"created": created.Load(), "seen": seen.Load(), "active": active.Load(), "maximum": maximum.Load()})
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) { w.Header().Set("ETag", `"fixture-ordinary"`); _, _ = fmt.Fprint(w, "fixture ordinary traffic") })
	if err := http.ListenAndServe(cfg.Address, mux); err != nil {
		panic("fixture listener stopped")
	}
}
