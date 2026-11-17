package authguard

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func fixtureGuard(t *testing.T, node http.Handler) (*Guard, []byte, Policy) {
	t.Helper()
	key := bytes.Repeat([]byte{0x31}, 32)
	server := httptest.NewServer(node)
	t.Cleanup(server.Close)
	weak := sha256.Sum256([]byte("fixture-common-choice"))
	file := filepath.Join(t.TempDir(), "weak.sha256")
	if err := os.WriteFile(file, []byte(hex.EncodeToString(weak[:])+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	policy := Policy{Adapter: "sub2api", Revision: "fixture-policy", RegistrationEnabled: true, EmailVerifyEnabled: true, StrictEmail: true, PrecreateRequired: true, AllowedDomains: []string{"example.com", "*.enterprise.example"}, DeniedDomains: []string{"temporary.example"}}
	guard, err := New(Config{Realm: "fixture", Key: key, PasswordFile: file, Nodes: map[string]string{"edge-a": server.URL}, Policy: func(context.Context) (Policy, error) { return policy, nil }})
	if err != nil {
		t.Fatal(err)
	}
	return guard, key, policy
}
func signedRequest(t *testing.T, g *Guard, key []byte, flow int, body string) *http.Request {
	t.Helper()
	request := httptest.NewRequest("POST", "http://app.example/api/v1/auth/register", bytes.NewBufferString(body))
	raw := []byte(request.Method + "\n" + request.URL.RequestURI() + "\n" + body)
	wire := WireContext{Version: 1, Node: "edge-a", Realm: "fixture", Attempt: "0123456789abcdef0123456789abcdef", Policy: "fixture-policy", Flow: flow, Expires: time.Now().Unix() + 15, ClientIP: "198.51.100.3", Subject: strings.Repeat("0", 64), Body: hex.EncodeToString(MAC(key, "body", raw))}
	data, _ := json.Marshal(wire)
	encoded := base64.RawURLEncoding.EncodeToString(data)
	request.Header.Set("X-SCDN-Auth-Request", "v1."+encoded+"."+hex.EncodeToString(MAC(key, "request", []byte(encoded))))
	attached, err := g.Attach(request)
	if err != nil {
		t.Fatal(err)
	}
	return attached
}
func TestCreateRequiresVerifiedOwnershipBeforeRPC(t *testing.T) {
	calls := 0
	g, key, _ := fixtureGuard(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls++; _, _ = w.Write([]byte(`{"reason":"ALLOWED"}`)) }))
	request := signedRequest(t, g, key, 2, `{"email":"person@example.com","password":"long-random-choice"}`)
	if err := g.CheckCreate(request.Context(), "person@example.com", "long-random-choice", false); err != ErrVerifiedEmail {
		t.Fatalf("ownership: %v", err)
	}
	if calls != 0 {
		t.Fatal("unverified address reached edge create gate")
	}
	if err := g.CheckCreate(request.Context(), "person@"+"temporary.example", "long-random-choice", true); err != ErrEmail {
		t.Fatalf("email policy: %v", err)
	}
	if err := g.CheckCreate(request.Context(), "person@example.com", "fixture-common-choice", true); err != ErrWeakPassword {
		t.Fatalf("weak password: %v", err)
	}
	if calls != 0 {
		t.Fatal("invalid choices reached create gate")
	}
}
func TestGateIsAuthenticatedAndOutcomesAreExplicit(t *testing.T) {
	var captured []byte
	var signature string
	g, key, _ := fixtureGuard(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		captured, _ = io.ReadAll(r.Body)
		signature = r.Header.Get("X-SCDN-Auth-Control")
		_, _ = w.Write([]byte(`{"reason":"ALLOWED"}`))
	}))
	request := signedRequest(t, g, key, 2, `{"email":"person@example.com","password":"long-random-choice"}`)
	if value := g.ResponseHeader(request.Context()); value != "" {
		t.Fatal("HTTP response alone invented an outcome")
	}
	if err := g.CheckCreate(request.Context(), "person@example.com", "long-random-choice", true); err != nil {
		t.Fatal(err)
	}
	if signature != hex.EncodeToString(MAC(key, "control", captured)) {
		t.Fatal("invalid control MAC")
	}
	if bytes.Contains(captured, []byte("person@example.com")) || bytes.Contains(captured, []byte("long-random-choice")) {
		t.Fatal("control request leaked credentials or mailbox")
	}
	Report(request.Context(), "registration_complete")
	if value := g.ResponseHeader(request.Context()); value == "" {
		t.Fatal("completed create did not produce feedback")
	}
	if TrustedClientIP(request.Context()) != "198.51.100.3" {
		t.Fatal("trusted address not preserved")
	}
}
func TestRequestBodyAndAuthorityCannotBeReplayedOrChanged(t *testing.T) {
	g, key, _ := fixtureGuard(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	attached := signedRequest(t, g, key, 1, `{"username":"person","password_encrypted":"opaque"}`)
	body, _ := io.ReadAll(attached.Body)
	if string(body) != `{"username":"person","password_encrypted":"opaque"}` {
		t.Fatal("body changed")
	}
	altered := httptest.NewRequest("POST", "http://app.example/api/v1/auth/register", bytes.NewBufferString("changed"))
	altered.Header = attached.Header.Clone()
	if _, err := g.Attach(altered); err != ErrContext {
		t.Fatal("altered body accepted")
	}
	altered.Header.Add("X-SCDN-Auth-Request", altered.Header.Get("X-SCDN-Auth-Request"))
	if _, err := g.Attach(altered); err != ErrContext {
		t.Fatal("duplicate attestation accepted")
	}
	if err := g.CheckCreate(context.Background(), "person@example.com", "long-random-choice", true); err != ErrContext {
		t.Fatal("direct origin creation accepted")
	}
}
func TestFailedAndRedirectedGateCannotCreate(t *testing.T) {
	for _, status := range []int{403, 500, 302} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			g, key, _ := fixtureGuard(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Location", "http://127.0.0.1:1/forbidden")
				w.WriteHeader(status)
			}))
			request := signedRequest(t, g, key, 2, `{"email":"person@example.com","password":"long-random-choice"}`)
			if err := g.CheckCreate(request.Context(), "person@example.com", "long-random-choice", true); err != ErrUnavailable {
				t.Fatalf("gate accepted: %v", err)
			}
		})
	}
}
func TestDomainWildcardsMatchUpstreamAndAliasesRemainExplicit(t *testing.T) {
	if !matchDomain("enterprise.example", "*.enterprise.example", false) || !matchDomain("a.enterprise.example", "*.enterprise.example", false) || matchDomain("enterprise.example.attacker.example", "*.enterprise.example", false) {
		t.Fatal("wildcard differs from Sub2API")
	}
	g, key, _ := fixtureGuard(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(`{"reason":"ALLOWED"}`)) }))
	request := signedRequest(t, g, key, 2, `{"email":"person@example.com","password":"long-random-choice"}`)
	if err := g.CheckCreate(request.Context(), "person+tag@example.com", "long-random-choice", true); err != nil {
		t.Fatal("normal alias rejected without policy")
	}
}
func TestExporterRequiresDedicatedMACAndReturnsNoKeys(t *testing.T) {
	g, key, _ := fixtureGuard(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	request := httptest.NewRequest("GET", "http://app.example/internal/policy", nil)
	response := httptest.NewRecorder()
	g.ExportPolicy(response, request)
	if response.Code != 403 {
		t.Fatal("exported private configuration without MAC")
	}
	data, _ := json.Marshal(time.Now().Unix())
	stamp := string(data)
	nonce := "0123456789abcdef0123456789abcdef"
	binding := stamp + "\n" + nonce + "\nfixture"
	request.Header.Set("X-SCDN-Auth-Time", stamp)
	request.Header.Set("X-SCDN-Auth-Nonce", nonce)
	request.Header.Set("X-SCDN-Auth-Policy", hex.EncodeToString(MAC(key, "policy-request", []byte(binding))))
	response = httptest.NewRecorder()
	g.ExportPolicy(response, request)
	if response.Code != 200 || response.Header().Get("X-SCDN-Auth-Policy") != hex.EncodeToString(MAC(key, "policy-response", append([]byte(binding+"\n"), response.Body.Bytes()...))) {
		t.Fatal("policy export not authenticated")
	}
	if bytes.Contains(response.Body.Bytes(), key) || bytes.Contains(response.Body.Bytes(), []byte("key_file")) {
		t.Fatal("policy export leaked key material")
	}
}

func TestRepositoryFenceRequiresTheAdmittedMailbox(t *testing.T) {
	g, key, _ := fixtureGuard(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(`{"reason":"ALLOWED"}`)) }))
	request := signedRequest(t, g, key, 7, `{"provider":"fixture"}`)
	if CheckInsert(request.Context(), "person@example.com") != ErrVerifiedEmail {
		t.Fatal("OAuth creation reached repository without verified-mailbox admission")
	}
	if err := RequireCreate(request.Context(), "person@example.com", "", true); err != nil {
		t.Fatal(err)
	}
	if err := CheckInsert(request.Context(), "PERSON@example.com"); err != nil {
		t.Fatal(err)
	}
	if err := CheckInsert(request.Context(), "different@example.com"); err != ErrVerifiedEmail {
		t.Fatal("admission moved to a different mailbox")
	}
	if err := CheckInsert(context.Background(), "admin-managed@example.com"); err != nil {
		t.Fatal("trusted admin/CLI boundary was replaced")
	}
	if ClientIP(request.Context(), "untrusted-fallback") != "198.51.100.3" {
		t.Fatal("signed client IP was not used")
	}
}

func TestCreationSuccessNeedsGateAndStalePolicyStopsCreation(t *testing.T) {
	calls := 0
	g, key, policy := fixtureGuard(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls++; _, _ = w.Write([]byte(`{"reason":"ALLOWED"}`)) }))
	request := signedRequest(t, g, key, 2, `{"email":"person@example.com"}`)
	Report(request.Context(), "registration_complete")
	if g.ResponseHeader(request.Context()) != "" {
		t.Fatal("reported creation without checking the edge gate")
	}
	policy.Revision = "changed-policy"
	g.config.Policy = func(context.Context) (Policy, error) { return policy, nil }
	if RequireCreate(request.Context(), "person@example.com", "long-random-choice", true) != ErrUnavailable || calls != 0 {
		t.Fatal("stale admission created an account or called the gate")
	}
}

func TestRouteSelectionLeavesModelAndOrdinaryRequestsAlone(t *testing.T) {
	for _, item := range []struct {
		adapter, method, path string
		wanted                bool
	}{
		{"sub2api", "POST", "/api/v1/auth/register/", true},
		{"sub2api", "GET", "/api/v1/auth/oauth/google/callback?code=fixture", true},
		{"sub2api", "POST", "/api//v1/auth/oauth/google/create-account", true},
		{"sub2api", "POST", "/api/v1/auth/other/../register", true},
		{"sub2api", "GET", "/api/v1/auth/login", false},
		{"newapi", "POST", "/api/user/login/verify", true},
		{"newapi", "GET", "/api/verification?email=person@example.com", true},
		{"newapi", "POST", "/v1/responses", false},
		{"newapi", "POST", "/v1/images/edits", false},
		{"newapi", "GET", "/asset", false},
	} {
		request := httptest.NewRequest(item.method, "http://app.example"+item.path, nil)
		if Matches(item.adapter, request) != item.wanted {
			t.Fatalf("wrong route selection: %s %s", item.method, item.path)
		}
	}
}
