// Package authguard binds explicit application outcomes to an edge attempt.
// It never infers password failure or completed login from HTTP status alone.
package authguard

import (
	"bufio"
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/mail"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

var (
	ErrContext       = errors.New("authentication attempt could not be verified")
	ErrEmail         = errors.New("this email domain is not supported")
	ErrVerifiedEmail = errors.New("verify the email address before creating an account")
	ErrWeakPassword  = errors.New("choose a less common password")
	ErrUnavailable   = errors.New("registration is temporarily unavailable")
)

type Policy struct {
	Adapter             string   `json:"adapter"`
	Revision            string   `json:"revision"`
	RegistrationEnabled bool     `json:"registration_enabled"`
	EmailVerifyEnabled  bool     `json:"email_verify_enabled"`
	AllowedDomains      []string `json:"allowed_domains"`
	DeniedDomains       []string `json:"denied_domains"`
	AliasRestriction    bool     `json:"email_alias_restriction"`
	StrictEmail         bool     `json:"strict_email"`
	PrecreateRequired   bool     `json:"precreate_required"`
}
type Config struct {
	Realm        string
	Key          []byte
	PasswordFile string
	Nodes        map[string]string // Fixed node ID -> HTTPS or unix:// control endpoint.
	Policy       func(context.Context) (Policy, error)
	Client       *http.Client
}
type Guard struct {
	config Config
	weak   map[[32]byte]struct{}
}
type WireContext struct {
	Version  int    `json:"version"`
	Node     string `json:"node"`
	Realm    string `json:"realm"`
	Attempt  string `json:"attempt"`
	Policy   string `json:"policy"`
	Flow     int    `json:"flow"`
	Expires  int64  `json:"expires"`
	Subject  string `json:"subject"`
	Body     string `json:"body"`
	ClientIP string `json:"client_ip"`
}
type contextKey struct{}
type attempt struct {
	guard         *Guard
	wire          WireContext
	mu            sync.Mutex
	result        string
	precreated    bool
	createSubject string
}

func MAC(key []byte, purpose string, data []byte) []byte {
	h := hmac.New(sha256.New, key)
	_, _ = h.Write([]byte(purpose + ":"))
	_, _ = h.Write(data)
	return h.Sum(nil)
}
func Subject(key []byte, email string) string {
	return hex.EncodeToString(MAC(key, "subject", []byte(strings.ToLower(strings.TrimSpace(email)))))
}
func New(config Config) (*Guard, error) {
	if config.Realm == "" || len(config.Key) != 32 || config.Policy == nil || len(config.Nodes) == 0 {
		return nil, ErrUnavailable
	}
	var nonzero byte
	for _, value := range config.Key {
		nonzero |= value
	}
	if nonzero == 0 {
		return nil, ErrUnavailable
	}
	config.Key = bytes.Clone(config.Key)
	client := http.Client{Timeout: 2 * time.Second}
	if config.Client != nil {
		client = *config.Client
	}
	if client.Timeout <= 0 {
		client.Timeout = 2 * time.Second
	}
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	config.Client = &client
	nodes := make(map[string]string, len(config.Nodes))
	for id, endpoint := range config.Nodes {
		nodes[id] = endpoint
	}
	config.Nodes = nodes
	weak := make(map[[32]byte]struct{})
	file, err := os.Open(config.PasswordFile)
	if err != nil {
		return nil, ErrUnavailable
	}
	defer file.Close()
	scan := bufio.NewScanner(io.LimitReader(file, 65000001))
	scan.Buffer(make([]byte, 128), 128)
	for scan.Scan() {
		text := scan.Text()
		if len(text) != 64 || len(weak) >= 1000000 {
			return nil, ErrUnavailable
		}
		raw, err := hex.DecodeString(text)
		if err != nil {
			return nil, ErrUnavailable
		}
		var value [32]byte
		copy(value[:], raw)
		if _, exists := weak[value]; exists {
			return nil, ErrUnavailable
		}
		weak[value] = struct{}{}
	}
	if scan.Err() != nil || len(weak) == 0 {
		return nil, ErrUnavailable
	}
	for _, endpoint := range config.Nodes {
		value, err := url.Parse(endpoint)
		if err != nil || value.User != nil || value.RawQuery != "" || value.Fragment != "" {
			return nil, ErrUnavailable
		}
		if value.Scheme == "unix" {
			if !filepath.IsAbs(value.Path) || value.Host != "" {
				return nil, ErrUnavailable
			}
		} else if value.Scheme != "https" {
			// HTTP is accepted only for an explicitly configured numeric loopback.
			ip := net.ParseIP(value.Hostname())
			if value.Scheme != "http" || ip == nil || !ip.IsLoopback() {
				return nil, ErrUnavailable
			}
		}
	}
	return &Guard{config: config, weak: weak}, nil
}
func ReadKey(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
		return nil, ErrUnavailable
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, ErrUnavailable
	}
	if len(data) == 32 {
		return data, nil
	}
	data = bytes.TrimSuffix(bytes.TrimSuffix(data, []byte("\n")), []byte("\r"))
	if len(data) != 64 {
		return nil, ErrUnavailable
	}
	out := make([]byte, 32)
	if _, err := hex.Decode(out, data); err != nil {
		return nil, ErrUnavailable
	}
	return out, nil
}
func (g *Guard) Weak(password string) bool {
	_, found := g.weak[sha256.Sum256([]byte(password))]
	return found
}
func (g *Guard) Attach(request *http.Request) (*http.Request, error) {
	values := request.Header.Values("X-SCDN-Auth-Request")
	if len(values) != 1 || len(values[0]) > 2048 {
		return nil, ErrContext
	}
	parts := strings.Split(values[0], ".")
	if len(parts) != 3 || parts[0] != "v1" {
		return nil, ErrContext
	}
	supplied, err := hex.DecodeString(parts[2])
	if err != nil || !hmac.Equal(supplied, MAC(g.config.Key, "request", []byte(parts[1]))) {
		return nil, ErrContext
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, ErrContext
	}
	var wire WireContext
	if json.Unmarshal(raw, &wire) != nil || wire.Version != 1 || wire.Realm != g.config.Realm {
		return nil, ErrContext
	}
	now := time.Now().Unix()
	if wire.Expires < now || wire.Expires > now+45 || wire.Flow < 1 || wire.Flow > 8 {
		return nil, ErrContext
	}
	id, err := hex.DecodeString(wire.Attempt)
	if err != nil || len(id) != 16 {
		return nil, ErrContext
	}
	if _, known := g.config.Nodes[wire.Node]; !known {
		return nil, ErrContext
	}
	if net.ParseIP(wire.ClientIP) == nil {
		return nil, ErrContext
	}
	subject, err := hex.DecodeString(wire.Subject)
	if err != nil || len(subject) != 32 || wire.Policy == "" || len(wire.Policy) > 96 {
		return nil, ErrContext
	}
	body, err := io.ReadAll(io.LimitReader(request.Body, 16385))
	if err != nil || len(body) > 16384 {
		return nil, ErrContext
	}
	request.Body = io.NopCloser(bytes.NewReader(body))
	input := make([]byte, 0, len(body)+len(request.URL.RequestURI())+len(request.Method)+2)
	input = append(input, request.Method...)
	input = append(input, '\n')
	input = append(input, request.URL.RequestURI()...)
	input = append(input, '\n')
	input = append(input, body...)
	bodyMAC, err := hex.DecodeString(wire.Body)
	if err != nil || !hmac.Equal(bodyMAC, MAC(g.config.Key, "body", input)) {
		return nil, ErrContext
	}
	a := &attempt{guard: g, wire: wire}
	return request.WithContext(context.WithValue(request.Context(), contextKey{}, a)), nil
}
func get(ctx context.Context) *attempt { value, _ := ctx.Value(contextKey{}).(*attempt); return value }
func Report(ctx context.Context, code string) {
	a := get(ctx)
	if a == nil {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if code == "login_complete" && a.precreated {
		code = "registration_complete"
	}
	switch code {
	case "invalid_credentials", "primary_ok_requires_verification", "login_complete", "invalid_second_factor", "captcha_failed", "invalid_email_code", "registration_complete", "weak_password_rejected", "email_policy_rejected", "rate_limited", "dependency_error", "business_rejected":
		a.result = code
	}
}
func TrustedClientIP(ctx context.Context) string {
	if a := get(ctx); a != nil {
		return a.wire.ClientIP
	}
	return ""
}
func (g *Guard) ResponseHeader(ctx context.Context) string {
	a := get(ctx)
	if a == nil || a.guard != g {
		return ""
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.result == "" {
		return ""
	}
	if a.result == "registration_complete" && !a.precreated {
		return ""
	}
	raw, _ := json.Marshal(map[string]any{"attempt": a.wire.Attempt, "code": a.result})
	encoded := base64.RawURLEncoding.EncodeToString(raw)
	return "v1." + encoded + "." + hex.EncodeToString(MAC(g.config.Key, "response", []byte(encoded)))
}
func matchDomain(domain, pattern string, subdomains bool) bool {
	if strings.HasPrefix(pattern, "*.") {
		pattern = strings.TrimPrefix(pattern, "*.")
		subdomains = true
	}
	return domain == pattern || (subdomains && strings.HasSuffix(domain, "."+pattern))
}
func normalizePolicy(policy Policy) Policy {
	normalize := func(values []string) []string {
		seen := map[string]bool{}
		out := []string{}
		for _, value := range values {
			value = strings.ToLower(strings.TrimSpace(strings.TrimPrefix(value, "@")))
			if value != "" && !seen[value] {
				seen[value] = true
				out = append(out, value)
			}
		}
		sort.Strings(out)
		return out
	}
	policy.AllowedDomains = normalize(policy.AllowedDomains)
	policy.DeniedDomains = normalize(policy.DeniedDomains)
	if policy.Revision == "" {
		raw, _ := json.Marshal(policy)
		digest := sha256.Sum256(raw)
		policy.Revision = hex.EncodeToString(digest[:])
	}
	return policy
}
func (g *Guard) CurrentPolicy(ctx context.Context) (Policy, error) {
	value, err := g.config.Policy(ctx)
	if err != nil {
		return Policy{}, ErrUnavailable
	}
	if value.Adapter != "sub2api" && value.Adapter != "newapi" {
		return Policy{}, ErrUnavailable
	}
	return normalizePolicy(value), nil
}
func (g *Guard) CheckCreate(ctx context.Context, email, password string, verifiedMailbox bool) error {
	a := get(ctx)
	if a == nil || a.guard != g {
		return ErrContext
	}
	if a.wire.Flow != 2 && a.wire.Flow != 7 {
		return ErrContext
	}
	policy, err := g.CurrentPolicy(ctx)
	if err != nil || policy.Revision != a.wire.Policy || !policy.RegistrationEnabled || !policy.EmailVerifyEnabled || !policy.StrictEmail || !policy.PrecreateRequired {
		return ErrUnavailable
	}
	if !verifiedMailbox {
		return ErrVerifiedEmail
	}
	normalized := strings.ToLower(strings.TrimSpace(email))
	local, domain, found := strings.Cut(normalized, "@")
	address, parseErr := mail.ParseAddress(normalized)
	if parseErr != nil || address.Name != "" || address.Address != normalized {
		return ErrEmail
	}
	if policy.Adapter == "sub2api" {
		domain = strings.TrimRight(domain, ".")
	}
	if !found || local == "" || domain == "" || strings.Contains(domain, "@") {
		return ErrEmail
	}
	for _, value := range policy.DeniedDomains {
		if matchDomain(domain, value, true) {
			Report(ctx, "email_policy_rejected")
			return ErrEmail
		}
	}
	allowed := false
	for _, value := range policy.AllowedDomains {
		if matchDomain(domain, value, false) {
			allowed = true
			break
		}
	}
	if !allowed || (policy.AliasRestriction && strings.ContainsAny(local, "+.")) {
		Report(ctx, "email_policy_rejected")
		return ErrEmail
	}
	if password != "" && g.Weak(password) {
		Report(ctx, "weak_password_rejected")
		return ErrWeakPassword
	}
	subject := Subject(g.config.Key, normalized)
	body, _ := json.Marshal(map[string]any{"realm": g.config.Realm, "operation": "pre-create", "attempt": a.wire.Attempt, "subject": subject, "domain": domain, "verified": true, "weak": false, "time": time.Now().Unix()})
	client := g.config.Client
	endpoint := g.config.Nodes[a.wire.Node]
	parsed, _ := url.Parse(endpoint)
	if parsed.Scheme == "unix" {
		transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var dialer net.Dialer
			return dialer.DialContext(ctx, "unix", parsed.Path)
		}}
		defer transport.CloseIdleConnections()
		client = &http.Client{Transport: transport, Timeout: 2 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
		endpoint = "http://unix/"
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return ErrUnavailable
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-SCDN-Auth-Control", hex.EncodeToString(MAC(g.config.Key, "control", body)))
	response, err := client.Do(request)
	if err != nil {
		return ErrUnavailable
	}
	defer response.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(response.Body, 4097))
	if err != nil || len(raw) > 4096 || response.StatusCode != 200 {
		return ErrUnavailable
	}
	var result struct {
		Reason string `json:"reason"`
	}
	if json.Unmarshal(raw, &result) != nil || result.Reason != "ALLOWED" {
		return ErrUnavailable
	}
	a.mu.Lock()
	a.precreated = true
	a.createSubject = subject
	a.mu.Unlock()
	return nil
}

// ExportPolicy exposes only the typed policy, never application admin options.
// Requests and response bytes use dedicated purpose labels with the realm key.
func (g *Guard) ExportPolicy(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", 405)
		return
	}
	stamp := r.Header.Get("X-SCDN-Auth-Time")
	when, err := strconv.ParseInt(stamp, 10, 64)
	nonce := r.Header.Get("X-SCDN-Auth-Nonce")
	nonceBytes, nonceErr := hex.DecodeString(nonce)
	if err != nil || nonceErr != nil || len(nonceBytes) != 16 || when < time.Now().Unix()-30 || when > time.Now().Unix()+30 {
		http.Error(w, "forbidden", 403)
		return
	}
	binding := stamp + "\n" + nonce + "\n" + g.config.Realm
	signature, err := hex.DecodeString(r.Header.Get("X-SCDN-Auth-Policy"))
	if err != nil || !hmac.Equal(signature, MAC(g.config.Key, "policy-request", []byte(binding))) {
		http.Error(w, "forbidden", 403)
		return
	}
	policy, err := g.CurrentPolicy(r.Context())
	if err != nil {
		http.Error(w, "unavailable", 503)
		return
	}
	raw, _ := json.Marshal(policy)
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-SCDN-Auth-Policy", hex.EncodeToString(MAC(g.config.Key, "policy-response", append([]byte(binding+"\n"), raw...))))
	_, _ = w.Write(raw)
}

type responseWriter struct {
	http.ResponseWriter
	guard *Guard
	ctx   context.Context
	sent  bool
}

func (w *responseWriter) prepare() {
	if !w.sent {
		w.sent = true
		if value := w.guard.ResponseHeader(w.ctx); value != "" {
			w.Header().Set("X-SCDN-Auth-Result", value)
		}
	}
}
func (w *responseWriter) WriteHeader(status int) { w.prepare(); w.ResponseWriter.WriteHeader(status) }
func (w *responseWriter) Write(data []byte) (int, error) {
	w.prepare()
	return w.ResponseWriter.Write(data)
}
func (g *Guard) Wrap(next http.Handler, match func(*http.Request) bool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !match(r) {
			next.ServeHTTP(w, r)
			return
		}
		attached, err := g.Attach(r)
		if err != nil {
			w.Header().Set("Cache-Control", "no-store")
			http.Error(w, ErrContext.Error(), 403)
			return
		}
		writer := &responseWriter{ResponseWriter: w, guard: g, ctx: attached.Context()}
		next.ServeHTTP(writer, attached)
		writer.prepare()
	})
}
