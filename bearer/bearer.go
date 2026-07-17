// Package bearer implements the platform's bearer-token authentication:
// named keys on the server side (HTTP middleware; grpcreef reuses the
// Verifier), a token-injecting RoundTripper on the client side.
//
// Secret hygiene: token values never appear in errors, logs, or responses —
// only key names do. Comparison is constant-time over sha256 digests, so
// neither timing nor token length leaks.
package bearer

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync/atomic"
	"unicode"

	"github.com/yaop-labs/reef/credential"
)

// Warning is a non-fatal validation finding (e.g. token file permissions).
type Warning string

const MaxTokenBytes = 8 << 10

// Key is one named credential accepted by a server. Exactly one of Token,
// TokenFile, TokenEnv must be set.
type Key struct {
	Name      string `yaml:"name"`
	Token     string `yaml:"token"`
	TokenFile string `yaml:"token_file"`
	TokenEnv  string `yaml:"token_env"`
}

// ServerConfig is the `auth:` block of a receiver. An empty Bearer list
// disables auth (dev mode).
type ServerConfig struct {
	Bearer []Key `yaml:"bearer"`
}

// ClientConfig is the `auth:` block of an exporter. All fields empty
// disables token injection. At most one source may be set.
type ClientConfig struct {
	Token     string `yaml:"token"`
	TokenFile string `yaml:"token_file"`
	TokenEnv  string `yaml:"token_env"`
}

// Validate checks the server block. nil-safe.
func (c *ServerConfig) Validate() ([]Warning, error) {
	_, warns, err := compileServer(c)
	return warns, err
}

// Validate checks the client block. nil-safe.
func (c *ClientConfig) Validate() ([]Warning, error) {
	if c == nil {
		return nil, nil
	}
	if c.Token == "" && c.TokenFile == "" && c.TokenEnv == "" {
		return nil, nil
	}
	if _, err := resolve(c.Token, c.TokenFile, c.TokenEnv); err != nil {
		return nil, fmt.Errorf("bearer: client token: %w", err)
	}
	return clientWarnings(c), nil
}

// Verifier holds the accepted keys compiled for verification. The zero value
// (or one built from an empty config) reports Enabled() == false.
type Verifier struct {
	state   atomic.Pointer[verifierState]
	managed *credential.Managed[*verifierState]
}

type verifierEntry struct {
	name   string
	digest [sha256.Size]byte
}

type verifierState struct {
	entries []verifierEntry
}

// NewVerifier resolves every key at startup (files are read once, not per
// request — and once here, not again after a separate Validate pass) and
// compiles the digest set. Note the tokens themselves do not hot-reload: a
// rotated token_file is picked up only on restart, unlike TLS certificates.
func NewVerifier(cfg *ServerConfig) (*Verifier, error) {
	v, _, err := BuildVerifier(cfg)
	return v, err
}

// BuildVerifier resolves the accepted keys and returns permission warnings in
// the same filesystem pass.
func BuildVerifier(cfg *ServerConfig) (*Verifier, []Warning, error) {
	state, warns, err := compileServer(cfg)
	if err != nil {
		return nil, nil, err
	}
	v := &Verifier{}
	v.state.Store(state)
	return v, warns, nil
}

// Enabled reports whether any key is configured.
func (v *Verifier) Enabled() bool {
	state := v.current()
	return state != nil && len(state.entries) > 0
}

// Verify reports whether token matches any configured key. Constant-time in
// the token comparison; iterates all keys regardless of an early match.
func (v *Verifier) Verify(token string) bool {
	_, ok := v.VerifyPrincipal(token)
	return ok
}

// VerifyPrincipal returns the configured key name after scanning every digest.
func (v *Verifier) VerifyPrincipal(token string) (string, bool) {
	state := v.current()
	if state == nil || len(state.entries) == 0 {
		return "", false
	}
	d := sha256.Sum256([]byte(token))
	match := 0
	principal := ""
	for i := range state.entries {
		equal := subtle.ConstantTimeCompare(d[:], state.entries[i].digest[:])
		match |= equal
		if equal == 1 {
			principal = state.entries[i].name
		}
	}
	return principal, match == 1
}

func (v *Verifier) current() *verifierState {
	if v == nil {
		return nil
	}
	if v.managed != nil {
		return v.managed.Current()
	}
	return v.state.Load()
}

// Settings are the materialized Options, exported so implementations outside
// this package (grpcreef) honor the same options.
type Settings struct {
	ExemptPaths []string
	OnFailure   func(remoteAddr, path string)
	OnSuccess   func(remoteAddr, path, principal string)
}

// Option customizes Require / grpcreef.ServerOptions.
type Option func(*Settings)

// ExemptPaths replaces the default no-auth path list
// (/healthz, /readyz, /metrics). Matching is exact.
func ExemptPaths(paths ...string) Option {
	return func(s *Settings) { s.ExemptPaths = paths }
}

// OnFailure installs a hook called on every rejected request, e.g. to
// increment a metrics counter. It must not block.
func OnFailure(f func(remoteAddr, path string)) Option {
	return func(s *Settings) { s.OnFailure = f }
}

// OnSuccess installs a non-blocking audit hook for authenticated requests.
func OnSuccess(f func(remoteAddr, path, principal string)) Option {
	return func(s *Settings) { s.OnSuccess = f }
}

// Apply materializes opts over the defaults.
func Apply(opts ...Option) Settings {
	s := Settings{ExemptPaths: []string{"/healthz", "/readyz", "/metrics"}}
	for _, o := range opts {
		o(&s)
	}
	return s
}

// Require builds the auth middleware. An empty/nil config yields a pass-through
// middleware (auth disabled). Rejection: 401, WWW-Authenticate: Bearer, JSON
// body — with no distinction between a missing and a wrong token.
func Require(cfg *ServerConfig, opts ...Option) (func(http.Handler) http.Handler, error) {
	middleware, _, err := BuildRequire(cfg, opts...)
	return middleware, err
}

// BuildRequire materializes the verifier, middleware, and permission warnings
// without a separate validation pass.
func BuildRequire(cfg *ServerConfig, opts ...Option) (func(http.Handler) http.Handler, []Warning, error) {
	v, warns, err := BuildVerifier(cfg)
	if err != nil {
		return nil, nil, err
	}
	return requireVerifier(v, opts...), warns, nil
}

func requireVerifier(v *Verifier, opts ...Option) func(http.Handler) http.Handler {
	if !v.Enabled() {
		return func(next http.Handler) http.Handler { return next }
	}
	set := Apply(opts...)
	exempt := make(map[string]bool, len(set.ExemptPaths))
	for _, p := range set.ExemptPaths {
		exempt[p] = true
	}
	middleware := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if exempt[r.URL.Path] {
				next.ServeHTTP(w, r)
				return
			}
			if tok, ok := FromHeader(r.Header.Get("Authorization")); ok {
				if principal, valid := v.VerifyPrincipal(tok); valid {
					if set.OnSuccess != nil {
						set.OnSuccess(r.RemoteAddr, r.URL.Path, principal)
					}
					next.ServeHTTP(w, r.WithContext(ContextWithPrincipal(r.Context(), principal)))
					return
				}
			}
			if set.OnFailure != nil {
				set.OnFailure(r.RemoteAddr, r.URL.Path)
			}
			w.Header().Set("WWW-Authenticate", "Bearer")
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":"unauthorized"}`))
		})
	}
	return middleware
}

type principalContextKey struct{}

// ContextWithPrincipal attaches an authenticated Reef principal.
func ContextWithPrincipal(ctx context.Context, principal string) context.Context {
	return context.WithValue(ctx, principalContextKey{}, principal)
}

// PrincipalFromContext returns the authenticated Reef principal.
func PrincipalFromContext(ctx context.Context) (string, bool) {
	principal, ok := ctx.Value(principalContextKey{}).(string)
	return principal, ok && principal != ""
}

// FromHeader extracts the token from an Authorization header value.
// The scheme match is case-insensitive per RFC 9110.
func FromHeader(h string) (string, bool) {
	const prefix = "bearer "
	if len(h) <= len(prefix) || !strings.EqualFold(h[:len(prefix)], prefix) {
		return "", false
	}
	tok := strings.TrimSpace(h[len(prefix):])
	return tok, tok != ""
}

// Transport wraps base with Authorization: Bearer injection. A nil base means
// http.DefaultTransport; an empty config returns base unchanged. A request
// that already carries an Authorization header wins over the config token.
func Transport(cfg *ClientConfig, base http.RoundTripper) (http.RoundTripper, error) {
	rt, _, err := BuildTransport(cfg, base)
	return rt, err
}

// BuildTransport materializes token injection and returns permission warnings
// without a separate validation pass.
func BuildTransport(cfg *ClientConfig, base http.RoundTripper) (http.RoundTripper, []Warning, error) {
	if base == nil {
		base = http.DefaultTransport
	}
	tok, warns, err := BuildClientToken(cfg)
	if err != nil {
		return nil, nil, err
	}
	if tok == "" {
		return base, warns, nil
	}
	return &transport{base: base, header: "Bearer " + tok}, warns, nil
}

// ClientToken resolves the client-side token ("" when unset).
func ClientToken(cfg *ClientConfig) (string, error) {
	tok, _, err := BuildClientToken(cfg)
	return tok, err
}

// BuildClientToken resolves the client token and returns permission warnings in
// the same filesystem pass.
func BuildClientToken(cfg *ClientConfig) (string, []Warning, error) {
	if cfg == nil || (cfg.Token == "" && cfg.TokenFile == "" && cfg.TokenEnv == "") {
		return "", nil, nil
	}
	tok, err := resolve(cfg.Token, cfg.TokenFile, cfg.TokenEnv)
	if err != nil {
		return "", nil, fmt.Errorf("bearer: client token: %w", err)
	}
	return tok, clientWarnings(cfg), nil
}

type transport struct {
	base   http.RoundTripper
	header string
}

func (t *transport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.Header.Get("Authorization") != "" {
		return t.base.RoundTrip(req)
	}
	clone := req.Clone(req.Context())
	if clone.Header == nil {
		clone.Header = make(http.Header)
	}
	clone.Header.Set("Authorization", t.header)
	return t.base.RoundTrip(clone)
}

type serverSource struct {
	name  string
	token string
	file  string
}

func compileServer(cfg *ServerConfig) (*verifierState, []Warning, error) {
	sources, warns, _, err := prepareServerSources(cfg)
	if err != nil {
		return nil, nil, err
	}
	state, _, err := loadServerSources(sources)
	if err != nil {
		return nil, nil, err
	}
	return state, warns, nil
}

func prepareServerSources(cfg *ServerConfig) ([]serverSource, []Warning, bool, error) {
	if cfg == nil {
		return nil, nil, false, nil
	}
	sources := make([]serverSource, 0, len(cfg.Bearer))
	seen := make(map[string]bool, len(cfg.Bearer))
	var warns []Warning
	hasFiles := false
	for i, key := range cfg.Bearer {
		if key.Name == "" {
			return nil, nil, false, fmt.Errorf("bearer: key #%d has no name", i)
		}
		if seen[key.Name] {
			return nil, nil, false, fmt.Errorf("bearer: duplicate key name %q", key.Name)
		}
		seen[key.Name] = true
		if err := validateSourceSelection(key.Token, key.TokenFile, key.TokenEnv); err != nil {
			return nil, nil, false, fmt.Errorf("bearer: key %q: %w", key.Name, err)
		}
		source := serverSource{name: key.Name, file: key.TokenFile}
		if key.TokenFile != "" {
			hasFiles = true
			warns = append(warns, filePermWarnings(key.TokenFile)...)
		} else {
			token, err := resolve(key.Token, key.TokenFile, key.TokenEnv)
			if err != nil {
				return nil, nil, false, fmt.Errorf("bearer: key %q: %w", key.Name, err)
			}
			source.token = token
		}
		if key.Token != "" {
			warns = append(warns, Warning(fmt.Sprintf(
				"inline token configured for key %q; prefer token_file or token_env", key.Name,
			)))
		}
		sources = append(sources, source)
	}
	return sources, warns, hasFiles, nil
}

func loadServerSources(sources []serverSource) (*verifierState, [sha256.Size]byte, error) {
	state := &verifierState{entries: make([]verifierEntry, 0, len(sources))}
	seenDigests := make(map[[sha256.Size]byte]string, len(sources))
	hash := sha256.New()
	for _, source := range sources {
		token := source.token
		if source.file != "" {
			var err error
			token, err = resolve("", source.file, "")
			if err != nil {
				return nil, [sha256.Size]byte{}, fmt.Errorf("bearer: key %q: %w", source.name, err)
			}
		}
		digest := sha256.Sum256([]byte(token))
		if existing, ok := seenDigests[digest]; ok {
			return nil, [sha256.Size]byte{}, fmt.Errorf(
				"bearer: keys %q and %q resolve to the same token", existing, source.name,
			)
		}
		seenDigests[digest] = source.name
		state.entries = append(state.entries, verifierEntry{name: source.name, digest: digest})
		_, _ = hash.Write([]byte(source.name))
		_, _ = hash.Write([]byte{0})
		_, _ = hash.Write(digest[:])
	}
	var fingerprint [sha256.Size]byte
	copy(fingerprint[:], hash.Sum(nil))
	return state, fingerprint, nil
}

// resolve returns the token from exactly one of the three sources.
func resolve(inline, file, env string) (string, error) {
	if err := validateSourceSelection(inline, file, env); err != nil {
		return "", err
	}
	switch {
	case inline != "":
		return normalizeToken(inline)
	case file != "":
		f, err := os.Open(file)
		if err != nil {
			return "", fmt.Errorf("read token file: %w", err)
		}
		defer func() { _ = f.Close() }()
		b, err := io.ReadAll(io.LimitReader(f, MaxTokenBytes+2))
		if err != nil {
			return "", fmt.Errorf("read token file: %w", err)
		}
		token, err := normalizeToken(string(b))
		if err != nil {
			return "", fmt.Errorf("token file %s: %w", file, err)
		}
		return token, nil
	default:
		tok := os.Getenv(env)
		if tok == "" {
			return "", fmt.Errorf("environment variable %s is empty or unset", env)
		}
		token, err := normalizeToken(tok)
		if err != nil {
			return "", fmt.Errorf("environment variable %s: %w", env, err)
		}
		return token, nil
	}
}

func validateSourceSelection(inline, file, env string) error {
	n := 0
	for _, s := range []string{inline, file, env} {
		if s != "" {
			n++
		}
	}
	switch {
	case n == 0:
		return errors.New("no token source set (token, token_file or token_env)")
	case n > 1:
		return errors.New("multiple token sources set; use exactly one of token, token_file, token_env")
	}
	return nil
}

func normalizeToken(raw string) (string, error) {
	token := strings.TrimSpace(raw)
	if token == "" {
		return "", errors.New("token is empty")
	}
	if len(token) > MaxTokenBytes {
		return "", fmt.Errorf("token exceeds maximum size of %d bytes", MaxTokenBytes)
	}
	if strings.IndexFunc(token, func(r rune) bool {
		return unicode.IsSpace(r) || unicode.IsControl(r)
	}) >= 0 {
		return "", errors.New("token contains whitespace or control characters")
	}
	return token, nil
}

func clientWarnings(cfg *ClientConfig) []Warning {
	if cfg == nil {
		return nil
	}
	warns := filePermWarnings(cfg.TokenFile)
	if cfg.Token != "" {
		warns = append(warns, Warning("inline client token configured; prefer token_file or token_env"))
	}
	return warns
}

func filePermWarnings(file string) []Warning {
	if file == "" {
		return nil
	}
	info, err := os.Stat(file)
	if err != nil {
		return nil
	}
	if perm := info.Mode().Perm(); perm&0o077 != 0 {
		return []Warning{Warning(fmt.Sprintf("token file %s has permissions %04o; tighten to 0600", file, perm))}
	}
	return nil
}
