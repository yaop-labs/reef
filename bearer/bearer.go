// Package bearer implements the platform's bearer-token authentication:
// named keys on the server side (HTTP middleware; grpcreef reuses the
// Verifier), a token-injecting RoundTripper on the client side.
//
// Secret hygiene: token values never appear in errors, logs, or responses —
// only key names do. Comparison is constant-time over sha256 digests, so
// neither timing nor token length leaks.
package bearer

import (
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
)

// Warning is a non-fatal validation finding (e.g. token file permissions).
type Warning string

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
	if c == nil {
		return nil, nil
	}
	var warns []Warning
	seen := make(map[string]bool, len(c.Bearer))
	for i, k := range c.Bearer {
		if k.Name == "" {
			return nil, fmt.Errorf("bearer: key #%d has no name", i)
		}
		if seen[k.Name] {
			return nil, fmt.Errorf("bearer: duplicate key name %q", k.Name)
		}
		seen[k.Name] = true
		if _, err := resolve(k.Token, k.TokenFile, k.TokenEnv); err != nil {
			return nil, fmt.Errorf("bearer: key %q: %w", k.Name, err)
		}
		warns = append(warns, filePermWarnings(k.TokenFile)...)
	}
	return warns, nil
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
	return filePermWarnings(c.TokenFile), nil
}

// Verifier holds the accepted keys compiled for verification. The zero value
// (or one built from an empty config) reports Enabled() == false.
type Verifier struct {
	digests [][sha256.Size]byte
}

// NewVerifier resolves every key at startup (files are read once, not per
// request — and once here, not again after a separate Validate pass) and
// compiles the digest set. Note the tokens themselves do not hot-reload: a
// rotated token_file is picked up only on restart, unlike TLS certificates.
func NewVerifier(cfg *ServerConfig) (*Verifier, error) {
	v := &Verifier{}
	if cfg == nil {
		return v, nil
	}
	seen := make(map[string]bool, len(cfg.Bearer))
	for i, k := range cfg.Bearer {
		if k.Name == "" {
			return nil, fmt.Errorf("bearer: key #%d has no name", i)
		}
		if seen[k.Name] {
			return nil, fmt.Errorf("bearer: duplicate key name %q", k.Name)
		}
		seen[k.Name] = true
		tok, err := resolve(k.Token, k.TokenFile, k.TokenEnv)
		if err != nil {
			return nil, fmt.Errorf("bearer: key %q: %w", k.Name, err)
		}
		v.digests = append(v.digests, sha256.Sum256([]byte(tok)))
	}
	return v, nil
}

// Enabled reports whether any key is configured.
func (v *Verifier) Enabled() bool { return v != nil && len(v.digests) > 0 }

// Verify reports whether token matches any configured key. Constant-time in
// the token comparison; iterates all keys regardless of an early match.
func (v *Verifier) Verify(token string) bool {
	if !v.Enabled() {
		return false
	}
	d := sha256.Sum256([]byte(token))
	match := 0
	for i := range v.digests {
		match |= subtle.ConstantTimeCompare(d[:], v.digests[i][:])
	}
	return match == 1
}

// Settings are the materialized Options — exported so implementations outside
// this package (grpcreef) honor the same knobs.
type Settings struct {
	ExemptPaths []string
	OnFailure   func(remoteAddr, path string)
}

// Option customizes Require / grpcreef.ServerOptions.
type Option func(*Settings)

// ExemptPaths replaces the default no-auth path list
// (/healthz, /readyz, /metrics). Matching is exact.
func ExemptPaths(paths ...string) Option {
	return func(s *Settings) { s.ExemptPaths = paths }
}

// OnFailure installs a hook called on every rejected request — the place to
// wire a selfobs counter. It must not block.
func OnFailure(f func(remoteAddr, path string)) Option {
	return func(s *Settings) { s.OnFailure = f }
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
	v, err := NewVerifier(cfg)
	if err != nil {
		return nil, err
	}
	if !v.Enabled() {
		return func(next http.Handler) http.Handler { return next }, nil
	}
	set := Apply(opts...)
	exempt := make(map[string]bool, len(set.ExemptPaths))
	for _, p := range set.ExemptPaths {
		exempt[p] = true
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if exempt[r.URL.Path] {
				next.ServeHTTP(w, r)
				return
			}
			if tok, ok := FromHeader(r.Header.Get("Authorization")); ok && v.Verify(tok) {
				next.ServeHTTP(w, r)
				return
			}
			if set.OnFailure != nil {
				set.OnFailure(r.RemoteAddr, r.URL.Path)
			}
			w.Header().Set("WWW-Authenticate", "Bearer")
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":"unauthorized"}`))
		})
	}, nil
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
	if base == nil {
		base = http.DefaultTransport
	}
	tok, err := ClientToken(cfg)
	if err != nil {
		return nil, err
	}
	if tok == "" {
		return base, nil
	}
	return &transport{base: base, header: "Bearer " + tok}, nil
}

// ClientToken resolves the client-side token ("" when unset).
func ClientToken(cfg *ClientConfig) (string, error) {
	if cfg == nil || (cfg.Token == "" && cfg.TokenFile == "" && cfg.TokenEnv == "") {
		return "", nil
	}
	tok, err := resolve(cfg.Token, cfg.TokenFile, cfg.TokenEnv)
	if err != nil {
		return "", fmt.Errorf("bearer: client token: %w", err)
	}
	return tok, nil
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
	clone.Header.Set("Authorization", t.header)
	return t.base.RoundTrip(clone)
}

// resolve returns the token from exactly one of the three sources.
func resolve(inline, file, env string) (string, error) {
	n := 0
	for _, s := range []string{inline, file, env} {
		if s != "" {
			n++
		}
	}
	switch {
	case n == 0:
		return "", errors.New("no token source set (token, token_file or token_env)")
	case n > 1:
		return "", errors.New("multiple token sources set; use exactly one of token, token_file, token_env")
	}
	switch {
	case inline != "":
		return inline, nil
	case file != "":
		b, err := os.ReadFile(file)
		if err != nil {
			return "", fmt.Errorf("read token file: %w", err)
		}
		tok := strings.TrimSpace(string(b))
		if tok == "" {
			return "", fmt.Errorf("token file %s is empty", file)
		}
		return tok, nil
	default:
		tok := os.Getenv(env)
		if tok == "" {
			return "", fmt.Errorf("environment variable %s is empty or unset", env)
		}
		return tok, nil
	}
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
