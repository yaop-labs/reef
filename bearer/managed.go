package bearer

import (
	"crypto/sha256"
	"net/http"
	"time"

	"github.com/yaop-labs/reef/credential"
)

// Lifecycle configures background reload for file-backed bearer credentials.
type Lifecycle struct {
	Interval time.Duration
	Observer credential.Observer
}

// ManagedVerifier is a verifier plus its owned credential lifecycle.
type ManagedVerifier struct {
	Verifier    *Verifier
	Warnings    []Warning
	Credentials *credential.Group
}

// Close stops background token reload.
func (m *ManagedVerifier) Close() error {
	if m == nil {
		return nil
	}
	return m.Credentials.Close()
}

// MaterializeVerifier builds a verifier whose token_file keys reload in the
// background. Inline and environment sources remain startup-only.
func MaterializeVerifier(cfg *ServerConfig, lifecycle Lifecycle) (*ManagedVerifier, error) {
	sources, warns, hasFiles, err := prepareServerSources(cfg)
	if err != nil {
		return nil, err
	}
	result := &ManagedVerifier{
		Verifier:    &Verifier{},
		Warnings:    warns,
		Credentials: credential.NewGroup(),
	}
	if !hasFiles {
		state, _, err := loadServerSources(sources)
		if err != nil {
			return nil, err
		}
		result.Verifier.state.Store(state)
		return result, nil
	}

	manager, err := credential.NewManaged(credential.Options{
		Name:     "server-bearer",
		Kind:     credential.KindServerToken,
		Interval: lifecycle.Interval,
		Observer: lifecycle.Observer,
	}, func() (*verifierState, credential.Metadata, error) {
		state, fingerprint, err := loadServerSources(sources)
		if err != nil {
			return nil, credential.Metadata{}, err
		}
		return state, credential.Metadata{Fingerprint: fingerprint}, nil
	})
	if err != nil {
		return nil, err
	}
	if err := result.Credentials.Add(manager); err != nil {
		_ = manager.Close()
		return nil, err
	}
	result.Verifier.managed = manager
	return result, nil
}

// ManagedMiddleware is HTTP auth middleware plus its owned lifecycle.
type ManagedMiddleware struct {
	Middleware  func(http.Handler) http.Handler
	Warnings    []Warning
	Credentials *credential.Group
}

// Close stops background token reload.
func (m *ManagedMiddleware) Close() error {
	if m == nil {
		return nil
	}
	return m.Credentials.Close()
}

// MaterializeRequire builds managed HTTP bearer middleware.
func MaterializeRequire(cfg *ServerConfig, lifecycle Lifecycle, opts ...Option) (*ManagedMiddleware, error) {
	materialized, err := MaterializeVerifier(cfg, lifecycle)
	if err != nil {
		return nil, err
	}
	return &ManagedMiddleware{
		Middleware:  requireVerifier(materialized.Verifier, opts...),
		Warnings:    materialized.Warnings,
		Credentials: materialized.Credentials,
	}, nil
}

// TokenProvider returns the current client bearer generation.
type TokenProvider struct {
	static  string
	managed *credential.Managed[string]
}

// Current returns the current token. The value must never be logged.
func (p *TokenProvider) Current() string {
	if p == nil {
		return ""
	}
	if p.managed != nil {
		return p.managed.Current()
	}
	return p.static
}

// ManagedClientToken is a token provider plus its owned lifecycle.
type ManagedClientToken struct {
	Provider    *TokenProvider
	Warnings    []Warning
	Credentials *credential.Group
}

// Close stops background token reload.
func (m *ManagedClientToken) Close() error {
	if m == nil {
		return nil
	}
	return m.Credentials.Close()
}

// MaterializeClientToken builds a provider whose token_file reloads in the
// background. Inline and environment sources remain startup-only.
func MaterializeClientToken(cfg *ClientConfig, lifecycle Lifecycle) (*ManagedClientToken, error) {
	result := &ManagedClientToken{
		Provider:    &TokenProvider{},
		Warnings:    clientWarnings(cfg),
		Credentials: credential.NewGroup(),
	}
	if cfg == nil || (cfg.Token == "" && cfg.TokenFile == "" && cfg.TokenEnv == "") {
		return result, nil
	}
	if err := validateSourceSelection(cfg.Token, cfg.TokenFile, cfg.TokenEnv); err != nil {
		return nil, err
	}
	if cfg.TokenFile == "" {
		token, err := resolve(cfg.Token, cfg.TokenFile, cfg.TokenEnv)
		if err != nil {
			return nil, err
		}
		result.Provider.static = token
		return result, nil
	}

	manager, err := credential.NewManaged(credential.Options{
		Name:     "client-bearer",
		Kind:     credential.KindClientToken,
		Interval: lifecycle.Interval,
		Observer: lifecycle.Observer,
	}, func() (string, credential.Metadata, error) {
		token, err := resolve("", cfg.TokenFile, "")
		if err != nil {
			return "", credential.Metadata{}, err
		}
		return token, credential.Metadata{Fingerprint: sha256.Sum256([]byte(token))}, nil
	})
	if err != nil {
		return nil, err
	}
	if err := result.Credentials.Add(manager); err != nil {
		_ = manager.Close()
		return nil, err
	}
	result.Provider.managed = manager
	return result, nil
}

// ManagedTransport is a token-injecting transport plus its owned lifecycle.
type ManagedTransport struct {
	Transport   http.RoundTripper
	Warnings    []Warning
	Credentials *credential.Group
}

// Close stops background token reload.
func (m *ManagedTransport) Close() error {
	if m == nil {
		return nil
	}
	return m.Credentials.Close()
}

// MaterializeTransport builds a transport that reads the current token on each
// request without file I/O on the request path.
func MaterializeTransport(cfg *ClientConfig, base http.RoundTripper, lifecycle Lifecycle) (*ManagedTransport, error) {
	if base == nil {
		base = http.DefaultTransport
	}
	token, err := MaterializeClientToken(cfg, lifecycle)
	if err != nil {
		return nil, err
	}
	rt := base
	if token.Provider.Current() != "" {
		rt = &managedTransport{base: base, token: token.Provider}
	}
	return &ManagedTransport{
		Transport:   rt,
		Warnings:    token.Warnings,
		Credentials: token.Credentials,
	}, nil
}

type managedTransport struct {
	base  http.RoundTripper
	token *TokenProvider
}

func (t *managedTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.Header.Get("Authorization") != "" {
		return t.base.RoundTrip(req)
	}
	clone := req.Clone(req.Context())
	if clone.Header == nil {
		clone.Header = make(http.Header)
	}
	clone.Header.Set("Authorization", "Bearer "+t.token.Current())
	return t.base.RoundTrip(clone)
}
