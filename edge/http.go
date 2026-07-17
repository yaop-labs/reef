package edge

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net/http"

	"github.com/yaop-labs/reef/bearer"
	"github.com/yaop-labs/reef/credential"
	"github.com/yaop-labs/reef/tlsconf"
)

// HTTPServer is a materialized HTTP security edge.
type HTTPServer struct {
	TLSConfig  *tls.Config
	Middleware func(http.Handler) http.Handler
	Warnings   []Warning

	tlsCredentials  *credential.Group
	authCredentials *credential.Group
}

// CredentialStatus returns all TLS and bearer lifecycle snapshots.
func (s *HTTPServer) CredentialStatus() []credential.Status {
	if s == nil {
		return nil
	}
	return append(s.tlsCredentials.Statuses(), s.authCredentials.Statuses()...)
}

// ReloadCredentials immediately checks all file-backed TLS and bearer
// credentials. Background reload remains active after the call.
func (s *HTTPServer) ReloadCredentials() error {
	if s == nil {
		return nil
	}
	return errors.Join(s.tlsCredentials.ReloadNow(), s.authCredentials.ReloadNow())
}

// Close stops all background credential reload.
func (s *HTTPServer) Close() error {
	if s == nil {
		return nil
	}
	return errors.Join(s.authCredentials.Close(), s.tlsCredentials.Close())
}

// NewHTTPServer validates the complete listener policy and builds its TLS
// config and auth middleware. The production default exempts health/readiness,
// but keeps /metrics protected. A caller may explicitly replace the exemptions
// with bearer.ExemptPaths.
func NewHTTPServer(c ServerConfig, opts ...bearer.Option) (*HTTPServer, error) {
	if err := CheckServer(c); err != nil {
		return nil, err
	}
	tlsResult, err := tlsconf.MaterializeServer(c.TLS, tlsconf.Lifecycle{
		Interval: c.ReloadInterval,
		Observer: c.Observer,
	})
	if err != nil {
		return nil, fmt.Errorf("edge: server TLS: %w", err)
	}
	authOpts := make([]bearer.Option, 0, len(opts)+1)
	authOpts = append(authOpts, bearer.ExemptPaths("/healthz", "/readyz"))
	authOpts = append(authOpts, opts...)
	authResult, err := bearer.MaterializeRequire(c.Auth, bearer.Lifecycle{
		Interval: c.ReloadInterval,
		Observer: c.Observer,
	}, authOpts...)
	if err != nil {
		_ = tlsResult.Close()
		return nil, fmt.Errorf("edge: server auth: %w", err)
	}
	return &HTTPServer{
		TLSConfig:       tlsResult.Config,
		Middleware:      authResult.Middleware,
		Warnings:        warnings(tlsResult.Warnings, authResult.Warnings),
		tlsCredentials:  tlsResult.Credentials,
		authCredentials: authResult.Credentials,
	}, nil
}
