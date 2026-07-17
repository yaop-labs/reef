// Package reefclient assembles the client side of an HTTP edge in one call:
// TLS from tlsconf plus bearer-token injection.
package reefclient

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/yaop-labs/reef/bearer"
	"github.com/yaop-labs/reef/credential"
	"github.com/yaop-labs/reef/edge"
	"github.com/yaop-labs/reef/tlsconf"
)

// Config mirrors the client-side YAML: `tls:` and `auth:` blocks.
type Config struct {
	TLS  *tlsconf.ClientConfig `yaml:"tls"`
	Auth *bearer.ClientConfig  `yaml:"auth"`
}

// Transport builds an http.RoundTripper honoring both blocks. With both
// empty it returns a plain default-equivalent transport (plaintext, no auth).
func Transport(cfg Config) (http.RoundTripper, error) {
	return TransportWithBase(cfg, nil)
}

// TransportWithBase builds the low-level HTTP transport on a clone of base.
// A nil base clones http.DefaultTransport. The caller's transport is never
// mutated.
func TransportWithBase(cfg Config, base *http.Transport) (http.RoundTripper, error) {
	rt, _, _, err := buildTransport(cfg, base)
	return rt, err
}

func buildTransport(cfg Config, base *http.Transport) (http.RoundTripper, []tlsconf.Warning, []bearer.Warning, error) {
	tlsCfg, tlsWarns, err := tlsconf.BuildClient(cfg.TLS)
	if err != nil {
		return nil, nil, nil, err
	}
	materialized := &http.Transport{}
	switch {
	case base != nil:
		materialized = base.Clone()
	default:
		// Clone the process default to inherit its proxy/timeout settings; fall
		// back to a fresh Transport if DefaultTransport was replaced.
		if dt, ok := http.DefaultTransport.(*http.Transport); ok {
			materialized = dt.Clone()
		}
	}
	if tlsCfg != nil {
		materialized.TLSClientConfig = tlsCfg
	}
	rt, authWarns, err := bearer.BuildTransport(cfg.Auth, materialized)
	if err != nil {
		return nil, nil, nil, err
	}
	return rt, tlsWarns, authWarns, nil
}

// EdgeTransport validates a complete HTTP client edge, builds its transport,
// and binds the result to the configured target origin. Redirects or reuse for
// another origin fail before bearer credentials can be injected.
func EdgeTransport(cfg edge.ClientConfig, base *http.Transport) (http.RoundTripper, []edge.Warning, error) {
	if err := edge.CheckHTTPClient(cfg); err != nil {
		return nil, nil, err
	}
	u, err := url.Parse(cfg.Target)
	if err != nil {
		return nil, nil, fmt.Errorf("reefclient: parse target: %w", err)
	}
	rt, tlsWarns, authWarns, err := buildTransport(Config{TLS: cfg.TLS, Auth: cfg.Auth}, base)
	if err != nil {
		return nil, nil, err
	}
	return &originTransport{
		base:   rt,
		scheme: strings.ToLower(u.Scheme),
		host:   u.Host,
	}, joinWarnings(tlsWarns, authWarns), nil
}

// EdgeClient is a target-bound managed HTTP transport.
type EdgeClient struct {
	transport       http.RoundTripper
	httpTransport   *http.Transport
	tlsCredentials  *credential.Group
	authCredentials *credential.Group
}

// NewEdgeTransport materializes provider-aware TLS and background bearer
// reload. Call Close when the owning HTTP client is no longer used.
func NewEdgeTransport(cfg edge.ClientConfig, base *http.Transport) (*EdgeClient, []edge.Warning, error) {
	if err := edge.CheckHTTPClient(cfg); err != nil {
		return nil, nil, err
	}
	u, err := url.Parse(cfg.Target)
	if err != nil {
		return nil, nil, fmt.Errorf("reefclient: parse target: %w", err)
	}

	tlsResult, err := tlsconf.MaterializeClient(cfg.TLS, tlsconf.Lifecycle{
		Interval: cfg.ReloadInterval,
		Observer: cfg.Observer,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("edge: client TLS: %w", err)
	}

	materialized := &http.Transport{}
	switch {
	case base != nil:
		materialized = base.Clone()
	default:
		if dt, ok := http.DefaultTransport.(*http.Transport); ok {
			materialized = dt.Clone()
		}
	}
	if tlsResult.Provider != nil {
		materialized.TLSClientConfig = tlsResult.Provider.ConfigForServer(u.Hostname())
	}

	authResult, err := bearer.MaterializeTransport(cfg.Auth, materialized, bearer.Lifecycle{
		Interval: cfg.ReloadInterval,
		Observer: cfg.Observer,
	})
	if err != nil {
		_ = tlsResult.Close()
		return nil, nil, fmt.Errorf("edge: client auth: %w", err)
	}
	origin := &originTransport{
		base:   authResult.Transport,
		scheme: strings.ToLower(u.Scheme),
		host:   u.Host,
	}
	return &EdgeClient{
		transport:       origin,
		httpTransport:   materialized,
		tlsCredentials:  tlsResult.Credentials,
		authCredentials: authResult.Credentials,
	}, joinWarnings(tlsResult.Warnings, authResult.Warnings), nil
}

// RoundTrip implements http.RoundTripper.
func (c *EdgeClient) RoundTrip(req *http.Request) (*http.Response, error) {
	return c.transport.RoundTrip(req)
}

// CredentialStatus returns TLS and bearer lifecycle snapshots.
func (c *EdgeClient) CredentialStatus() []credential.Status {
	if c == nil {
		return nil
	}
	return append(c.tlsCredentials.Statuses(), c.authCredentials.Statuses()...)
}

// ReloadCredentials immediately checks all file-backed TLS and bearer
// credentials. Background reload remains active after the call.
func (c *EdgeClient) ReloadCredentials() error {
	if c == nil {
		return nil
	}
	return errors.Join(c.tlsCredentials.ReloadNow(), c.authCredentials.ReloadNow())
}

// Close closes idle connections and stops all background reload.
func (c *EdgeClient) Close() error {
	if c == nil {
		return nil
	}
	if c.httpTransport != nil {
		c.httpTransport.CloseIdleConnections()
	}
	return errors.Join(c.authCredentials.Close(), c.tlsCredentials.Close())
}

type originTransport struct {
	base   http.RoundTripper
	scheme string
	host   string
}

func (t *originTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req == nil || req.URL == nil {
		return nil, fmt.Errorf("reefclient: request URL is required")
	}
	if strings.ToLower(req.URL.Scheme) != t.scheme || !strings.EqualFold(req.URL.Host, t.host) {
		return nil, fmt.Errorf(
			"reefclient: request origin %q is outside configured edge %q",
			req.URL.Scheme+"://"+req.URL.Host,
			t.scheme+"://"+t.host,
		)
	}
	return t.base.RoundTrip(req)
}

func joinWarnings(tlsWarns []tlsconf.Warning, authWarns []bearer.Warning) []edge.Warning {
	out := make([]edge.Warning, 0, len(tlsWarns)+len(authWarns))
	for _, warning := range tlsWarns {
		out = append(out, edge.Warning("tls: "+string(warning)))
	}
	for _, warning := range authWarns {
		out = append(out, edge.Warning("auth: "+string(warning)))
	}
	return out
}
