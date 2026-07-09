// Package reefclient assembles the client side of an HTTP edge in one call:
// TLS from tlsconf plus bearer-token injection — what an exporter needs.
package reefclient

import (
	"net/http"

	"github.com/yaop-labs/reef/bearer"
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
	tlsCfg, err := tlsconf.Client(cfg.TLS)
	if err != nil {
		return nil, err
	}
	base := http.DefaultTransport.(*http.Transport).Clone()
	if tlsCfg != nil {
		base.TLSClientConfig = tlsCfg
	}
	return bearer.Transport(cfg.Auth, base)
}
