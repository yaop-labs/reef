// Package edge enforces the platform security policy for complete server and
// client edges. It is the high-level layer above tlsconf and bearer: low-level
// packages remain available for embedded and test use, while production
// callers should materialize their transports through edge-aware constructors.
package edge

import (
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/yaop-labs/reef/bearer"
	"github.com/yaop-labs/reef/credential"
	"github.com/yaop-labs/reef/tlsconf"
)

// Warning is a non-fatal finding returned while materializing an edge.
type Warning string

// ServerConfig describes the complete security boundary of a listener.
type ServerConfig struct {
	Bind                           string                `yaml:"bind"`
	TLS                            *tlsconf.ServerConfig `yaml:"tls"`
	Auth                           *bearer.ServerConfig  `yaml:"auth"`
	Insecure                       bool                  `yaml:"insecure"`
	DangerAllowBearerOverPlaintext bool                  `yaml:"danger_allow_bearer_over_plaintext"`
	ReloadInterval                 time.Duration         `yaml:"-"`
	Observer                       credential.Observer   `yaml:"-"`
}

// ClientConfig describes the complete security boundary of a client.
type ClientConfig struct {
	Target                         string                `yaml:"target"`
	TLS                            *tlsconf.ClientConfig `yaml:"tls"`
	Auth                           *bearer.ClientConfig  `yaml:"auth"`
	Insecure                       bool                  `yaml:"insecure"`
	DangerAllowBearerOverPlaintext bool                  `yaml:"danger_allow_bearer_over_plaintext"`
	ReloadInterval                 time.Duration         `yaml:"-"`
	Observer                       credential.Observer   `yaml:"-"`
}

// CheckServer enforces the address/TLS/auth policy without reading credential
// files. ValidateServer additionally validates the underlying config blocks.
func CheckServer(c ServerConfig) error {
	return checkPlaintext(
		"server",
		c.Bind,
		serverTLSEnabled(c.TLS),
		serverAuthEnabled(c.Auth),
		c.Insecure,
		c.DangerAllowBearerOverPlaintext,
	)
}

// CheckClient enforces policy for clients whose transport security is selected
// by the TLS block, such as gRPC.
func CheckClient(c ClientConfig) error {
	return checkPlaintext(
		"client",
		c.Target,
		clientTLSEnabled(c.TLS),
		clientAuthEnabled(c.Auth),
		c.Insecure,
		c.DangerAllowBearerOverPlaintext,
	)
}

// CheckHTTPClient enforces policy using the target URL scheme as the actual
// transport mode. HTTPS may use the system trust store with an empty TLS block.
func CheckHTTPClient(c ClientConfig) error {
	u, err := parseHTTPURL(c.Target)
	if err != nil {
		return err
	}
	secure := u.Scheme == "https"
	if u.Scheme == "http" && clientTLSEnabled(c.TLS) {
		return errorsf("client target %q uses http but TLS is enabled", c.Target)
	}
	return checkPlaintext(
		"client",
		u.Hostname(),
		secure,
		clientAuthEnabled(c.Auth),
		c.Insecure,
		c.DangerAllowBearerOverPlaintext,
	)
}

// ValidateServer validates both low-level blocks, returns their warnings, and
// enforces the complete edge policy.
func ValidateServer(c ServerConfig) ([]Warning, error) {
	tw, err := c.TLS.Validate()
	if err != nil {
		return nil, fmt.Errorf("edge: server TLS: %w", err)
	}
	aw, err := c.Auth.Validate()
	if err != nil {
		return nil, fmt.Errorf("edge: server auth: %w", err)
	}
	if err := CheckServer(c); err != nil {
		return nil, err
	}
	return warnings(tw, aw), nil
}

// ValidateClient validates both low-level blocks, returns their warnings, and
// enforces policy for a TLS-block-selected transport such as gRPC.
func ValidateClient(c ClientConfig) ([]Warning, error) {
	tw, aw, err := validateClientBlocks(c)
	if err != nil {
		return nil, err
	}
	if err := CheckClient(c); err != nil {
		return nil, err
	}
	return warnings(tw, aw), nil
}

// ValidateHTTPClient validates both low-level blocks, returns their warnings,
// and enforces policy against the target URL scheme.
func ValidateHTTPClient(c ClientConfig) ([]Warning, error) {
	tw, aw, err := validateClientBlocks(c)
	if err != nil {
		return nil, err
	}
	if err := CheckHTTPClient(c); err != nil {
		return nil, err
	}
	return warnings(tw, aw), nil
}

func validateClientBlocks(c ClientConfig) ([]tlsconf.Warning, []bearer.Warning, error) {
	tw, err := c.TLS.Validate()
	if err != nil {
		return nil, nil, fmt.Errorf("edge: client TLS: %w", err)
	}
	aw, err := c.Auth.Validate()
	if err != nil {
		return nil, nil, fmt.Errorf("edge: client auth: %w", err)
	}
	return tw, aw, nil
}

func checkPlaintext(kind, address string, secure, auth, insecure, dangerBearer bool) error {
	if secure {
		if insecure {
			return errorsf("%s %q enables TLS and insecure plaintext opt-in", kind, address)
		}
		if dangerBearer {
			return errorsf("%s %q enables TLS and plaintext bearer opt-in", kind, address)
		}
		return nil
	}
	if dangerBearer && !auth {
		return errorsf("%s %q enables plaintext bearer opt-in without bearer auth", kind, address)
	}
	if auth && !dangerBearer {
		return errorsf("%s %q would use bearer auth over plaintext; set danger_allow_bearer_over_plaintext: true to accept credential exposure", kind, address)
	}
	if !literalLoopback(address) && !insecure {
		return errorsf("%s %q is not a literal loopback address; enable TLS or set insecure: true", kind, address)
	}
	return nil
}

func parseHTTPURL(target string) (*url.URL, error) {
	u, err := url.Parse(target)
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return nil, errorsf("client target %q must be an absolute http or https URL", target)
	}
	return u, nil
}

func literalLoopback(address string) bool {
	address = strings.TrimSpace(address)
	if address == "" {
		return false
	}
	if strings.Contains(address, "://") {
		u, err := url.Parse(address)
		if err != nil || u.Host == "" {
			return false
		}
		address = u.Hostname()
	} else if host, _, err := net.SplitHostPort(address); err == nil {
		address = host
	}
	address = strings.TrimPrefix(strings.TrimSuffix(address, "]"), "[")
	ip := net.ParseIP(address)
	return ip != nil && ip.IsLoopback()
}

func serverTLSEnabled(c *tlsconf.ServerConfig) bool {
	return c != nil && c.Enabled
}

func clientTLSEnabled(c *tlsconf.ClientConfig) bool {
	return c != nil && c.Enabled
}

func serverAuthEnabled(c *bearer.ServerConfig) bool {
	return c != nil && len(c.Bearer) != 0
}

func clientAuthEnabled(c *bearer.ClientConfig) bool {
	return c != nil && (c.Token != "" || c.TokenFile != "" || c.TokenEnv != "")
}

func warnings(tw []tlsconf.Warning, aw []bearer.Warning) []Warning {
	out := make([]Warning, 0, len(tw)+len(aw))
	for _, w := range tw {
		out = append(out, Warning("tls: "+string(w)))
	}
	for _, w := range aw {
		out = append(out, Warning("auth: "+string(w)))
	}
	return out
}

func errorsf(format string, args ...any) error {
	return fmt.Errorf("edge: "+format, args...)
}
