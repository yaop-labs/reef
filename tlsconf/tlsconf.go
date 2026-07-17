// Package tlsconf builds server- and client-side *tls.Config values from the
// shared tls YAML config block.
//
// Fail-stop rule: a block with fields set but enabled: false is a startup
// error, never a silent plaintext edge. A fully empty/nil block is deliberate
// plaintext (dev mode); callers must announce it via WarnIfPlaintext.
package tlsconf

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"os"
)

// Warning is a non-fatal validation finding (e.g. a key file readable by
// group/other). The product decides whether to log it or refuse to start.
type Warning string

// ServerConfig is the `tls:` block of a receiver.
type ServerConfig struct {
	Enabled      bool   `yaml:"enabled"`
	CertFile     string `yaml:"cert_file"`
	KeyFile      string `yaml:"key_file"`
	ClientCAFile string `yaml:"client_ca_file"`
	MinVersion   string `yaml:"min_version"`
}

// ClientConfig is the `tls:` block of an exporter/client.
type ClientConfig struct {
	Enabled            bool   `yaml:"enabled"`
	CAFile             string `yaml:"ca_file"`
	CertFile           string `yaml:"cert_file"`
	KeyFile            string `yaml:"key_file"`
	ServerName         string `yaml:"server_name"`
	InsecureSkipVerify bool   `yaml:"insecure_skip_verify"`
	DangerAcceptAny    bool   `yaml:"danger_accept_any"`
}

// checkFields validates the server block's structure without touching the
// filesystem, so Server can share the checks without a redundant I/O pass.
func (c *ServerConfig) checkFields() error {
	if c == nil {
		return nil
	}
	if !c.Enabled {
		if c.CertFile != "" || c.KeyFile != "" || c.ClientCAFile != "" || c.MinVersion != "" {
			return errors.New("tlsconf: tls fields are set but enabled is false; set enabled: true or remove the fields")
		}
		return nil
	}
	if c.CertFile == "" || c.KeyFile == "" {
		return errors.New("tlsconf: enabled tls requires both cert_file and key_file")
	}
	if _, err := minVersion(c.MinVersion); err != nil {
		return err
	}
	return nil
}

// Validate checks the server block. nil-safe.
func (c *ServerConfig) Validate() ([]Warning, error) {
	if err := c.checkFields(); err != nil {
		return nil, err
	}
	if c == nil || !c.Enabled {
		return nil, nil
	}
	if _, err := tls.LoadX509KeyPair(c.CertFile, c.KeyFile); err != nil {
		return nil, fmt.Errorf("tlsconf: load cert/key pair: %w", err)
	}
	if c.ClientCAFile != "" {
		if _, err := loadCertPool(c.ClientCAFile); err != nil {
			return nil, err
		}
	}
	return permWarnings(c.KeyFile), nil
}

// checkFields validates the client block's structure without touching the
// filesystem, so Client can share the checks without a redundant I/O pass.
func (c *ClientConfig) checkFields() error {
	if c == nil {
		return nil
	}
	if !c.Enabled {
		if c.CAFile != "" || c.CertFile != "" || c.KeyFile != "" || c.ServerName != "" ||
			c.InsecureSkipVerify || c.DangerAcceptAny {
			return errors.New("tlsconf: tls fields are set but enabled is false; set enabled: true or remove the fields")
		}
		return nil
	}
	if c.InsecureSkipVerify != c.DangerAcceptAny {
		return errors.New("tlsconf: insecure_skip_verify requires danger_accept_any: true (and vice versa)")
	}
	if (c.CertFile == "") != (c.KeyFile == "") {
		return errors.New("tlsconf: cert_file and key_file must be set together")
	}
	return nil
}

// Validate checks the client block. nil-safe.
func (c *ClientConfig) Validate() ([]Warning, error) {
	if err := c.checkFields(); err != nil {
		return nil, err
	}
	if c == nil || !c.Enabled {
		return nil, nil
	}
	if c.CertFile != "" {
		if _, err := tls.LoadX509KeyPair(c.CertFile, c.KeyFile); err != nil {
			return nil, fmt.Errorf("tlsconf: load client cert/key pair: %w", err)
		}
	}
	if c.CAFile != "" {
		if _, err := loadCertPool(c.CAFile); err != nil {
			return nil, err
		}
	}
	var warns []Warning
	if c.KeyFile != "" {
		warns = permWarnings(c.KeyFile)
	}
	return warns, nil
}

// Server builds the listener-side *tls.Config. Returns (nil, nil) for a nil or
// disabled block: the caller serves plaintext and must call WarnIfPlaintext.
// The certificate is served through GetCertificate and hot-reloads when the
// cert/key files change on disk (see certReloader), so rotation needs no
// restart.
func Server(c *ServerConfig) (*tls.Config, error) {
	cfg, _, err := BuildServer(c)
	return cfg, err
}

// BuildServer materializes the listener TLS config and permission warnings in
// one filesystem pass.
func BuildServer(c *ServerConfig) (*tls.Config, []Warning, error) {
	if err := c.checkFields(); err != nil {
		return nil, nil, err
	}
	if c == nil || !c.Enabled {
		return nil, nil, nil
	}
	reloader, err := newCertReloader(c.CertFile, c.KeyFile)
	if err != nil {
		return nil, nil, fmt.Errorf("tlsconf: load cert/key pair: %w", err)
	}
	minV, err := minVersion(c.MinVersion)
	if err != nil {
		return nil, nil, err
	}
	cfg := &tls.Config{
		MinVersion: minV,
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
			return reloader.get(), nil
		},
	}
	if c.ClientCAFile != "" {
		pool, err := loadCertPool(c.ClientCAFile)
		if err != nil {
			return nil, nil, err
		}
		cfg.ClientCAs = pool
		cfg.ClientAuth = tls.RequireAndVerifyClientCert
	}
	return cfg, permWarnings(c.KeyFile), nil
}

// Client builds the dialer-side *tls.Config. Returns (nil, nil) for a nil or
// disabled block (plaintext dial).
func Client(c *ClientConfig) (*tls.Config, error) {
	cfg, _, err := BuildClient(c)
	return cfg, err
}

// BuildClient materializes the dialer TLS config and permission warnings in
// one filesystem pass.
func BuildClient(c *ClientConfig) (*tls.Config, []Warning, error) {
	if err := c.checkFields(); err != nil {
		return nil, nil, err
	}
	if c == nil || !c.Enabled {
		return nil, nil, nil
	}
	cfg := &tls.Config{
		MinVersion: tls.VersionTLS13,
		ServerName: c.ServerName,
	}
	if c.CAFile != "" {
		pool, err := loadCertPool(c.CAFile)
		if err != nil {
			return nil, nil, err
		}
		cfg.RootCAs = pool
	}
	if c.CertFile != "" {
		reloader, err := newCertReloader(c.CertFile, c.KeyFile)
		if err != nil {
			return nil, nil, fmt.Errorf("tlsconf: load client cert/key pair: %w", err)
		}
		cfg.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
			return reloader.get(), nil
		}
	}
	if c.InsecureSkipVerify && c.DangerAcceptAny {
		cfg.InsecureSkipVerify = true
	}
	var warns []Warning
	if c.KeyFile != "" {
		warns = permWarnings(c.KeyFile)
	}
	return cfg, warns, nil
}

// WarnIfPlaintext logs exactly one warning when an edge runs without TLS.
// edge names the edge in product terms: "otlp-receiver", "amber-exporter".
func WarnIfPlaintext(log *slog.Logger, edge string, enabled bool) {
	if enabled || log == nil {
		return
	}
	log.Warn("reef: edge is plaintext", "edge", edge)
}

func minVersion(s string) (uint16, error) {
	switch s {
	case "", "1.3":
		return tls.VersionTLS13, nil
	case "1.2":
		return tls.VersionTLS12, nil
	default:
		return 0, fmt.Errorf("tlsconf: min_version must be \"1.2\" or \"1.3\", got %q", s)
	}
}

func loadCertPool(path string) (*x509.CertPool, error) {
	pem, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("tlsconf: read CA file: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("tlsconf: no certificates found in %s", path)
	}
	return pool, nil
}

func permWarnings(keyFile string) []Warning {
	info, err := os.Stat(keyFile)
	if err != nil {
		return nil // unreadable files are caught by Validate as errors
	}
	if perm := info.Mode().Perm(); perm&0o077 != 0 {
		return []Warning{Warning(fmt.Sprintf("key file %s has permissions %04o; tighten to 0600", keyFile, perm))}
	}
	return nil
}
