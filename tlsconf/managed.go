package tlsconf

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/yaop-labs/reef/credential"
)

// Lifecycle configures background reload for file-backed TLS material.
type Lifecycle struct {
	Interval time.Duration
	Observer credential.Observer
}

// ManagedServer is a server TLS config plus its owned credential lifecycle.
type ManagedServer struct {
	Config      *tls.Config
	Warnings    []Warning
	Credentials *credential.Group
}

// Close stops all background credential reload.
func (m *ManagedServer) Close() error {
	if m == nil {
		return nil
	}
	return m.Credentials.Close()
}

// MaterializeServer builds provider-aware server TLS. New handshakes observe
// rotated leaf certificates and client-CA pools.
func MaterializeServer(c *ServerConfig, lifecycle Lifecycle) (*ManagedServer, error) {
	if err := c.checkFields(); err != nil {
		return nil, err
	}
	result := &ManagedServer{Credentials: credential.NewGroup()}
	if c == nil || !c.Enabled {
		return result, nil
	}

	leaf, err := newLeafManager(
		"server-leaf",
		credential.KindServerLeaf,
		c.CertFile,
		c.KeyFile,
		lifecycle,
	)
	if err != nil {
		return nil, fmt.Errorf("tlsconf: load cert/key pair: %w", err)
	}
	if err := result.Credentials.Add(leaf); err != nil {
		_ = leaf.Close()
		return nil, err
	}

	minV, err := minVersion(c.MinVersion)
	if err != nil {
		_ = result.Close()
		return nil, err
	}
	cfg := &tls.Config{
		MinVersion: minV,
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
			return leaf.Current(), nil
		},
	}

	if c.ClientCAFile != "" {
		clientCA, err := newCAManager(
			"server-client-ca",
			credential.KindServerCA,
			c.ClientCAFile,
			lifecycle,
		)
		if err != nil {
			_ = result.Close()
			return nil, err
		}
		if err := result.Credentials.Add(clientCA); err != nil {
			_ = clientCA.Close()
			_ = result.Close()
			return nil, err
		}
		cfg.ClientAuth = tls.RequireAndVerifyClientCert
		cfg.ClientCAs = clientCA.Current()
		cfg.GetConfigForClient = func(*tls.ClientHelloInfo) (*tls.Config, error) {
			current := cfg.Clone()
			current.GetConfigForClient = nil
			current.ClientCAs = clientCA.Current()
			return current, nil
		}
	}

	result.Config = cfg
	result.Warnings = permWarnings(c.KeyFile)
	return result, nil
}

// ClientProvider creates a fresh TLS config for each target/handshake while
// retaining references to the latest managed CA and leaf generations.
type ClientProvider struct {
	base  *tls.Config
	roots *credential.Managed[*x509.CertPool]
}

// ConfigForServer returns a TLS config that verifies serverName against the
// latest root-CA generation. An explicit config server_name takes precedence.
func (p *ClientProvider) ConfigForServer(serverName string) *tls.Config {
	if p == nil {
		return nil
	}
	cfg := p.base.Clone()
	if cfg.ServerName == "" {
		cfg.ServerName = serverName
	}
	if p.roots != nil && !cfg.InsecureSkipVerify {
		verifyName := cfg.ServerName
		cfg.InsecureSkipVerify = true // verification is performed below with current roots
		cfg.VerifyConnection = func(state tls.ConnectionState) error {
			return verifyServer(state, p.roots.Current(), verifyName)
		}
	}
	return cfg
}

// ManagedClient is a provider plus its owned credential lifecycle.
type ManagedClient struct {
	Provider    *ClientProvider
	Warnings    []Warning
	Credentials *credential.Group
}

// Close stops all background credential reload.
func (m *ManagedClient) Close() error {
	if m == nil {
		return nil
	}
	return m.Credentials.Close()
}

// MaterializeClient builds provider-aware client TLS. New handshakes observe
// rotated root CAs and client leaf certificates.
func MaterializeClient(c *ClientConfig, lifecycle Lifecycle) (*ManagedClient, error) {
	if err := c.checkFields(); err != nil {
		return nil, err
	}
	result := &ManagedClient{Credentials: credential.NewGroup()}
	if c == nil || !c.Enabled {
		return result, nil
	}

	provider := &ClientProvider{base: &tls.Config{
		MinVersion: tls.VersionTLS13,
		ServerName: c.ServerName,
	}}
	if c.CAFile != "" {
		roots, err := newCAManager(
			"client-root-ca",
			credential.KindClientCA,
			c.CAFile,
			lifecycle,
		)
		if err != nil {
			return nil, err
		}
		if err := result.Credentials.Add(roots); err != nil {
			_ = roots.Close()
			return nil, err
		}
		provider.roots = roots
		provider.base.RootCAs = roots.Current()
	}
	if c.CertFile != "" {
		leaf, err := newLeafManager(
			"client-leaf",
			credential.KindClientLeaf,
			c.CertFile,
			c.KeyFile,
			lifecycle,
		)
		if err != nil {
			_ = result.Close()
			return nil, fmt.Errorf("tlsconf: load client cert/key pair: %w", err)
		}
		if err := result.Credentials.Add(leaf); err != nil {
			_ = leaf.Close()
			_ = result.Close()
			return nil, err
		}
		provider.base.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
			return leaf.Current(), nil
		}
	}
	if c.InsecureSkipVerify && c.DangerAcceptAny {
		provider.base.InsecureSkipVerify = true
	}

	result.Provider = provider
	if c.KeyFile != "" {
		result.Warnings = permWarnings(c.KeyFile)
	}
	return result, nil
}

func newLeafManager(
	name string,
	kind credential.Kind,
	certFile string,
	keyFile string,
	lifecycle Lifecycle,
) (*credential.Managed[*tls.Certificate], error) {
	return credential.NewManaged(credential.Options{
		Name: name, Kind: kind, Interval: lifecycle.Interval, Observer: lifecycle.Observer,
	}, func() (*tls.Certificate, credential.Metadata, error) {
		certPEM, err := os.ReadFile(certFile)
		if err != nil {
			return nil, credential.Metadata{}, fmt.Errorf("read certificate file %s: %w", certFile, err)
		}
		keyPEM, err := os.ReadFile(keyFile)
		if err != nil {
			return nil, credential.Metadata{}, fmt.Errorf("read key file %s: %w", keyFile, err)
		}
		pair, err := tls.X509KeyPair(certPEM, keyPEM)
		if err != nil {
			return nil, credential.Metadata{}, fmt.Errorf("parse certificate/key pair: %w", err)
		}
		if len(pair.Certificate) == 0 {
			return nil, credential.Metadata{}, errors.New("certificate chain is empty")
		}
		leaf, err := x509.ParseCertificate(pair.Certificate[0])
		if err != nil {
			return nil, credential.Metadata{}, fmt.Errorf("parse leaf certificate: %w", err)
		}
		pair.Leaf = leaf
		hash := sha256.New()
		_, _ = hash.Write(certPEM)
		_, _ = hash.Write([]byte{0})
		_, _ = hash.Write(keyPEM)
		var fingerprint [sha256.Size]byte
		copy(fingerprint[:], hash.Sum(nil))
		return &pair, credential.Metadata{
			Fingerprint: fingerprint,
			NotBefore:   leaf.NotBefore,
			NotAfter:    leaf.NotAfter,
		}, nil
	})
}

func newCAManager(
	name string,
	kind credential.Kind,
	path string,
	lifecycle Lifecycle,
) (*credential.Managed[*x509.CertPool], error) {
	return credential.NewManaged(credential.Options{
		Name: name, Kind: kind, Interval: lifecycle.Interval, Observer: lifecycle.Observer,
	}, func() (*x509.CertPool, credential.Metadata, error) {
		pem, err := os.ReadFile(path)
		if err != nil {
			return nil, credential.Metadata{}, fmt.Errorf("read CA file %s: %w", path, err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, credential.Metadata{}, fmt.Errorf("no certificates found in %s", path)
		}
		return pool, credential.Metadata{Fingerprint: sha256.Sum256(pem)}, nil
	})
}

func verifyServer(state tls.ConnectionState, roots *x509.CertPool, serverName string) error {
	if len(state.PeerCertificates) == 0 {
		return errors.New("tlsconf: server sent no certificates")
	}
	intermediates := x509.NewCertPool()
	for _, cert := range state.PeerCertificates[1:] {
		intermediates.AddCert(cert)
	}
	_, err := state.PeerCertificates[0].Verify(x509.VerifyOptions{
		DNSName:       serverName,
		Roots:         roots,
		Intermediates: intermediates,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	})
	if err != nil {
		return fmt.Errorf("tlsconf: verify server certificate: %w", err)
	}
	return nil
}
