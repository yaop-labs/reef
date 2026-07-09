package grpcreef_test

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/yaop-labs/reef/bearer"
	"github.com/yaop-labs/reef/reeftest"
	"github.com/yaop-labs/reef/tlsconf"
)

type serverYAML struct {
	TLS  tlsconf.ServerConfig `yaml:"tls"`
	Auth bearer.ServerConfig  `yaml:"auth"`
}

type clientYAML struct {
	TLS  tlsconf.ClientConfig `yaml:"tls"`
	Auth bearer.ClientConfig  `yaml:"auth"`
}

// TestYAMLConfigSmoke drives a gRPC edge configured entirely from the YAML
// schema: a token-bearing client is served, a tokenless one gets Unauthenticated.
func TestYAMLConfigSmoke(t *testing.T) {
	certs := reeftest.GenCerts(t, t.TempDir())
	const secret = "grpc-yaml-s3cr3t"
	tokenFile := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(tokenFile, []byte(secret), 0o600); err != nil {
		t.Fatal(err)
	}

	serverDoc := fmt.Sprintf(`
tls:
  enabled: true
  cert_file: %s
  key_file: %s
auth:
  bearer:
    - name: coral
      token_file: %s
`, certs.ServerCert, certs.ServerKey, tokenFile)
	var sy serverYAML
	if err := yaml.Unmarshal([]byte(serverDoc), &sy); err != nil {
		t.Fatalf("server YAML: %v", err)
	}
	ln := startServer(t, &sy.TLS, &sy.Auth)

	clientDoc := fmt.Sprintf(`
tls:
  enabled: true
  ca_file: %s
  server_name: localhost
auth:
  token_file: %s
`, certs.CACert, tokenFile)
	var cy clientYAML
	if err := yaml.Unmarshal([]byte(clientDoc), &cy); err != nil {
		t.Fatalf("client YAML: %v", err)
	}

	if err := check(dial(t, ln, &cy.TLS, &cy.Auth)); err != nil {
		t.Fatalf("yaml-configured client failed: %v", err)
	}
	wantUnauthenticated(t, check(dial(t, ln, &cy.TLS, nil)))
}
