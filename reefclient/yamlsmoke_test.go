package reefclient_test

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/yaop-labs/reef/bearer"
	"github.com/yaop-labs/reef/reefclient"
	"github.com/yaop-labs/reef/reeftest"
	"github.com/yaop-labs/reef/tlsconf"
)

// serverYAML is the receiver's config as a product embeds it: reef's tls/auth
// blocks under their documented keys (docs/03-api.md).
type serverYAML struct {
	TLS  tlsconf.ServerConfig `yaml:"tls"`
	Auth bearer.ServerConfig  `yaml:"auth"`
}

// TestYAMLConfigSmoke parses the exact schema from docs/03-api.md into reef's
// structs and drives a full HTTP edge end-to-end. It proves the yaml tags match
// the documented contract (a tag typo would fail here and nowhere else) and
// that a tokenless client is refused.
func TestYAMLConfigSmoke(t *testing.T) {
	certs := reeftest.GenCerts(t, t.TempDir())
	const secret = "yaml-smoke-s3cr3t"
	tokenFile := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(tokenFile, []byte(secret+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	serverDoc := fmt.Sprintf(`
tls:
  enabled: true
  cert_file: %s
  key_file: %s
  min_version: "1.3"
auth:
  bearer:
    - name: wisp-agents
      token_file: %s
`, certs.ServerCert, certs.ServerKey, tokenFile)

	var sy serverYAML
	if err := yaml.Unmarshal([]byte(serverDoc), &sy); err != nil {
		t.Fatalf("server YAML: %v", err)
	}

	tlsCfg, err := tlsconf.Server(&sy.TLS)
	if err != nil {
		t.Fatal(err)
	}
	mw, err := bearer.Require(&sy.Auth)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewUnstartedServer(mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "ok")
	})))
	srv.TLS = tlsCfg
	srv.StartTLS()
	defer srv.Close()

	clientDoc := fmt.Sprintf(`
tls:
  enabled: true
  ca_file: %s
  server_name: localhost
auth:
  token_file: %s
`, certs.CACert, tokenFile)

	var cc reefclient.Config
	if err := yaml.Unmarshal([]byte(clientDoc), &cc); err != nil {
		t.Fatalf("client YAML: %v", err)
	}
	rt, err := reefclient.Transport(cc)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := (&http.Client{Transport: rt}).Get(srv.URL + "/v1/metrics-not-exempt")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("reef client with token: status %d, want 200", resp.StatusCode)
	}

	// A stranger presenting no token is refused.
	strangerTLS, err := tlsconf.Client(&tlsconf.ClientConfig{Enabled: true, CAFile: certs.CACert, ServerName: "localhost"})
	if err != nil {
		t.Fatal(err)
	}
	stranger := &http.Client{Transport: &http.Transport{TLSClientConfig: strangerTLS}}
	resp2, err := stranger.Get(srv.URL + "/v1/metrics-not-exempt")
	if err != nil {
		t.Fatal(err)
	}
	resp2.Body.Close()
	if resp2.StatusCode != http.StatusUnauthorized {
		t.Fatalf("tokenless client: status %d, want 401", resp2.StatusCode)
	}
}
