package tlsconf_test

import (
	"crypto/tls"
	"crypto/x509"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/yaop-labs/reef/reeftest"
	"github.com/yaop-labs/reef/tlsconf"
)

func TestServerValidate(t *testing.T) {
	certs := reeftest.GenCerts(t, t.TempDir())

	tests := []struct {
		name    string
		cfg     *tlsconf.ServerConfig
		wantErr string
	}{
		{name: "nil ok", cfg: nil},
		{name: "empty disabled ok", cfg: &tlsconf.ServerConfig{}},
		{
			name:    "fields without enabled",
			cfg:     &tlsconf.ServerConfig{CertFile: certs.ServerCert, KeyFile: certs.ServerKey},
			wantErr: "enabled is false",
		},
		{
			name:    "enabled without key",
			cfg:     &tlsconf.ServerConfig{Enabled: true, CertFile: certs.ServerCert},
			wantErr: "cert_file and key_file",
		},
		{
			name:    "bad min version",
			cfg:     &tlsconf.ServerConfig{Enabled: true, CertFile: certs.ServerCert, KeyFile: certs.ServerKey, MinVersion: "1.1"},
			wantErr: "min_version",
		},
		{
			name:    "unreadable cert",
			cfg:     &tlsconf.ServerConfig{Enabled: true, CertFile: "/nonexistent.crt", KeyFile: certs.ServerKey},
			wantErr: "load cert/key",
		},
		{
			name: "happy",
			cfg:  &tlsconf.ServerConfig{Enabled: true, CertFile: certs.ServerCert, KeyFile: certs.ServerKey},
		},
		{
			name: "happy mtls",
			cfg:  &tlsconf.ServerConfig{Enabled: true, CertFile: certs.ServerCert, KeyFile: certs.ServerKey, ClientCAFile: certs.CACert},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := tt.cfg.Validate()
			checkErr(t, err, tt.wantErr)
		})
	}
}

func TestClientValidate(t *testing.T) {
	certs := reeftest.GenCerts(t, t.TempDir())

	tests := []struct {
		name    string
		cfg     *tlsconf.ClientConfig
		wantErr string
	}{
		{name: "nil ok", cfg: nil},
		{
			name:    "fields without enabled",
			cfg:     &tlsconf.ClientConfig{CAFile: certs.CACert},
			wantErr: "enabled is false",
		},
		{
			name:    "skip verify without danger",
			cfg:     &tlsconf.ClientConfig{Enabled: true, InsecureSkipVerify: true},
			wantErr: "danger_accept_any",
		},
		{
			name:    "cert without key",
			cfg:     &tlsconf.ClientConfig{Enabled: true, CertFile: certs.ClientCert},
			wantErr: "set together",
		},
		{
			name: "happy",
			cfg:  &tlsconf.ClientConfig{Enabled: true, CAFile: certs.CACert, CertFile: certs.ClientCert, KeyFile: certs.ClientKey},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := tt.cfg.Validate()
			checkErr(t, err, tt.wantErr)
		})
	}
}

func TestKeyPermissionWarning(t *testing.T) {
	certs := reeftest.GenCerts(t, t.TempDir())
	if err := os.Chmod(certs.ServerKey, 0o644); err != nil {
		t.Fatal(err)
	}
	warns, err := (&tlsconf.ServerConfig{Enabled: true, CertFile: certs.ServerCert, KeyFile: certs.ServerKey}).Validate()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(warns) != 1 || !strings.Contains(string(warns[0]), "0644") {
		t.Fatalf("want one 0644 permissions warning, got %v", warns)
	}
}

func TestHandshake(t *testing.T) {
	certs := reeftest.GenCerts(t, t.TempDir())

	srv := newTLSServer(t, &tlsconf.ServerConfig{Enabled: true, CertFile: certs.ServerCert, KeyFile: certs.ServerKey})
	defer srv.Close()

	client, err := newClient(&tlsconf.ClientConfig{Enabled: true, CAFile: certs.CACert, ServerName: "localhost"})
	if err != nil {
		t.Fatal(err)
	}
	mustGet(t, client, srv.URL)
}

func TestMutualTLS(t *testing.T) {
	certs := reeftest.GenCerts(t, t.TempDir())

	srv := newTLSServer(t, &tlsconf.ServerConfig{
		Enabled: true, CertFile: certs.ServerCert, KeyFile: certs.ServerKey, ClientCAFile: certs.CACert,
	})
	defer srv.Close()

	// Without a client certificate the handshake must fail.
	bare, err := newClient(&tlsconf.ClientConfig{Enabled: true, CAFile: certs.CACert, ServerName: "localhost"})
	if err != nil {
		t.Fatal(err)
	}
	if resp, err := bare.Get(srv.URL); err == nil {
		resp.Body.Close()
		t.Fatal("expected handshake failure without client certificate")
	}

	full, err := newClient(&tlsconf.ClientConfig{
		Enabled: true, CAFile: certs.CACert, ServerName: "localhost", CertFile: certs.ClientCert, KeyFile: certs.ClientKey,
	})
	if err != nil {
		t.Fatal(err)
	}
	mustGet(t, full, srv.URL)
}

func TestMinVersionEnforced(t *testing.T) {
	certs := reeftest.GenCerts(t, t.TempDir())

	srv := newTLSServer(t, &tlsconf.ServerConfig{Enabled: true, CertFile: certs.ServerCert, KeyFile: certs.ServerKey})
	defer srv.Close()

	pem, err := os.ReadFile(certs.CACert)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(pem)

	old := &http.Client{Transport: &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: pool, MaxVersion: tls.VersionTLS12},
	}}
	if resp, err := old.Get(srv.URL); err == nil {
		resp.Body.Close()
		t.Fatal("expected TLS 1.2 client to be rejected by the 1.3-only server")
	}
}

func TestPlaintextPassthrough(t *testing.T) {
	cfg, err := tlsconf.Server(nil)
	if err != nil || cfg != nil {
		t.Fatalf("nil config: want (nil, nil), got (%v, %v)", cfg, err)
	}
	ccfg, err := tlsconf.Client(&tlsconf.ClientConfig{})
	if err != nil || ccfg != nil {
		t.Fatalf("disabled config: want (nil, nil), got (%v, %v)", ccfg, err)
	}
	if _, err := tlsconf.Server(&tlsconf.ServerConfig{CertFile: "x"}); err == nil {
		t.Fatal("Server must reject fields with enabled: false")
	}
}

func TestClientDisabledWithFields(t *testing.T) {
	_, err := tlsconf.Client(&tlsconf.ClientConfig{CAFile: "/some/ca.crt"})
	if err == nil || !strings.Contains(err.Error(), "enabled is false") {
		t.Fatalf("Client must reject fields with enabled: false, got %v", err)
	}
}

func TestSkipVerifyMismatch(t *testing.T) {
	// danger_accept_any set without insecure_skip_verify is just as invalid as
	// the reverse: both halves of the opt-out must be present.
	_, err := tlsconf.Client(&tlsconf.ClientConfig{Enabled: true, DangerAcceptAny: true})
	if err == nil || !strings.Contains(err.Error(), "danger_accept_any") {
		t.Fatalf("want danger_accept_any error, got %v", err)
	}
}

func TestBadCAFile(t *testing.T) {
	junk := filepath.Join(t.TempDir(), "not-a-ca.pem")
	if err := os.WriteFile(junk, []byte("definitely not pem"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := (&tlsconf.ClientConfig{Enabled: true, CAFile: junk}).Validate(); err == nil ||
		!strings.Contains(err.Error(), "no certificates") {
		t.Fatalf("want no-certificates error for client CA, got %v", err)
	}
	certs := reeftest.GenCerts(t, t.TempDir())
	if _, err := (&tlsconf.ServerConfig{
		Enabled: true, CertFile: certs.ServerCert, KeyFile: certs.ServerKey, ClientCAFile: junk,
	}).Validate(); err == nil || !strings.Contains(err.Error(), "no certificates") {
		t.Fatalf("want no-certificates error for server client-CA, got %v", err)
	}
}

func TestMinVersion12OptDown(t *testing.T) {
	certs := reeftest.GenCerts(t, t.TempDir())
	srv := newTLSServer(t, &tlsconf.ServerConfig{
		Enabled: true, CertFile: certs.ServerCert, KeyFile: certs.ServerKey, MinVersion: "1.2",
	})
	defer srv.Close()

	// A TLS 1.2 client is accepted when the server opts down to 1.2.
	pool := x509.NewCertPool()
	pem, err := os.ReadFile(certs.CACert)
	if err != nil {
		t.Fatal(err)
	}
	pool.AppendCertsFromPEM(pem)
	client := &http.Client{Transport: &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: pool, ServerName: "localhost", MaxVersion: tls.VersionTLS12},
	}}
	mustGet(t, client, srv.URL)
}

func TestWarnIfPlaintext(t *testing.T) {
	var buf strings.Builder
	log := slog.New(slog.NewTextHandler(&buf, nil))

	tlsconf.WarnIfPlaintext(log, "otlp-receiver", true)
	if buf.Len() != 0 {
		t.Fatalf("no warning expected when the edge is encrypted, got %q", buf.String())
	}
	tlsconf.WarnIfPlaintext(log, "otlp-receiver", false)
	if !strings.Contains(buf.String(), "otlp-receiver") || !strings.Contains(buf.String(), "plaintext") {
		t.Fatalf("expected a plaintext warning naming the edge, got %q", buf.String())
	}
	// A nil logger must be a no-op, not a panic.
	tlsconf.WarnIfPlaintext(nil, "otlp-receiver", false)
}

func newTLSServer(t *testing.T, cfg *tlsconf.ServerConfig) *httptest.Server {
	t.Helper()
	tlsCfg, err := tlsconf.Server(cfg)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "ok")
	}))
	srv.TLS = tlsCfg
	srv.StartTLS()
	return srv
}

func newClient(cfg *tlsconf.ClientConfig) (*http.Client, error) {
	tlsCfg, err := tlsconf.Client(cfg)
	if err != nil {
		return nil, err
	}
	return &http.Client{Transport: &http.Transport{TLSClientConfig: tlsCfg}}, nil
}

func mustGet(t *testing.T, c *http.Client, url string) {
	t.Helper()
	resp, err := c.Get(url)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET %s: status %d", url, resp.StatusCode)
	}
}

func checkErr(t *testing.T, err error, want string) {
	t.Helper()
	if want == "" {
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		return
	}
	if err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("want error containing %q, got %v", want, err)
	}
}
