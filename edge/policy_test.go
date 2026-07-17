package edge_test

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/yaop-labs/reef/bearer"
	"github.com/yaop-labs/reef/edge"
	"github.com/yaop-labs/reef/reeftest"
	"github.com/yaop-labs/reef/tlsconf"
)

func TestServerPolicyMatrix(t *testing.T) {
	auth := &bearer.ServerConfig{Bearer: []bearer.Key{{Name: "agent", Token: "secret"}}}
	tls := &tlsconf.ServerConfig{Enabled: true}

	tests := []struct {
		name    string
		cfg     edge.ServerConfig
		wantErr string
	}{
		{name: "ipv4 loopback plaintext", cfg: edge.ServerConfig{Bind: "127.0.0.1:4317"}},
		{name: "ipv6 loopback plaintext", cfg: edge.ServerConfig{Bind: "[::1]:4317"}},
		{
			name:    "loopback bearer plaintext rejected",
			cfg:     edge.ServerConfig{Bind: "127.0.0.1:4317", Auth: auth},
			wantErr: "bearer auth over plaintext",
		},
		{
			name: "loopback bearer explicit danger",
			cfg: edge.ServerConfig{
				Bind:                           "127.0.0.1:4317",
				Auth:                           auth,
				DangerAllowBearerOverPlaintext: true,
			},
		},
		{
			name:    "external plaintext rejected",
			cfg:     edge.ServerConfig{Bind: "192.0.2.10:4317"},
			wantErr: "not a literal loopback",
		},
		{
			name: "external plaintext explicit",
			cfg:  edge.ServerConfig{Bind: "192.0.2.10:4317", Insecure: true},
		},
		{
			name: "external bearer plaintext explicit",
			cfg: edge.ServerConfig{
				Bind:                           "192.0.2.10:4317",
				Auth:                           auth,
				Insecure:                       true,
				DangerAllowBearerOverPlaintext: true,
			},
		},
		{
			name: "external bearer still needs insecure",
			cfg: edge.ServerConfig{
				Bind:                           "192.0.2.10:4317",
				Auth:                           auth,
				DangerAllowBearerOverPlaintext: true,
			},
			wantErr: "not a literal loopback",
		},
		{name: "external tls", cfg: edge.ServerConfig{Bind: "0.0.0.0:4317", TLS: tls}},
		{
			name:    "tls contradicts insecure",
			cfg:     edge.ServerConfig{Bind: "0.0.0.0:4317", TLS: tls, Insecure: true},
			wantErr: "TLS and insecure",
		},
		{
			name: "tls contradicts bearer danger",
			cfg: edge.ServerConfig{
				Bind:                           "0.0.0.0:4317",
				TLS:                            tls,
				Auth:                           auth,
				DangerAllowBearerOverPlaintext: true,
			},
			wantErr: "TLS and plaintext bearer",
		},
		{
			name:    "wildcard is ambiguous",
			cfg:     edge.ServerConfig{Bind: ":4317"},
			wantErr: "not a literal loopback",
		},
		{
			name:    "localhost is not inferred",
			cfg:     edge.ServerConfig{Bind: "localhost:4317"},
			wantErr: "not a literal loopback",
		},
		{
			name: "danger without auth",
			cfg: edge.ServerConfig{
				Bind:                           "127.0.0.1:4317",
				DangerAllowBearerOverPlaintext: true,
			},
			wantErr: "without bearer auth",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			checkError(t, edge.CheckServer(tt.cfg), tt.wantErr)
		})
	}
}

func TestClientPolicyMatrix(t *testing.T) {
	auth := &bearer.ClientConfig{Token: "secret"}
	tls := &tlsconf.ClientConfig{Enabled: true}

	tests := []struct {
		name    string
		cfg     edge.ClientConfig
		wantErr string
	}{
		{name: "loopback plaintext", cfg: edge.ClientConfig{Target: "127.0.0.1:4317"}},
		{
			name:    "resolver target is ambiguous",
			cfg:     edge.ClientConfig{Target: "dns:///localhost:4317"},
			wantErr: "not a literal loopback",
		},
		{
			name:    "external plaintext rejected",
			cfg:     edge.ClientConfig{Target: "coral.internal:4317"},
			wantErr: "not a literal loopback",
		},
		{
			name: "external plaintext explicit",
			cfg:  edge.ClientConfig{Target: "coral.internal:4317", Insecure: true},
		},
		{
			name:    "bearer plaintext rejected",
			cfg:     edge.ClientConfig{Target: "127.0.0.1:4317", Auth: auth},
			wantErr: "bearer auth over plaintext",
		},
		{
			name: "external bearer plaintext explicit",
			cfg: edge.ClientConfig{
				Target:                         "coral.internal:4317",
				Auth:                           auth,
				Insecure:                       true,
				DangerAllowBearerOverPlaintext: true,
			},
		},
		{name: "external tls bearer", cfg: edge.ClientConfig{Target: "coral.internal:4317", TLS: tls, Auth: auth}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			checkError(t, edge.CheckClient(tt.cfg), tt.wantErr)
		})
	}
}

func TestHTTPClientPolicy(t *testing.T) {
	auth := &bearer.ClientConfig{Token: "secret"}

	tests := []struct {
		name    string
		cfg     edge.ClientConfig
		wantErr string
	}{
		{
			name: "https with system roots",
			cfg:  edge.ClientConfig{Target: "https://coral.internal:4318", Auth: auth},
		},
		{
			name: "http loopback",
			cfg:  edge.ClientConfig{Target: "http://127.0.0.1:4318"},
		},
		{
			name:    "http bearer rejected",
			cfg:     edge.ClientConfig{Target: "http://127.0.0.1:4318", Auth: auth},
			wantErr: "bearer auth over plaintext",
		},
		{
			name: "http external explicit",
			cfg:  edge.ClientConfig{Target: "http://coral.internal:4318", Insecure: true},
		},
		{
			name: "http bearer explicit danger",
			cfg: edge.ClientConfig{
				Target:                         "http://coral.internal:4318",
				Auth:                           auth,
				Insecure:                       true,
				DangerAllowBearerOverPlaintext: true,
			},
		},
		{
			name:    "http contradicts tls block",
			cfg:     edge.ClientConfig{Target: "http://127.0.0.1:4318", TLS: &tlsconf.ClientConfig{Enabled: true}},
			wantErr: "uses http but TLS is enabled",
		},
		{
			name:    "https contradicts insecure",
			cfg:     edge.ClientConfig{Target: "https://coral.internal:4318", Insecure: true},
			wantErr: "TLS and insecure",
		},
		{
			name:    "relative URL rejected",
			cfg:     edge.ClientConfig{Target: "coral.internal:4318"},
			wantErr: "absolute http or https URL",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			checkError(t, edge.CheckHTTPClient(tt.cfg), tt.wantErr)
		})
	}
}

func TestNewHTTPServerProtectsMetricsByDefault(t *testing.T) {
	certs := reeftest.GenCerts(t, t.TempDir())
	const secret = "edge-secret"

	result, err := edge.NewHTTPServer(edge.ServerConfig{
		Bind: "0.0.0.0:4318",
		TLS: &tlsconf.ServerConfig{
			Enabled:  true,
			CertFile: certs.ServerCert,
			KeyFile:  certs.ServerKey,
		},
		Auth: &bearer.ServerConfig{Bearer: []bearer.Key{{Name: "agent", Token: secret}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = result.Close() })
	if result.TLSConfig == nil {
		t.Fatal("expected materialized TLS config")
	}

	handler := result.Middleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	for _, tt := range []struct {
		path   string
		token  string
		status int
	}{
		{path: "/healthz", status: http.StatusNoContent},
		{path: "/readyz", status: http.StatusNoContent},
		{path: "/metrics", status: http.StatusUnauthorized},
		{path: "/metrics", token: secret, status: http.StatusNoContent},
	} {
		req := httptest.NewRequest(http.MethodGet, tt.path, nil)
		if tt.token != "" {
			req.Header.Set("Authorization", "Bearer "+tt.token)
		}
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != tt.status {
			t.Errorf("%s token=%t: status %d, want %d", tt.path, tt.token != "", rec.Code, tt.status)
		}
	}
}

func TestValidateServerWrapsConfigError(t *testing.T) {
	_, err := edge.ValidateServer(edge.ServerConfig{
		Bind: "127.0.0.1:4317",
		TLS:  &tlsconf.ServerConfig{CertFile: "set-without-enabled"},
	})
	if err == nil || !strings.Contains(err.Error(), "server TLS") {
		t.Fatalf("expected wrapped server TLS error, got %v", err)
	}
}

func TestValidateClientVariants(t *testing.T) {
	if warns, err := edge.ValidateClient(edge.ClientConfig{Target: "127.0.0.1:4317"}); err != nil {
		t.Fatal(err)
	} else if len(warns) != 0 {
		t.Fatalf("unexpected warnings: %v", warns)
	}
	if warns, err := edge.ValidateHTTPClient(edge.ClientConfig{Target: "https://coral.internal:4318"}); err != nil {
		t.Fatal(err)
	} else if len(warns) != 0 {
		t.Fatalf("unexpected warnings: %v", warns)
	}
	_, err := edge.ValidateClient(edge.ClientConfig{
		Target: "127.0.0.1:4317",
		Auth:   &bearer.ClientConfig{Token: "one", TokenEnv: "TWO"},
	})
	if err == nil || !strings.Contains(err.Error(), "client auth") {
		t.Fatalf("expected wrapped client auth error, got %v", err)
	}
}

func TestNewHTTPServerReturnsMaterializationWarnings(t *testing.T) {
	dir := t.TempDir()
	certs := reeftest.GenCerts(t, dir)
	tokenFile := filepath.Join(dir, "token")
	if err := os.WriteFile(tokenFile, []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(certs.ServerKey, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(tokenFile, 0o644); err != nil {
		t.Fatal(err)
	}

	result, err := edge.NewHTTPServer(edge.ServerConfig{
		Bind: "0.0.0.0:4318",
		TLS: &tlsconf.ServerConfig{
			Enabled: true, CertFile: certs.ServerCert, KeyFile: certs.ServerKey,
		},
		Auth: &bearer.ServerConfig{Bearer: []bearer.Key{{
			Name: "agent", TokenFile: tokenFile,
		}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = result.Close() })
	if len(result.Warnings) != 2 {
		t.Fatalf("want TLS and auth warnings, got %v", result.Warnings)
	}
	if !strings.HasPrefix(string(result.Warnings[0]), "tls:") ||
		!strings.HasPrefix(string(result.Warnings[1]), "auth:") {
		t.Fatalf("warnings must retain their layer: %v", result.Warnings)
	}
}

func checkError(t *testing.T, err error, want string) {
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
