package bearer_test

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/yaop-labs/reef/bearer"
)

const secret = "s3cr3t-tok-v41ue"

func serverCfg(keys ...bearer.Key) *bearer.ServerConfig {
	return &bearer.ServerConfig{Bearer: keys}
}

func TestServerValidate(t *testing.T) {
	tokenFile := filepath.Join(t.TempDir(), "tok")
	if err := os.WriteFile(tokenFile, []byte(secret+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("REEF_TEST_TOKEN", secret)

	tests := []struct {
		name    string
		cfg     *bearer.ServerConfig
		wantErr string
	}{
		{name: "nil ok", cfg: nil},
		{name: "empty ok", cfg: serverCfg()},
		{name: "inline ok", cfg: serverCfg(bearer.Key{Name: "a", Token: secret})},
		{name: "file ok", cfg: serverCfg(bearer.Key{Name: "a", TokenFile: tokenFile})},
		{name: "env ok", cfg: serverCfg(bearer.Key{Name: "a", TokenEnv: "REEF_TEST_TOKEN"})},
		{name: "no name", cfg: serverCfg(bearer.Key{Token: secret}), wantErr: "no name"},
		{
			name:    "duplicate name",
			cfg:     serverCfg(bearer.Key{Name: "a", Token: secret}, bearer.Key{Name: "a", Token: "other"}),
			wantErr: "duplicate",
		},
		{name: "no source", cfg: serverCfg(bearer.Key{Name: "a"}), wantErr: "no token source"},
		{
			name:    "two sources",
			cfg:     serverCfg(bearer.Key{Name: "a", Token: secret, TokenFile: tokenFile}),
			wantErr: "multiple token sources",
		},
		{
			name:    "unset env",
			cfg:     serverCfg(bearer.Key{Name: "a", TokenEnv: "REEF_TEST_UNSET"}),
			wantErr: "empty or unset",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := tt.cfg.Validate()
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("want error containing %q, got %v", tt.wantErr, err)
			}
		})
	}
}

func TestTokenFilePermissionWarning(t *testing.T) {
	tokenFile := filepath.Join(t.TempDir(), "tok")
	if err := os.WriteFile(tokenFile, []byte(secret), 0o644); err != nil {
		t.Fatal(err)
	}
	warns, err := serverCfg(bearer.Key{Name: "a", TokenFile: tokenFile}).Validate()
	if err != nil {
		t.Fatal(err)
	}
	if len(warns) != 1 {
		t.Fatalf("want one permissions warning, got %v", warns)
	}
}

func TestRequire(t *testing.T) {
	var failures atomic.Int64
	mw, err := bearer.Require(
		serverCfg(bearer.Key{Name: "main", Token: secret}),
		bearer.OnFailure(func(_, _ string) { failures.Add(1) }),
	)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "ok")
	})))
	defer srv.Close()

	tests := []struct {
		name   string
		path   string
		header string
		want   int
	}{
		{name: "no token", path: "/v1/logs", want: http.StatusUnauthorized},
		{name: "wrong token", path: "/v1/logs", header: "Bearer nope", want: http.StatusUnauthorized},
		{name: "wrong scheme", path: "/v1/logs", header: "Basic " + secret, want: http.StatusUnauthorized},
		{name: "right token", path: "/v1/logs", header: "Bearer " + secret, want: http.StatusOK},
		{name: "case-insensitive scheme", path: "/v1/logs", header: "bearer " + secret, want: http.StatusOK},
		{name: "healthz exempt", path: "/healthz", want: http.StatusOK},
		{name: "readyz exempt", path: "/readyz", want: http.StatusOK},
		{name: "metrics exempt", path: "/metrics", want: http.StatusOK},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, _ := http.NewRequest(http.MethodGet, srv.URL+tt.path, nil)
			if tt.header != "" {
				req.Header.Set("Authorization", tt.header)
			}
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			if resp.StatusCode != tt.want {
				t.Fatalf("status %d, want %d", resp.StatusCode, tt.want)
			}
			if tt.want == http.StatusUnauthorized {
				if resp.Header.Get("WWW-Authenticate") != "Bearer" {
					t.Fatal("missing WWW-Authenticate: Bearer")
				}
				if strings.Contains(string(body), secret) {
					t.Fatal("response body leaks the token")
				}
			}
		})
	}
	if failures.Load() != 3 {
		t.Fatalf("OnFailure called %d times, want 3", failures.Load())
	}
}

func TestRequireCustomExempt(t *testing.T) {
	mw, err := bearer.Require(
		serverCfg(bearer.Key{Name: "main", Token: secret}),
		bearer.ExemptPaths("/public"),
	)
	if err != nil {
		t.Fatal(err)
	}
	h := mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(200) }))

	for path, want := range map[string]int{"/public": 200, "/healthz": 401} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		if rec.Code != want {
			t.Fatalf("%s: status %d, want %d", path, rec.Code, want)
		}
	}
}

func TestRequireDisabled(t *testing.T) {
	mw, err := bearer.Require(nil)
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(200) })).
		ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/v1/logs", nil))
	if rec.Code != 200 {
		t.Fatalf("disabled auth must pass through, got %d", rec.Code)
	}
}

func TestLowLevelCompatibilityWrappers(t *testing.T) {
	v, err := bearer.NewVerifier(serverCfg(bearer.Key{Name: "main", Token: secret}))
	if err != nil {
		t.Fatal(err)
	}
	if !v.Verify(secret) {
		t.Fatal("NewVerifier wrapper did not materialize the configured key")
	}
	token, err := bearer.ClientToken(&bearer.ClientConfig{Token: secret})
	if err != nil {
		t.Fatal(err)
	}
	if token != secret {
		t.Fatalf("ClientToken = %q", token)
	}
}

func TestRequireConcurrent(t *testing.T) {
	mw, err := bearer.Require(serverCfg(bearer.Key{Name: "main", Token: secret}))
	if err != nil {
		t.Fatal(err)
	}
	h := mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(200) }))

	var wg sync.WaitGroup
	for i := range 32 {
		wg.Add(1)
		go func(authorized bool) {
			defer wg.Done()
			req := httptest.NewRequest(http.MethodGet, "/x", nil)
			if authorized {
				req.Header.Set("Authorization", "Bearer "+secret)
			}
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			want := 401
			if authorized {
				want = 200
			}
			if rec.Code != want {
				t.Errorf("status %d, want %d", rec.Code, want)
			}
		}(i%2 == 0)
	}
	wg.Wait()
}

func TestTransport(t *testing.T) {
	var got atomic.Value
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got.Store(r.Header.Get("Authorization"))
	}))
	defer srv.Close()

	rt, err := bearer.Transport(&bearer.ClientConfig{Token: secret}, nil)
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Transport: rt}

	resp, err := client.Get(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if got.Load() != "Bearer "+secret {
		t.Fatalf("token not injected: %q", got.Load())
	}

	// An explicit Authorization header on the request wins.
	req, _ := http.NewRequest(http.MethodGet, srv.URL, nil)
	req.Header.Set("Authorization", "Bearer explicit")
	resp2, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp2.Body.Close()
	if got.Load() != "Bearer explicit" {
		t.Fatalf("explicit header overwritten: %q", got.Load())
	}
}

func TestTransportEmptyConfig(t *testing.T) {
	rt, err := bearer.Transport(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if rt != http.DefaultTransport {
		t.Fatal("empty config must return base transport unchanged")
	}
}

func TestTransportNilHeader(t *testing.T) {
	var got string
	base := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		got = req.Header.Get("Authorization")
		return &http.Response{
			StatusCode: http.StatusNoContent,
			Header:     make(http.Header),
			Body:       http.NoBody,
			Request:    req,
		}, nil
	})
	rt, err := bearer.Transport(&bearer.ClientConfig{Token: secret}, base)
	if err != nil {
		t.Fatal(err)
	}
	req := &http.Request{Method: http.MethodGet, Header: nil}
	resp, err := rt.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if got != "Bearer "+secret {
		t.Fatalf("token not injected for nil Header: %q", got)
	}
	if req.Header != nil {
		t.Fatal("transport must not mutate the original request")
	}
}

func TestSecretHygiene(t *testing.T) {
	// Every validation error path must keep token values out of messages.
	cfgs := []*bearer.ServerConfig{
		serverCfg(bearer.Key{Name: "a", Token: secret, TokenEnv: "ALSO"}),
		serverCfg(bearer.Key{Token: secret}),
	}
	for _, cfg := range cfgs {
		if _, err := cfg.Validate(); err != nil && strings.Contains(err.Error(), secret) {
			t.Fatalf("error leaks token value: %v", err)
		}
	}
	if _, err := (&bearer.ClientConfig{Token: secret, TokenEnv: "ALSO"}).Validate(); err == nil {
		t.Fatal("expected error")
	} else if strings.Contains(err.Error(), secret) {
		t.Fatalf("error leaks token value: %v", err)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}
