package bearer_test

import (
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/yaop-labs/reef/bearer"
)

func TestManagedVerifierRotatesByContentAndKeepsLastGood(t *testing.T) {
	path := filepath.Join(t.TempDir(), "server.token")
	if err := os.WriteFile(path, []byte("first\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}

	result, err := bearer.MaterializeVerifier(&bearer.ServerConfig{Bearer: []bearer.Key{{
		Name: "wisp", TokenFile: path,
	}}}, bearer.Lifecycle{Interval: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = result.Close() })
	if principal, ok := result.Verifier.VerifyPrincipal("first"); !ok || principal != "wisp" {
		t.Fatalf("initial principal=%q ok=%v", principal, ok)
	}

	if err := os.WriteFile(path, []byte("second\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(path, info.ModTime(), info.ModTime()); err != nil {
		t.Fatal(err)
	}
	if err := result.Credentials.ReloadNow(); err != nil {
		t.Fatal(err)
	}
	if result.Verifier.Verify("first") || !result.Verifier.Verify("second") {
		t.Fatal("content rotation did not replace the accepted token")
	}
	status := result.Credentials.Statuses()[0]
	if status.Generation != 2 {
		t.Fatalf("generation=%d, want 2", status.Generation)
	}

	if err := os.WriteFile(path, []byte("bad token with spaces"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := result.Credentials.ReloadNow(); err == nil {
		t.Fatal("invalid generation must report an error")
	}
	if !result.Verifier.Verify("second") {
		t.Fatal("invalid generation must keep last-known-good")
	}
	status = result.Credentials.Statuses()[0]
	if status.LastError == "" || strings.Contains(status.LastError, "second") {
		t.Fatalf("unsafe failure status: %+v", status)
	}
}

func TestManagedClientTransportRotatesToken(t *testing.T) {
	path := filepath.Join(t.TempDir(), "client.token")
	if err := os.WriteFile(path, []byte("first"), 0o600); err != nil {
		t.Fatal(err)
	}
	var got string
	base := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		got = req.Header.Get("Authorization")
		return &http.Response{
			StatusCode: http.StatusNoContent,
			Header:     make(http.Header),
			Body:       io.NopCloser(strings.NewReader("")),
			Request:    req,
		}, nil
	})
	result, err := bearer.MaterializeTransport(
		&bearer.ClientConfig{TokenFile: path},
		base,
		bearer.Lifecycle{Interval: time.Hour},
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = result.Close() })

	request := func() {
		req, err := http.NewRequest(http.MethodGet, "http://example.test", nil)
		if err != nil {
			t.Fatal(err)
		}
		resp, err := result.Transport.RoundTrip(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
	}
	request()
	if got != "Bearer first" {
		t.Fatalf("initial Authorization=%q", got)
	}
	if err := os.WriteFile(path, []byte("second"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := result.Credentials.ReloadNow(); err != nil {
		t.Fatal(err)
	}
	request()
	if got != "Bearer second" {
		t.Fatalf("rotated Authorization=%q", got)
	}
}

func TestPrincipalContextAndSuccessHook(t *testing.T) {
	var hooked string
	middleware, err := bearer.Require(
		&bearer.ServerConfig{Bearer: []bearer.Key{{Name: "coral", Token: "secret"}}},
		bearer.OnSuccess(func(_, _, principal string) { hooked = principal }),
	)
	if err != nil {
		t.Fatal(err)
	}
	handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		principal, ok := bearer.PrincipalFromContext(req.Context())
		if !ok || principal != "coral" {
			t.Fatalf("principal=%q ok=%v", principal, ok)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	req, err := http.NewRequest(http.MethodGet, "http://example.test/private", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer secret")
	recorder := &responseRecorder{header: make(http.Header)}
	handler.ServeHTTP(recorder, req)
	if recorder.status != http.StatusNoContent || hooked != "coral" {
		t.Fatalf("status=%d hooked=%q", recorder.status, hooked)
	}
}

func TestTokenHygieneAndDuplicateDigest(t *testing.T) {
	_, _, err := bearer.BuildVerifier(&bearer.ServerConfig{Bearer: []bearer.Key{
		{Name: "one", Token: "same"},
		{Name: "two", Token: "same"},
	}})
	if err == nil || !strings.Contains(err.Error(), "same token") {
		t.Fatalf("duplicate digest error=%v", err)
	}
	for name, token := range map[string]string{
		"internal whitespace": "one two",
		"control":             "one\x00two",
		"oversized":           strings.Repeat("x", bearer.MaxTokenBytes+1),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := bearer.ClientToken(&bearer.ClientConfig{Token: token}); err == nil {
				t.Fatal("expected hygiene error")
			} else if strings.Contains(err.Error(), token) {
				t.Fatal("error leaks token")
			}
		})
	}
	if _, warns, err := bearer.BuildClientToken(&bearer.ClientConfig{Token: "inline"}); err != nil {
		t.Fatal(err)
	} else if len(warns) != 1 || !strings.Contains(string(warns[0]), "inline") {
		t.Fatalf("inline warning=%v", warns)
	}
}

type responseRecorder struct {
	header http.Header
	status int
}

func (r *responseRecorder) Header() http.Header { return r.header }

func (r *responseRecorder) WriteHeader(status int) { r.status = status }

func (r *responseRecorder) Write(body []byte) (int, error) {
	if r.status == 0 {
		r.status = http.StatusOK
	}
	return len(body), nil
}
