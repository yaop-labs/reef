package reefclient_test

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/yaop-labs/reef/bearer"
	"github.com/yaop-labs/reef/credential"
	"github.com/yaop-labs/reef/edge"
	"github.com/yaop-labs/reef/reefclient"
	"github.com/yaop-labs/reef/reeftest"
	"github.com/yaop-labs/reef/tlsconf"
)

func TestTransportEndToEnd(t *testing.T) {
	certs := reeftest.GenCerts(t, t.TempDir())
	const secret = "client-s3cr3t"

	mw, err := bearer.Require(&bearer.ServerConfig{Bearer: []bearer.Key{{Name: "a", Token: secret}}})
	if err != nil {
		t.Fatal(err)
	}
	tlsCfg, err := tlsconf.Server(&tlsconf.ServerConfig{
		Enabled: true, CertFile: certs.ServerCert, KeyFile: certs.ServerKey,
	})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewUnstartedServer(mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "ok")
	})))
	srv.TLS = tlsCfg
	srv.StartTLS()
	defer srv.Close()

	rt, err := reefclient.Transport(reefclient.Config{
		TLS:  &tlsconf.ClientConfig{Enabled: true, CAFile: certs.CACert, ServerName: "localhost"},
		Auth: &bearer.ClientConfig{Token: secret},
	})
	if err != nil {
		t.Fatal(err)
	}
	resp, err := (&http.Client{Transport: rt}).Get(srv.URL + "/v1/metrics-not-exempt")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d, want 200", resp.StatusCode)
	}

	// Same server, transport without a token: 401.
	bare, err := reefclient.Transport(reefclient.Config{
		TLS: &tlsconf.ClientConfig{Enabled: true, CAFile: certs.CACert, ServerName: "localhost"},
	})
	if err != nil {
		t.Fatal(err)
	}
	resp2, err := (&http.Client{Transport: bare}).Get(srv.URL + "/v1/metrics-not-exempt")
	if err != nil {
		t.Fatal(err)
	}
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status %d, want 401", resp2.StatusCode)
	}
}

func TestEmptyConfig(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	rt, err := reefclient.Transport(reefclient.Config{})
	if err != nil {
		t.Fatal(err)
	}
	resp, err := (&http.Client{Transport: rt}).Get(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d, want 200", resp.StatusCode)
	}
}

func TestTransportWithBaseClonesInput(t *testing.T) {
	base := &http.Transport{MaxIdleConns: 17, MaxIdleConnsPerHost: 9}
	rt, err := reefclient.TransportWithBase(reefclient.Config{}, base)
	if err != nil {
		t.Fatal(err)
	}
	got, ok := rt.(*http.Transport)
	if !ok {
		t.Fatalf("expected *http.Transport, got %T", rt)
	}
	if got == base {
		t.Fatal("TransportWithBase must clone, not mutate, the caller's transport")
	}
	if got.MaxIdleConns != 17 || got.MaxIdleConnsPerHost != 9 {
		t.Fatalf("base settings not preserved: %+v", got)
	}
}

func TestEdgeTransportBindsBearerToTargetOrigin(t *testing.T) {
	const token = "origin-bound-secret"
	var targetCalls atomic.Int64
	var otherCalls atomic.Int64

	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		targetCalls.Add(1)
		if r.Header.Get("Authorization") != "Bearer "+token {
			t.Errorf("target Authorization = %q", r.Header.Get("Authorization"))
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer target.Close()
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		otherCalls.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer other.Close()

	rt, warns, err := reefclient.EdgeTransport(edge.ClientConfig{
		Target:                         target.URL,
		Auth:                           &bearer.ClientConfig{Token: token},
		DangerAllowBearerOverPlaintext: true,
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(warns) != 1 {
		t.Fatalf("want inline-token warning, got %v", warns)
	}
	client := &http.Client{Transport: rt}
	resp, err := client.Get(target.URL)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	otherResp, err := client.Get(other.URL)
	if otherResp != nil {
		otherResp.Body.Close()
	}
	if err == nil || !strings.Contains(err.Error(), "outside configured edge") {
		t.Fatalf("expected origin-bound rejection, got %v", err)
	}
	if targetCalls.Load() != 1 || otherCalls.Load() != 0 {
		t.Fatalf("calls: target=%d other=%d", targetCalls.Load(), otherCalls.Load())
	}
}

func TestEdgeTransportRejectsBearerOverPlaintext(t *testing.T) {
	_, _, err := reefclient.EdgeTransport(edge.ClientConfig{
		Target: "http://127.0.0.1:4318",
		Auth:   &bearer.ClientConfig{Token: "secret"},
	}, nil)
	if err == nil || !strings.Contains(err.Error(), "bearer auth over plaintext") {
		t.Fatalf("expected plaintext bearer rejection, got %v", err)
	}
}

func TestEdgeTransportReturnsWarnings(t *testing.T) {
	tokenFile := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(tokenFile, []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(tokenFile, 0o644); err != nil {
		t.Fatal(err)
	}
	_, warns, err := reefclient.EdgeTransport(edge.ClientConfig{
		Target: "https://coral.internal:4318",
		Auth:   &bearer.ClientConfig{TokenFile: tokenFile},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(warns) != 1 || !strings.HasPrefix(string(warns[0]), "auth:") {
		t.Fatalf("want one auth permission warning, got %v", warns)
	}
}

func TestEdgeTransportRejectsRequestWithoutURL(t *testing.T) {
	rt, _, err := reefclient.EdgeTransport(edge.ClientConfig{
		Target: "http://127.0.0.1:4318",
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := rt.RoundTrip(&http.Request{})
	if resp != nil {
		resp.Body.Close()
	}
	if err == nil || !strings.Contains(err.Error(), "request URL is required") {
		t.Fatalf("expected missing URL rejection, got %v", err)
	}
}

func TestNewEdgeTransportRotatesTokenAndOwnsLifecycle(t *testing.T) {
	tokenFile := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(tokenFile, []byte("first"), 0o600); err != nil {
		t.Fatal(err)
	}
	var want atomic.Value
	want.Store("Bearer first")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if got := request.Header.Get("Authorization"); got != want.Load().(string) {
			t.Errorf("Authorization=%q, want %q", got, want.Load())
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(server.Close)

	managed, warnings, err := reefclient.NewEdgeTransport(edge.ClientConfig{
		Target:                         server.URL,
		Auth:                           &bearer.ClientConfig{TokenFile: tokenFile},
		DangerAllowBearerOverPlaintext: true,
		ReloadInterval:                 time.Hour,
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(warnings) != 0 {
		t.Fatalf("warnings=%v", warnings)
	}
	client := &http.Client{Transport: managed}
	request := func() {
		response, requestErr := client.Get(server.URL)
		if requestErr != nil {
			t.Fatal(requestErr)
		}
		response.Body.Close()
		if response.StatusCode != http.StatusNoContent {
			t.Fatalf("status=%d", response.StatusCode)
		}
	}
	request()

	if err := os.WriteFile(tokenFile, []byte("second"), 0o600); err != nil {
		t.Fatal(err)
	}
	want.Store("Bearer second")
	if err := managed.ReloadCredentials(); err != nil {
		t.Fatal(err)
	}
	request()
	statuses := managed.CredentialStatus()
	if len(statuses) != 1 || statuses[0].Generation != 2 {
		t.Fatalf("statuses=%+v", statuses)
	}

	if err := managed.Close(); err != nil {
		t.Fatal(err)
	}
	if !errors.Is(managed.ReloadCredentials(), credential.ErrClosed) {
		t.Fatal("reload after Close must return credential.ErrClosed")
	}
}
