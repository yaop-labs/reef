package reefclient_test

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/yaop-labs/reef/bearer"
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
