package tlsconf_test

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/yaop-labs/reef/credential"
	"github.com/yaop-labs/reef/reeftest"
	"github.com/yaop-labs/reef/tlsconf"
)

func TestManagedTLSRotatesCompleteMTLSIdentityWithStableMtime(t *testing.T) {
	first := reeftest.GenCerts(t, t.TempDir())
	second := reeftest.GenCerts(t, t.TempDir())
	active := reeftest.Certs{
		CACert:     filepath.Join(t.TempDir(), "ca.crt"),
		ServerCert: filepath.Join(t.TempDir(), "server.crt"),
		ServerKey:  filepath.Join(t.TempDir(), "server.key"),
		ClientCert: filepath.Join(t.TempDir(), "client.crt"),
		ClientKey:  filepath.Join(t.TempDir(), "client.key"),
	}
	stamp := time.Unix(1_700_000_000, 0)
	copyCertSet(t, active, first, stamp)

	server, err := tlsconf.MaterializeServer(&tlsconf.ServerConfig{
		Enabled:      true,
		CertFile:     active.ServerCert,
		KeyFile:      active.ServerKey,
		ClientCAFile: active.CACert,
	}, tlsconf.Lifecycle{Interval: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = server.Close() })

	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "ok")
	}))
	srv.TLS = server.Config
	srv.StartTLS()
	t.Cleanup(srv.Close)

	client, err := tlsconf.MaterializeClient(&tlsconf.ClientConfig{
		Enabled:    true,
		CAFile:     active.CACert,
		ServerName: "localhost",
		CertFile:   active.ClientCert,
		KeyFile:    active.ClientKey,
	}, tlsconf.Lifecycle{Interval: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	transport := &http.Transport{TLSClientConfig: client.Provider.ConfigForServer("localhost")}
	httpClient := &http.Client{Transport: transport}
	mustGet(t, httpClient, srv.URL)

	copyCertSet(t, active, second, stamp)
	if err := server.Credentials.ReloadNow(); err != nil {
		t.Fatal(err)
	}
	transport.CloseIdleConnections()
	if response, requestErr := httpClient.Get(srv.URL); requestErr == nil {
		response.Body.Close()
		t.Fatal("client with the old CA and leaf must not survive a complete server identity rotation")
	}

	if err := client.Credentials.ReloadNow(); err != nil {
		t.Fatal(err)
	}
	transport.CloseIdleConnections()
	mustGet(t, httpClient, srv.URL)

	assertGenerations(t, server.Credentials.Statuses(), 2)
	assertGenerations(t, client.Credentials.Statuses(), 2)
}

func TestManagedServerLeafKeepsLastKnownGoodAndReportsFailure(t *testing.T) {
	first := reeftest.GenCerts(t, t.TempDir())
	second := reeftest.GenCerts(t, t.TempDir())
	activeCert := filepath.Join(t.TempDir(), "server.crt")
	activeKey := filepath.Join(t.TempDir(), "server.key")
	stamp := time.Unix(1_700_000_000, 0)
	copyStable(t, activeCert, first.ServerCert, stamp)
	copyStable(t, activeKey, first.ServerKey, stamp)

	events := make(chan credential.Event, 8)
	server, err := tlsconf.MaterializeServer(&tlsconf.ServerConfig{
		Enabled: true, CertFile: activeCert, KeyFile: activeKey,
	}, tlsconf.Lifecycle{
		Interval: time.Hour,
		Observer: credential.ObserverFunc(func(event credential.Event) { events <- event }),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = server.Close() })

	if err := os.WriteFile(activeCert, []byte("not a certificate"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(activeCert, stamp, stamp); err != nil {
		t.Fatal(err)
	}
	if err := server.Credentials.ReloadNow(); err == nil {
		t.Fatal("expected invalid leaf reload to fail")
	}
	status := server.Credentials.Statuses()[0]
	if status.Generation != 1 || status.LastError == "" || status.LastFailure.IsZero() {
		t.Fatalf("failure must retain generation and expose safe status: %+v", status)
	}
	if certificate, getErr := server.Config.GetCertificate(nil); getErr != nil || certificate == nil {
		t.Fatal("last-known-good leaf was discarded")
	}

	copyStable(t, activeCert, second.ServerCert, stamp)
	copyStable(t, activeKey, second.ServerKey, stamp)
	if err := server.Credentials.ReloadNow(); err != nil {
		t.Fatal(err)
	}
	status = server.Credentials.Statuses()[0]
	if status.Generation != 2 || status.LastError != "" {
		t.Fatalf("valid recovery was not applied: %+v", status)
	}

	var sawFailure, sawRecovery bool
	for len(events) > 0 {
		event := <-events
		sawFailure = sawFailure || !event.Success
		sawRecovery = sawRecovery || (event.Success && event.Status.Generation == 2)
	}
	if !sawFailure || !sawRecovery {
		t.Fatalf("observer transitions: failure=%v recovery=%v", sawFailure, sawRecovery)
	}
}

func copyCertSet(t *testing.T, dst, src reeftest.Certs, stamp time.Time) {
	t.Helper()
	copyStable(t, dst.CACert, src.CACert, stamp)
	copyStable(t, dst.ServerCert, src.ServerCert, stamp)
	copyStable(t, dst.ServerKey, src.ServerKey, stamp)
	copyStable(t, dst.ClientCert, src.ClientCert, stamp)
	copyStable(t, dst.ClientKey, src.ClientKey, stamp)
}

func copyStable(t *testing.T, dst, src string, stamp time.Time) {
	t.Helper()
	data, err := os.ReadFile(src)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dst, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(dst, stamp, stamp); err != nil {
		t.Fatal(err)
	}
}

func assertGenerations(t *testing.T, statuses []credential.Status, want uint64) {
	t.Helper()
	if len(statuses) != 2 {
		t.Fatalf("statuses=%+v, want leaf and CA", statuses)
	}
	for _, status := range statuses {
		if status.Generation != want || status.LastError != "" {
			t.Fatalf("status=%+v, want generation %d without error", status, want)
		}
	}
}
