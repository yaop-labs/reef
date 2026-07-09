package tlsconf

import (
	"bytes"
	"encoding/pem"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/yaop-labs/reef/reeftest"
)

func leafDER(t *testing.T, certFile string) []byte {
	t.Helper()
	pemBytes, err := os.ReadFile(certFile)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		t.Fatalf("no PEM block in %s", certFile)
	}
	return block.Bytes
}

func copyFile(t *testing.T, src, dst string) {
	t.Helper()
	data, err := os.ReadFile(src)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dst, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestCertReloaderReloadsOnChange(t *testing.T) {
	a := reeftest.GenCerts(t, t.TempDir())
	b := reeftest.GenCerts(t, t.TempDir())

	cur := time.Unix(1_000_000, 0)
	r, err := newCertReloaderWithClock(a.ServerCert, a.ServerKey, func() time.Time { return cur })
	if err != nil {
		t.Fatal(err)
	}

	leafA := leafDER(t, a.ServerCert)
	if !bytes.Equal(r.get().Certificate[0], leafA) {
		t.Fatal("initial certificate mismatch")
	}

	// Rotate: overwrite the served pair with b's and mark the files newer than
	// the mtimes the reloader recorded at construction.
	copyFile(t, b.ServerCert, a.ServerCert)
	copyFile(t, b.ServerKey, a.ServerKey)
	future := time.Now().Add(time.Hour)
	if err := os.Chtimes(a.ServerCert, future, future); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(a.ServerKey, future, future); err != nil {
		t.Fatal(err)
	}

	// Inside the throttle window the old certificate is still served.
	if !bytes.Equal(r.get().Certificate[0], leafA) {
		t.Fatal("reloaded before the throttle window elapsed")
	}

	// Past the window the rotated certificate is picked up.
	cur = cur.Add(reloadTTL + time.Second)
	if !bytes.Equal(r.get().Certificate[0], leafDER(t, b.ServerCert)) {
		t.Fatal("did not reload after the files changed")
	}
}

func TestCertReloaderKeepsLastGoodOnError(t *testing.T) {
	c := reeftest.GenCerts(t, t.TempDir())

	cur := time.Unix(1_000_000, 0)
	r, err := newCertReloaderWithClock(c.ServerCert, c.ServerKey, func() time.Time { return cur })
	if err != nil {
		t.Fatal(err)
	}
	leaf := leafDER(t, c.ServerCert)

	// A missing file must not break serving.
	if err := os.Remove(c.ServerCert); err != nil {
		t.Fatal(err)
	}
	cur = cur.Add(reloadTTL + time.Second)
	if got := r.get(); got == nil || !bytes.Equal(got.Certificate[0], leaf) {
		t.Fatal("a stat error must keep the last good certificate")
	}

	// A half-written (unparseable) file must also be ignored.
	if err := os.WriteFile(c.ServerCert, []byte("not a certificate"), 0o600); err != nil {
		t.Fatal(err)
	}
	future := time.Now().Add(time.Hour)
	if err := os.Chtimes(c.ServerCert, future, future); err != nil {
		t.Fatal(err)
	}
	cur = cur.Add(reloadTTL + time.Second)
	if got := r.get(); got == nil || !bytes.Equal(got.Certificate[0], leaf) {
		t.Fatal("a corrupt file must keep the last good certificate")
	}
}

func TestCertReloaderInitialLoadFails(t *testing.T) {
	if _, err := newCertReloader("/nonexistent.crt", "/nonexistent.key"); err == nil {
		t.Fatal("missing files must fail at construction (fail-stop)")
	}
}

func TestCertReloaderConcurrent(t *testing.T) {
	c := reeftest.GenCerts(t, t.TempDir())
	r, err := newCertReloader(c.ServerCert, c.ServerKey)
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for range 16 {
		wg.Go(func() { _ = r.get() })
	}
	wg.Wait()
}
