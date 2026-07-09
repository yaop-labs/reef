package tlsconf

import (
	"crypto/tls"
	"os"
	"sync"
	"time"
)

// reloadTTL bounds how often a certReloader stats its backing files: at most
// one stat per file per window, regardless of handshake rate.
const reloadTTL = 5 * time.Second

// certReloader serves a key pair that is re-read from disk when the backing
// files change, so operators can rotate certificates without a restart. It
// plugs into the GetCertificate / GetClientCertificate callbacks, which is why
// hot-reload needs no change to the tlsconf API.
//
// It stats the files at most once per ttl and reloads only when an mtime moved.
// A failed stat or a failed reload keeps the last good pair, so a half-written
// file never breaks a live handshake. There is no background goroutine — all
// work happens inline in the callback, guarded by a mutex for concurrent
// handshakes.
type certReloader struct {
	certFile string
	keyFile  string
	ttl      time.Duration
	now      func() time.Time

	mu       sync.Mutex
	cert     *tls.Certificate
	certMod  time.Time
	keyMod   time.Time
	lastStat time.Time
}

// newCertReloader loads the pair once (fail-stop: a startup error surfaces to
// the caller) and returns a reloader ready to serve it.
func newCertReloader(certFile, keyFile string) (*certReloader, error) {
	return newCertReloaderWithClock(certFile, keyFile, time.Now)
}

func newCertReloaderWithClock(certFile, keyFile string, now func() time.Time) (*certReloader, error) {
	r := &certReloader{certFile: certFile, keyFile: keyFile, ttl: reloadTTL, now: now}
	if err := r.reload(now()); err != nil {
		return nil, err
	}
	return r, nil
}

// get returns the current certificate, reloading it when the files changed and
// the throttle window has elapsed. It never returns an error once the initial
// load in newCertReloader succeeded.
func (r *certReloader) get() *tls.Certificate {
	r.mu.Lock()
	defer r.mu.Unlock()

	now := r.now()
	if now.Sub(r.lastStat) < r.ttl {
		return r.cert
	}
	r.lastStat = now

	ci, cerr := os.Stat(r.certFile)
	ki, kerr := os.Stat(r.keyFile)
	if cerr != nil || kerr != nil {
		return r.cert // transient stat error: keep serving the last good pair
	}
	if ci.ModTime().Equal(r.certMod) && ki.ModTime().Equal(r.keyMod) {
		return r.cert
	}
	_ = r.reload(now) // reload failure (e.g. half-written file) keeps the last good pair
	return r.cert
}

// reload reads the pair and records the files' mtimes. The initial call (from
// newCertReloader) propagates its error for fail-stop startup; get ignores
// later errors and holds the last good pair.
func (r *certReloader) reload(now time.Time) error {
	ci, err := os.Stat(r.certFile)
	if err != nil {
		return err
	}
	ki, err := os.Stat(r.keyFile)
	if err != nil {
		return err
	}
	cert, err := tls.LoadX509KeyPair(r.certFile, r.keyFile)
	if err != nil {
		return err
	}
	r.cert = &cert
	r.certMod = ci.ModTime()
	r.keyMod = ki.ModTime()
	r.lastStat = now
	return nil
}
