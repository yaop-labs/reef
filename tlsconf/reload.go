package tlsconf

import (
	"crypto/tls"
	"os"
	"sync"
	"sync/atomic"
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
// The common path — a handshake inside the throttle window — is lock-free: a
// pair of atomic loads, no mutex. At most one handshake per window claims the
// stat/reload (via a CAS on lastStat) and takes the mutex; a failed stat or a
// failed reload keeps the last good pair, so a half-written file never breaks a
// live handshake. There is no background goroutine — all work happens inline in
// the callback.
type certReloader struct {
	certFile string
	keyFile  string
	ttl      time.Duration
	now      func() time.Time

	cert     atomic.Pointer[tls.Certificate] // current pair; read lock-free
	lastStat atomic.Int64                    // unix-nanos of the last stat window

	mu      sync.Mutex // guards the reload path (mtimes + LoadX509KeyPair)
	certMod time.Time
	keyMod  time.Time
}

// newCertReloader loads the pair once (fail-stop: a startup error surfaces to
// the caller) and returns a reloader ready to serve it.
func newCertReloader(certFile, keyFile string) (*certReloader, error) {
	return newCertReloaderWithClock(certFile, keyFile, time.Now)
}

func newCertReloaderWithClock(certFile, keyFile string, now func() time.Time) (*certReloader, error) {
	r := &certReloader{certFile: certFile, keyFile: keyFile, ttl: reloadTTL, now: now}
	if err := r.reload(); err != nil {
		return nil, err
	}
	r.lastStat.Store(now().UnixNano())
	return r, nil
}

// get returns the current certificate, reloading it when the files changed and
// the throttle window has elapsed. It never returns an error once the initial
// load in newCertReloader succeeded.
func (r *certReloader) get() *tls.Certificate {
	now := r.now().UnixNano()
	last := r.lastStat.Load()
	if now-last < int64(r.ttl) {
		return r.cert.Load() // fast path: still inside the window, no lock
	}
	if !r.lastStat.CompareAndSwap(last, now) {
		return r.cert.Load() // another handshake owns this window
	}
	r.mu.Lock()
	r.reloadIfChanged()
	r.mu.Unlock()
	return r.cert.Load()
}

// reloadIfChanged stats the files and reloads only when an mtime moved. A
// transient stat error or a failed reload keeps the last good pair. The caller
// holds r.mu.
func (r *certReloader) reloadIfChanged() {
	ci, cerr := os.Stat(r.certFile)
	ki, kerr := os.Stat(r.keyFile)
	if cerr != nil || kerr != nil {
		return // transient stat error: keep serving the last good pair
	}
	if ci.ModTime().Equal(r.certMod) && ki.ModTime().Equal(r.keyMod) {
		return
	}
	_ = r.reload() // reload failure (e.g. half-written file) keeps the last good pair
}

// reload reads the pair and records the files' mtimes. The initial call (from
// newCertReloader) propagates its error for fail-stop startup; reloadIfChanged
// ignores later errors and holds the last good pair. Callers other than the
// initial load hold r.mu.
func (r *certReloader) reload() error {
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
	r.cert.Store(&cert)
	r.certMod = ci.ModTime()
	r.keyMod = ki.ModTime()
	return nil
}
