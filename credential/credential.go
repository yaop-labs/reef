// Package credential provides the observable lifecycle used by Reef's
// file-backed certificates, CA bundles, and bearer tokens.
package credential

import (
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"
)

// Kind identifies a credential without exposing its value.
type Kind string

const (
	KindServerLeaf  Kind = "server_leaf"
	KindClientLeaf  Kind = "client_leaf"
	KindServerCA    Kind = "server_client_ca"
	KindClientCA    Kind = "client_root_ca"
	KindServerToken Kind = "server_bearer"
	KindClientToken Kind = "client_bearer"
)

// Status is a secret-free snapshot of one credential's lifecycle.
type Status struct {
	Name        string
	Kind        Kind
	Generation  uint64
	LastSuccess time.Time
	LastFailure time.Time
	LastError   string
	NotBefore   time.Time
	NotAfter    time.Time
}

// Event is emitted on initial load, generation change, failure transition, or
// recovery. Observer implementations must not block.
type Event struct {
	Status  Status
	Success bool
	Changed bool
}

// Observer receives credential lifecycle transitions.
type Observer interface {
	ObserveCredential(Event)
}

// ObserverFunc adapts a function to Observer.
type ObserverFunc func(Event)

func (f ObserverFunc) ObserveCredential(event Event) { f(event) }

// Metadata accompanies a loaded value. Fingerprint must describe the source
// contents, not metadata such as mtime.
type Metadata struct {
	Fingerprint [32]byte
	NotBefore   time.Time
	NotAfter    time.Time
}

// Loader returns a complete new credential generation. Errors must never
// contain secret values.
type Loader[T any] func() (T, Metadata, error)

// Options configures a managed credential.
type Options struct {
	Name     string
	Kind     Kind
	Interval time.Duration
	Observer Observer
}

const DefaultInterval = 5 * time.Second

var ErrClosed = errors.New("credential: manager is closed")

type snapshot[T any] struct {
	value       T
	fingerprint [32]byte
	status      Status
}

// Managed owns one background-reloaded credential. Current is lock-free.
type Managed[T any] struct {
	options Options
	loader  Loader[T]

	current atomic.Pointer[snapshot[T]]
	closed  atomic.Bool

	reloadMu sync.Mutex
	close    sync.Once
	stop     chan struct{}
	done     chan struct{}
}

// NewManaged performs the fail-stop initial load before starting the
// background reload loop.
func NewManaged[T any](options Options, loader Loader[T]) (*Managed[T], error) {
	if loader == nil {
		return nil, errors.New("credential: loader is required")
	}
	if options.Name == "" {
		return nil, errors.New("credential: name is required")
	}
	if options.Kind == "" {
		return nil, errors.New("credential: kind is required")
	}
	if options.Interval <= 0 {
		options.Interval = DefaultInterval
	}
	m := &Managed[T]{
		options: options,
		loader:  loader,
		stop:    make(chan struct{}),
		done:    make(chan struct{}),
	}
	if err := m.reload(true); err != nil {
		return nil, fmt.Errorf("credential: initial load %s: %w", options.Name, err)
	}
	go m.run()
	return m, nil
}

// Current returns the last-known-good generation.
func (m *Managed[T]) Current() T {
	if state := m.current.Load(); state != nil {
		return state.value
	}
	var zero T
	return zero
}

// Status returns a consistent secret-free status snapshot.
func (m *Managed[T]) Status() Status {
	if state := m.current.Load(); state != nil {
		return state.status
	}
	return Status{Name: m.options.Name, Kind: m.options.Kind}
}

// ReloadNow performs an immediate serialized reload. It is useful for
// operational controls and deterministic tests.
func (m *Managed[T]) ReloadNow() error {
	if m.closed.Load() {
		return ErrClosed
	}
	return m.reload(false)
}

func (m *Managed[T]) reload(initial bool) error {
	m.reloadMu.Lock()
	defer m.reloadMu.Unlock()
	if m.closed.Load() {
		return ErrClosed
	}

	value, metadata, err := m.loader()
	now := time.Now()
	old := m.current.Load()
	if err != nil {
		status := Status{Name: m.options.Name, Kind: m.options.Kind, LastFailure: now, LastError: err.Error()}
		notify := true
		if old != nil {
			status = old.status
			status.LastFailure = now
			status.LastError = err.Error()
			notify = old.status.LastError != status.LastError
			m.current.Store(&snapshot[T]{
				value: old.value, fingerprint: old.fingerprint, status: status,
			})
		}
		if notify {
			m.observe(Event{Status: status, Success: false})
		}
		return err
	}

	changed := old == nil || old.fingerprint != metadata.Fingerprint
	recovered := old != nil && old.status.LastError != ""
	status := Status{
		Name:        m.options.Name,
		Kind:        m.options.Kind,
		Generation:  1,
		LastSuccess: now,
		NotBefore:   metadata.NotBefore,
		NotAfter:    metadata.NotAfter,
	}
	if old != nil {
		status.Generation = old.status.Generation
		status.LastFailure = old.status.LastFailure
		if changed {
			status.Generation++
		} else {
			value = old.value
			status.NotBefore = old.status.NotBefore
			status.NotAfter = old.status.NotAfter
		}
	}
	m.current.Store(&snapshot[T]{
		value: value, fingerprint: metadata.Fingerprint, status: status,
	})
	if initial || changed || recovered {
		m.observe(Event{Status: status, Success: true, Changed: changed})
	}
	return nil
}

func (m *Managed[T]) observe(event Event) {
	if m.options.Observer != nil && !m.closed.Load() {
		m.options.Observer.ObserveCredential(event)
	}
}

func (m *Managed[T]) run() {
	defer close(m.done)
	ticker := time.NewTicker(m.options.Interval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			_ = m.reload(false)
		case <-m.stop:
			return
		}
	}
}

// Close stops reload and waits for any in-flight reload to finish. It is
// idempotent; no observer callback occurs after it returns.
func (m *Managed[T]) Close() error {
	m.close.Do(func() {
		m.closed.Store(true)
		close(m.stop)
		<-m.done
		m.reloadMu.Lock()
		// Observe the state while holding the reload lock so Close also
		// waits for a synchronous ReloadNow call already in progress.
		_ = m.current.Load()
		m.reloadMu.Unlock()
	})
	return nil
}

// Resource is the non-generic lifecycle surface exposed by an edge.
type Resource interface {
	Status() Status
	Close() error
}

// Group owns all managed credentials materialized for one edge.
type Group struct {
	mu        sync.RWMutex
	resources []Resource
	closed    bool
}

// NewGroup creates an empty lifecycle group.
func NewGroup() *Group { return &Group{} }

// Add transfers lifecycle ownership to the group.
func (g *Group) Add(resource Resource) error {
	if resource == nil {
		return nil
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.closed {
		_ = resource.Close()
		return ErrClosed
	}
	g.resources = append(g.resources, resource)
	return nil
}

// Statuses returns one snapshot per managed credential.
func (g *Group) Statuses() []Status {
	if g == nil {
		return nil
	}
	g.mu.RLock()
	defer g.mu.RUnlock()
	out := make([]Status, 0, len(g.resources))
	for _, resource := range g.resources {
		out = append(out, resource.Status())
	}
	return out
}

// ReloadNow immediately checks every managed credential.
func (g *Group) ReloadNow() error {
	if g == nil {
		return nil
	}
	g.mu.RLock()
	resources := append([]Resource(nil), g.resources...)
	closed := g.closed
	g.mu.RUnlock()
	if closed {
		return ErrClosed
	}
	var errs []error
	for _, resource := range resources {
		if reloader, ok := resource.(interface{ ReloadNow() error }); ok {
			if err := reloader.ReloadNow(); err != nil {
				errs = append(errs, err)
			}
		}
	}
	return errors.Join(errs...)
}

// Close closes resources in reverse materialization order.
func (g *Group) Close() error {
	if g == nil {
		return nil
	}
	g.mu.Lock()
	if g.closed {
		g.mu.Unlock()
		return nil
	}
	g.closed = true
	resources := append([]Resource(nil), g.resources...)
	g.mu.Unlock()

	var errs []error
	for i := len(resources) - 1; i >= 0; i-- {
		if err := resources[i].Close(); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}
