package credential_test

import (
	"crypto/sha256"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/yaop-labs/reef/credential"
)

func TestManagedGenerationFailureRecoveryAndClose(t *testing.T) {
	var (
		mu     sync.Mutex
		value  = "one"
		fail   bool
		events []credential.Event
	)
	loader := func() (string, credential.Metadata, error) {
		mu.Lock()
		defer mu.Unlock()
		if fail {
			return "", credential.Metadata{}, errors.New("safe load failure")
		}
		return value, credential.Metadata{Fingerprint: sha256.Sum256([]byte(value))}, nil
	}
	manager, err := credential.NewManaged(credential.Options{
		Name:     "test",
		Kind:     credential.KindClientToken,
		Interval: time.Hour,
		Observer: credential.ObserverFunc(func(event credential.Event) {
			mu.Lock()
			events = append(events, event)
			mu.Unlock()
		}),
	}, loader)
	if err != nil {
		t.Fatal(err)
	}
	if manager.Current() != "one" || manager.Status().Generation != 1 {
		t.Fatalf("initial state: value=%q status=%+v", manager.Current(), manager.Status())
	}

	mu.Lock()
	value = "two"
	mu.Unlock()
	if err := manager.ReloadNow(); err != nil {
		t.Fatal(err)
	}
	if manager.Current() != "two" || manager.Status().Generation != 2 {
		t.Fatalf("rotated state: value=%q status=%+v", manager.Current(), manager.Status())
	}

	mu.Lock()
	fail = true
	mu.Unlock()
	if err := manager.ReloadNow(); err == nil {
		t.Fatal("expected reload failure")
	}
	if manager.Current() != "two" || manager.Status().LastError == "" {
		t.Fatalf("failure must keep last good: value=%q status=%+v", manager.Current(), manager.Status())
	}

	mu.Lock()
	fail = false
	mu.Unlock()
	if err := manager.ReloadNow(); err != nil {
		t.Fatal(err)
	}
	if manager.Status().LastError != "" || manager.Status().Generation != 2 {
		t.Fatalf("unchanged recovery status: %+v", manager.Status())
	}

	if err := manager.Close(); err != nil {
		t.Fatal(err)
	}
	if err := manager.Close(); err != nil {
		t.Fatal(err)
	}
	if !errors.Is(manager.ReloadNow(), credential.ErrClosed) {
		t.Fatal("reload after Close must return ErrClosed")
	}
	mu.Lock()
	defer mu.Unlock()
	if len(events) != 4 {
		t.Fatalf("events=%d, want initial/change/failure/recovery", len(events))
	}
}

func TestManagedBackgroundAndConcurrentReads(t *testing.T) {
	var value atomic.Int64
	value.Store(1)
	manager, err := credential.NewManaged(credential.Options{
		Name: "counter", Kind: credential.KindServerToken, Interval: time.Millisecond,
	}, func() (int64, credential.Metadata, error) {
		v := value.Load()
		return v, credential.Metadata{Fingerprint: sha256.Sum256([]byte{byte(v)})}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = manager.Close() })

	value.Store(2)
	deadline := time.Now().Add(time.Second)
	for manager.Current() != 2 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if manager.Current() != 2 {
		t.Fatal("background reload did not apply")
	}

	var wg sync.WaitGroup
	for range 32 {
		wg.Go(func() {
			for range 100 {
				_ = manager.Current()
				_ = manager.Status()
			}
		})
	}
	wg.Wait()
}

func TestGroupCloseAndStatus(t *testing.T) {
	group := credential.NewGroup()
	manager, err := credential.NewManaged(credential.Options{
		Name: "one", Kind: credential.KindServerCA, Interval: time.Hour,
	}, func() (string, credential.Metadata, error) {
		return "value", credential.Metadata{Fingerprint: sha256.Sum256([]byte("value"))}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := group.Add(manager); err != nil {
		t.Fatal(err)
	}
	if got := group.Statuses(); len(got) != 1 || got[0].Generation != 1 {
		t.Fatalf("statuses: %+v", got)
	}
	if err := group.ReloadNow(); err != nil {
		t.Fatal(err)
	}
	if err := group.Close(); err != nil {
		t.Fatal(err)
	}
	if err := group.Close(); err != nil {
		t.Fatal(err)
	}
	if !errors.Is(group.ReloadNow(), credential.ErrClosed) {
		t.Fatal("group reload after Close must return ErrClosed")
	}
}
