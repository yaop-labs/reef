package grpcreef_test

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"

	"github.com/yaop-labs/reef/bearer"
	"github.com/yaop-labs/reef/grpcreef"
	"github.com/yaop-labs/reef/reeftest"
	"github.com/yaop-labs/reef/tlsconf"
)

const secret = "grpc-s3cr3t"

func startServer(t *testing.T, tc *tlsconf.ServerConfig, ac *bearer.ServerConfig, authOpts ...bearer.Option) *bufconn.Listener {
	t.Helper()
	opts, err := grpcreef.ServerOptions(tc, ac, authOpts...)
	if err != nil {
		t.Fatal(err)
	}
	srv := grpc.NewServer(opts...)
	healthpb.RegisterHealthServer(srv, health.NewServer())

	ln := bufconn.Listen(1 << 20)
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(srv.Stop)
	return ln
}

func dial(t *testing.T, ln *bufconn.Listener, tc *tlsconf.ClientConfig, ac *bearer.ClientConfig) *grpc.ClientConn {
	t.Helper()
	conn, err := grpcreef.Dial(context.Background(), "passthrough:///bufnet", tc, ac,
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return ln.DialContext(ctx)
		}))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

func check(conn *grpc.ClientConn) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err := healthpb.NewHealthClient(conn).Check(ctx, &healthpb.HealthCheckRequest{})
	return err
}

func wantUnauthenticated(t *testing.T, err error) {
	t.Helper()
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("want Unauthenticated, got %v", err)
	}
}

func TestPlaintextAuth(t *testing.T) {
	ln := startServer(t, nil, &bearer.ServerConfig{Bearer: []bearer.Key{{Name: "a", Token: secret}}})

	wantUnauthenticated(t, check(dial(t, ln, nil, nil)))
	wantUnauthenticated(t, check(dial(t, ln, nil, &bearer.ClientConfig{Token: "wrong"})))
	if err := check(dial(t, ln, nil, &bearer.ClientConfig{Token: secret})); err != nil {
		t.Fatalf("authorized check failed: %v", err)
	}
}

func TestStreamAuth(t *testing.T) {
	ln := startServer(t, nil, &bearer.ServerConfig{Bearer: []bearer.Key{{Name: "a", Token: secret}}})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Watch is a server-streaming method: the stream interceptor must gate it.
	stream, err := healthpb.NewHealthClient(dial(t, ln, nil, nil)).Watch(ctx, &healthpb.HealthCheckRequest{})
	if err == nil {
		_, err = stream.Recv()
	}
	wantUnauthenticated(t, err)

	stream, err = healthpb.NewHealthClient(dial(t, ln, nil, &bearer.ClientConfig{Token: secret})).
		Watch(ctx, &healthpb.HealthCheckRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := stream.Recv(); err != nil {
		t.Fatalf("authorized watch failed: %v", err)
	}
}

func TestExemptMethod(t *testing.T) {
	ln := startServer(t, nil,
		&bearer.ServerConfig{Bearer: []bearer.Key{{Name: "a", Token: secret}}},
		bearer.ExemptPaths("/grpc.health.v1.Health/Check"),
	)

	// Check is exempt: it must pass without a token.
	if err := check(dial(t, ln, nil, nil)); err != nil {
		t.Fatalf("exempt method must skip auth, got %v", err)
	}

	// Watch is not exempt: it stays gated.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	stream, err := healthpb.NewHealthClient(dial(t, ln, nil, nil)).Watch(ctx, &healthpb.HealthCheckRequest{})
	if err == nil {
		_, err = stream.Recv()
	}
	wantUnauthenticated(t, err)
}

func TestTLSAndAuth(t *testing.T) {
	certs := reeftest.GenCerts(t, t.TempDir())

	ln := startServer(t,
		&tlsconf.ServerConfig{Enabled: true, CertFile: certs.ServerCert, KeyFile: certs.ServerKey},
		&bearer.ServerConfig{Bearer: []bearer.Key{{Name: "a", Token: secret}}},
	)
	clientTLS := &tlsconf.ClientConfig{Enabled: true, CAFile: certs.CACert, ServerName: "localhost"}

	if err := check(dial(t, ln, clientTLS, &bearer.ClientConfig{Token: secret})); err != nil {
		t.Fatalf("tls+token check failed: %v", err)
	}
	wantUnauthenticated(t, check(dial(t, ln, clientTLS, nil)))
}

func TestMutualTLS(t *testing.T) {
	certs := reeftest.GenCerts(t, t.TempDir())

	ln := startServer(t,
		&tlsconf.ServerConfig{Enabled: true, CertFile: certs.ServerCert, KeyFile: certs.ServerKey, ClientCAFile: certs.CACert},
		nil,
	)

	good := dial(t, ln, &tlsconf.ClientConfig{
		Enabled: true, CAFile: certs.CACert, ServerName: "localhost",
		CertFile: certs.ClientCert, KeyFile: certs.ClientKey,
	}, nil)
	if err := check(good); err != nil {
		t.Fatalf("mtls check failed: %v", err)
	}

	bare := dial(t, ln, &tlsconf.ClientConfig{Enabled: true, CAFile: certs.CACert, ServerName: "localhost"}, nil)
	if err := check(bare); err == nil {
		t.Fatal("expected handshake failure without client certificate")
	} else if status.Code(err) == codes.OK {
		t.Fatalf("unexpected: %v", err)
	}
}

func TestInvalidConfig(t *testing.T) {
	_, err := grpcreef.ServerOptions(&tlsconf.ServerConfig{CertFile: "x"}, nil)
	if err == nil {
		t.Fatal("ServerOptions must reject tls fields with enabled: false")
	}
	_, err = grpcreef.DialOptions(nil, &bearer.ClientConfig{Token: "a", TokenEnv: "B"})
	if err == nil {
		t.Fatal("DialOptions must reject two token sources")
	}
	var unauth interface{ GRPCStatus() *status.Status }
	_ = errors.As(err, &unauth) // keep errors import honest
}
