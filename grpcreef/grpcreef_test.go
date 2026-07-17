package grpcreef_test

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"

	"github.com/yaop-labs/reef/bearer"
	"github.com/yaop-labs/reef/edge"
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

func check(conn grpc.ClientConnInterface) error {
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

	serverOpts, warns, err := grpcreef.EdgeServerOptions(edge.ServerConfig{
		Bind: "127.0.0.1:4317",
		TLS:  &tlsconf.ServerConfig{Enabled: true, CertFile: certs.ServerCert, KeyFile: certs.ServerKey},
		Auth: &bearer.ServerConfig{Bearer: []bearer.Key{{Name: "a", Token: secret}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(warns) != 1 {
		t.Fatalf("want inline-token server warning, got %v", warns)
	}
	srv := grpc.NewServer(serverOpts...)
	healthpb.RegisterHealthServer(srv, health.NewServer())
	ln := bufconn.Listen(1 << 20)
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(srv.Stop)

	clientTLS := &tlsconf.ClientConfig{Enabled: true, CAFile: certs.CACert, ServerName: "localhost"}
	dialer := grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
		return ln.DialContext(ctx)
	})

	conn, warns, err := grpcreef.NewEdgeClient(edge.ClientConfig{
		Target: "passthrough:///bufnet",
		TLS:    clientTLS,
		Auth:   &bearer.ClientConfig{Token: secret},
	}, dialer)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	if len(warns) != 1 {
		t.Fatalf("want inline-token client warning, got %v", warns)
	}
	if err := check(conn); err != nil {
		t.Fatalf("tls+token check failed: %v", err)
	}

	bare, _, err := grpcreef.NewEdgeClient(edge.ClientConfig{
		Target: "passthrough:///bufnet",
		TLS:    clientTLS,
	}, dialer)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = bare.Close() })
	wantUnauthenticated(t, check(bare))
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

func TestEdgePolicyRejectsUnsafePlaintext(t *testing.T) {
	_, _, err := grpcreef.EdgeServerOptions(edge.ServerConfig{Bind: "0.0.0.0:4317"})
	if err == nil {
		t.Fatal("external plaintext server must require explicit insecure opt-in")
	}
	_, _, err = grpcreef.EdgeDialOptions(edge.ClientConfig{
		Target: "127.0.0.1:4317",
		Auth:   &bearer.ClientConfig{Token: secret},
	})
	if err == nil {
		t.Fatal("plaintext gRPC bearer must require the dedicated danger opt-in")
	}
}

func TestEdgeDialOptionsReturnWarnings(t *testing.T) {
	tokenFile := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(tokenFile, []byte(secret), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(tokenFile, 0o644); err != nil {
		t.Fatal(err)
	}
	_, warns, err := grpcreef.EdgeDialOptions(edge.ClientConfig{
		Target: "coral.internal:4317",
		TLS:    &tlsconf.ClientConfig{Enabled: true},
		Auth:   &bearer.ClientConfig{TokenFile: tokenFile},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(warns) != 1 {
		t.Fatalf("want one permission warning, got %v", warns)
	}
}

func TestManagedEdgeRotatesBearerAndPropagatesPrincipal(t *testing.T) {
	tokenFile := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(tokenFile, []byte("first"), 0o600); err != nil {
		t.Fatal(err)
	}
	serverEdge, err := grpcreef.NewServerEdge(edge.ServerConfig{
		Bind:                           "127.0.0.1:4317",
		Auth:                           &bearer.ServerConfig{Bearer: []bearer.Key{{Name: "wisp-agent", TokenFile: tokenFile}}},
		DangerAllowBearerOverPlaintext: true,
		ReloadInterval:                 time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = serverEdge.Close() })
	principals := make(chan string, 4)
	server := grpc.NewServer(serverEdge.Options...)
	healthpb.RegisterHealthServer(server, &principalHealth{principals: principals})
	listener := bufconn.Listen(1 << 20)
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(server.Stop)

	dialer := grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
		return listener.DialContext(ctx)
	})
	client, _, err := grpcreef.NewEdgeClient(edge.ClientConfig{
		Target:                         "127.0.0.1:4317",
		Auth:                           &bearer.ClientConfig{TokenFile: tokenFile},
		DangerAllowBearerOverPlaintext: true,
		ReloadInterval:                 time.Hour,
	}, dialer)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })

	if err := check(client); err != nil {
		t.Fatal(err)
	}
	if got := <-principals; got != "wisp-agent" {
		t.Fatalf("unary principal=%q", got)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	stream, err := healthpb.NewHealthClient(client).Watch(ctx, &healthpb.HealthCheckRequest{})
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	if _, err := stream.Recv(); err != nil {
		cancel()
		t.Fatal(err)
	}
	cancel()
	if got := <-principals; got != "wisp-agent" {
		t.Fatalf("stream principal=%q", got)
	}

	if err := os.WriteFile(tokenFile, []byte("second"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := serverEdge.ReloadCredentials(); err != nil {
		t.Fatal(err)
	}
	if err := client.ReloadCredentials(); err != nil {
		t.Fatal(err)
	}
	if err := check(client); err != nil {
		t.Fatal(err)
	}
	if got := <-principals; got != "wisp-agent" {
		t.Fatalf("rotated principal=%q", got)
	}
	if got := serverEdge.CredentialStatus(); len(got) != 1 || got[0].Generation != 2 {
		t.Fatalf("server status=%+v", got)
	}
	if got := client.CredentialStatus(); len(got) != 1 || got[0].Generation != 2 {
		t.Fatalf("client status=%+v", got)
	}
}

type principalHealth struct {
	healthpb.UnimplementedHealthServer
	principals chan<- string
}

func (s *principalHealth) Check(
	ctx context.Context,
	_ *healthpb.HealthCheckRequest,
) (*healthpb.HealthCheckResponse, error) {
	principal, _ := bearer.PrincipalFromContext(ctx)
	s.principals <- principal
	return &healthpb.HealthCheckResponse{Status: healthpb.HealthCheckResponse_SERVING}, nil
}

func (s *principalHealth) Watch(
	_ *healthpb.HealthCheckRequest,
	stream grpc.ServerStreamingServer[healthpb.HealthCheckResponse],
) error {
	principal, _ := bearer.PrincipalFromContext(stream.Context())
	s.principals <- principal
	return stream.Send(&healthpb.HealthCheckResponse{Status: healthpb.HealthCheckResponse_SERVING})
}
