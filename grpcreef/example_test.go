package grpcreef_test

import (
	"google.golang.org/grpc"

	"github.com/yaop-labs/reef/bearer"
	"github.com/yaop-labs/reef/edge"
	"github.com/yaop-labs/reef/grpcreef"
	"github.com/yaop-labs/reef/tlsconf"
)

// ExampleServerOptions builds a gRPC server with TLS credentials and bearer
// interceptors from the shared config blocks.
func ExampleServerOptions() {
	opts, err := grpcreef.ServerOptions(
		&tlsconf.ServerConfig{Enabled: true, CertFile: "server.crt", KeyFile: "server.key"},
		&bearer.ServerConfig{Bearer: []bearer.Key{{Name: "coral", TokenFile: "/etc/yaop/tokens/coral"}}},
	)
	if err != nil {
		panic(err)
	}
	srv := grpc.NewServer(opts...)
	_ = srv
}

// ExampleNewEdgeClient opens a policy-validated production client.
func ExampleNewEdgeClient() {
	conn, warnings, err := grpcreef.NewEdgeClient(edge.ClientConfig{
		Target: "coral.internal:4317",
		TLS:    &tlsconf.ClientConfig{Enabled: true, CAFile: "ca.crt", ServerName: "coral.internal"},
		Auth:   &bearer.ClientConfig{TokenFile: "/etc/yaop/tokens/this-agent"},
	})
	if err != nil {
		panic(err)
	}
	_ = warnings
	defer conn.Close()
}

// ExampleNewClient opens a lazy client connection that presents the bearer
// token per RPC.
func ExampleNewClient() {
	conn, err := grpcreef.NewClient(
		"coral.internal:4317",
		&tlsconf.ClientConfig{Enabled: true, CAFile: "ca.crt", ServerName: "coral.internal"},
		&bearer.ClientConfig{TokenFile: "/etc/yaop/tokens/this-agent"},
	)
	if err != nil {
		panic(err)
	}
	defer conn.Close()
}
