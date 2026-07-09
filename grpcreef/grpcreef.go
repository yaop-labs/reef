// Package grpcreef adapts reef's TLS and bearer layers to gRPC: server
// options with credentials and auth interceptors, and client dial options
// with transport credentials and per-RPC token injection.
//
// This is the only reef package that imports google.golang.org/grpc, so
// products without gRPC never link it.
package grpcreef

import (
	"context"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"

	"github.com/yaop-labs/reef/bearer"
	"github.com/yaop-labs/reef/tlsconf"
)

// ServerOptions assembles transport credentials and auth interceptors
// (unary + stream) from the two config blocks. Either block may be nil —
// that layer is then disabled. Rejection semantics: codes.Unauthenticated
// with no detail, mirroring bearer.Require's 401.
func ServerOptions(tc *tlsconf.ServerConfig, ac *bearer.ServerConfig, opts ...bearer.Option) ([]grpc.ServerOption, error) {
	var out []grpc.ServerOption

	tlsCfg, err := tlsconf.Server(tc)
	if err != nil {
		return nil, err
	}
	if tlsCfg != nil {
		out = append(out, grpc.Creds(credentials.NewTLS(tlsCfg)))
	}

	v, err := bearer.NewVerifier(ac)
	if err != nil {
		return nil, err
	}
	if v.Enabled() {
		set := bearer.Apply(opts...)
		exempt := make(map[string]bool, len(set.ExemptPaths))
		for _, p := range set.ExemptPaths {
			exempt[p] = true
		}
		out = append(out,
			grpc.ChainUnaryInterceptor(unaryAuth(v, set, exempt)),
			grpc.ChainStreamInterceptor(streamAuth(v, set, exempt)),
		)
	}
	return out, nil
}

// DialOptions assembles the client side: transport credentials from the TLS
// block (insecure credentials when disabled — single-node plaintext), and
// per-RPC bearer credentials when a token is configured. The token is sent
// even over plaintext: on a single node that is the deliberate dev mode.
func DialOptions(tc *tlsconf.ClientConfig, ac *bearer.ClientConfig) ([]grpc.DialOption, error) {
	var out []grpc.DialOption

	tlsCfg, err := tlsconf.Client(tc)
	if err != nil {
		return nil, err
	}
	if tlsCfg != nil {
		out = append(out, grpc.WithTransportCredentials(credentials.NewTLS(tlsCfg)))
	} else {
		out = append(out, grpc.WithTransportCredentials(insecure.NewCredentials()))
	}

	tok, err := bearer.ClientToken(ac)
	if err != nil {
		return nil, err
	}
	if tok != "" {
		out = append(out, grpc.WithPerRPCCredentials(tokenCreds{
			header: "Bearer " + tok,
			secure: tlsCfg != nil,
		}))
	}
	return out, nil
}

// Dial builds the client connection from the two config blocks plus any extra
// options. ctx is reserved for parity with future connect-on-dial semantics;
// the underlying grpc.NewClient connects lazily.
func Dial(_ context.Context, target string, tc *tlsconf.ClientConfig, ac *bearer.ClientConfig, extra ...grpc.DialOption) (*grpc.ClientConn, error) {
	dialOpts, err := DialOptions(tc, ac)
	if err != nil {
		return nil, err
	}
	return grpc.NewClient(target, append(dialOpts, extra...)...)
}

func unaryAuth(v *bearer.Verifier, set bearer.Settings, exempt map[string]bool) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		if err := authorize(ctx, v, set, exempt, info.FullMethod); err != nil {
			return nil, err
		}
		return handler(ctx, req)
	}
}

func streamAuth(v *bearer.Verifier, set bearer.Settings, exempt map[string]bool) grpc.StreamServerInterceptor {
	return func(srv any, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		if err := authorize(ss.Context(), v, set, exempt, info.FullMethod); err != nil {
			return err
		}
		return handler(srv, ss)
	}
}

// authorize gates one RPC. Exempt methods (bearer.ExemptPaths, matched against
// the full method name "/pkg.Service/Method") skip auth entirely — the gRPC
// analogue of the HTTP middleware's exempt paths, e.g. the health service.
func authorize(ctx context.Context, v *bearer.Verifier, set bearer.Settings, exempt map[string]bool, method string) error {
	if exempt[method] {
		return nil
	}
	if md, ok := metadata.FromIncomingContext(ctx); ok {
		for _, h := range md.Get("authorization") {
			if tok, ok := bearer.FromHeader(h); ok && v.Verify(tok) {
				return nil
			}
		}
	}
	if set.OnFailure != nil {
		remote := ""
		if p, ok := peer.FromContext(ctx); ok && p.Addr != nil {
			remote = p.Addr.String()
		}
		set.OnFailure(remote, method)
	}
	return status.Error(codes.Unauthenticated, "unauthorized")
}

type tokenCreds struct {
	header string
	secure bool
}

func (c tokenCreds) GetRequestMetadata(context.Context, ...string) (map[string]string, error) {
	return map[string]string{"authorization": c.header}, nil
}

func (c tokenCreds) RequireTransportSecurity() bool { return c.secure }
