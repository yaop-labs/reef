// Package grpcreef adapts reef's TLS and bearer layers to gRPC: server
// options with credentials and auth interceptors, and client dial options
// with transport credentials and per-RPC token injection.
//
// This is the only reef package that imports google.golang.org/grpc, so
// products without gRPC never link it.
package grpcreef

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"

	"github.com/yaop-labs/reef/bearer"
	"github.com/yaop-labs/reef/credential"
	"github.com/yaop-labs/reef/edge"
	"github.com/yaop-labs/reef/tlsconf"
)

// ServerEdge is a managed set of gRPC server options.
type ServerEdge struct {
	Options  []grpc.ServerOption
	Warnings []edge.Warning

	tlsCredentials  *credential.Group
	authCredentials *credential.Group
}

// NewServerEdge materializes provider-aware TLS and background bearer reload.
func NewServerEdge(c edge.ServerConfig, opts ...bearer.Option) (*ServerEdge, error) {
	if err := edge.CheckServer(c); err != nil {
		return nil, err
	}
	tlsResult, err := tlsconf.MaterializeServer(c.TLS, tlsconf.Lifecycle{
		Interval: c.ReloadInterval,
		Observer: c.Observer,
	})
	if err != nil {
		return nil, fmt.Errorf("edge: server TLS: %w", err)
	}
	authResult, err := bearer.MaterializeVerifier(c.Auth, bearer.Lifecycle{
		Interval: c.ReloadInterval,
		Observer: c.Observer,
	})
	if err != nil {
		_ = tlsResult.Close()
		return nil, fmt.Errorf("edge: server auth: %w", err)
	}
	return &ServerEdge{
		Options:         serverOptions(tlsResult.Config, authResult.Verifier, opts...),
		Warnings:        joinWarnings(tlsResult.Warnings, authResult.Warnings),
		tlsCredentials:  tlsResult.Credentials,
		authCredentials: authResult.Credentials,
	}, nil
}

// CredentialStatus returns TLS and bearer lifecycle snapshots.
func (s *ServerEdge) CredentialStatus() []credential.Status {
	if s == nil {
		return nil
	}
	return append(s.tlsCredentials.Statuses(), s.authCredentials.Statuses()...)
}

// ReloadCredentials immediately checks all file-backed TLS and bearer
// credentials. Background reload remains active after the call.
func (s *ServerEdge) ReloadCredentials() error {
	if s == nil {
		return nil
	}
	return errors.Join(s.tlsCredentials.ReloadNow(), s.authCredentials.ReloadNow())
}

// Close stops all background credential reload.
func (s *ServerEdge) Close() error {
	if s == nil {
		return nil
	}
	return errors.Join(s.authCredentials.Close(), s.tlsCredentials.Close())
}

// EdgeServerOptions validates the complete listener policy before assembling
// transport credentials and auth interceptors. Production callers should use
// this high-level constructor and report every returned warning.
func EdgeServerOptions(c edge.ServerConfig, opts ...bearer.Option) ([]grpc.ServerOption, []edge.Warning, error) {
	if err := edge.CheckServer(c); err != nil {
		return nil, nil, err
	}
	tlsCfg, tlsWarns, err := tlsconf.BuildServer(c.TLS)
	if err != nil {
		return nil, nil, fmt.Errorf("edge: server TLS: %w", err)
	}
	v, authWarns, err := bearer.BuildVerifier(c.Auth)
	if err != nil {
		return nil, nil, fmt.Errorf("edge: server auth: %w", err)
	}
	return serverOptions(tlsCfg, v, opts...), joinWarnings(tlsWarns, authWarns), nil
}

// ServerOptions assembles transport credentials and auth interceptors
// (unary + stream) from the two config blocks. Either block may be nil —
// that layer is then disabled. Rejection semantics: codes.Unauthenticated
// with no detail, mirroring bearer.Require's 401.
func ServerOptions(tc *tlsconf.ServerConfig, ac *bearer.ServerConfig, opts ...bearer.Option) ([]grpc.ServerOption, error) {
	tlsCfg, _, err := tlsconf.BuildServer(tc)
	if err != nil {
		return nil, err
	}

	v, _, err := bearer.BuildVerifier(ac)
	if err != nil {
		return nil, err
	}
	return serverOptions(tlsCfg, v, opts...), nil
}

func serverOptions(tlsCfg *tls.Config, v *bearer.Verifier, opts ...bearer.Option) []grpc.ServerOption {
	var out []grpc.ServerOption
	if tlsCfg != nil {
		out = append(out, grpc.Creds(credentials.NewTLS(tlsCfg)))
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
	return out
}

// DialOptions assembles the client side: transport credentials from the TLS
// block (insecure credentials when TLS is disabled), and per-RPC bearer
// credentials when a token is configured. The token is sent even over
// plaintext; RequireTransportSecurity reports false in that case.
func DialOptions(tc *tlsconf.ClientConfig, ac *bearer.ClientConfig) ([]grpc.DialOption, error) {
	tlsCfg, _, err := tlsconf.BuildClient(tc)
	if err != nil {
		return nil, err
	}

	tok, _, err := bearer.BuildClientToken(ac)
	if err != nil {
		return nil, err
	}
	return dialOptions(tlsCfg, tok), nil
}

func dialOptions(tlsCfg *tls.Config, tok string) []grpc.DialOption {
	var out []grpc.DialOption
	if tlsCfg != nil {
		out = append(out, grpc.WithTransportCredentials(credentials.NewTLS(tlsCfg)))
	} else {
		out = append(out, grpc.WithTransportCredentials(insecure.NewCredentials()))
	}
	if tok != "" {
		out = append(out, grpc.WithPerRPCCredentials(tokenCreds{
			header: "Bearer " + tok,
			secure: tlsCfg != nil,
		}))
	}
	return out
}

// EdgeDialOptions validates the complete client policy before assembling gRPC
// dial options.
func EdgeDialOptions(c edge.ClientConfig) ([]grpc.DialOption, []edge.Warning, error) {
	if err := edge.CheckClient(c); err != nil {
		return nil, nil, err
	}
	tlsCfg, tlsWarns, err := tlsconf.BuildClient(c.TLS)
	if err != nil {
		return nil, nil, fmt.Errorf("edge: client TLS: %w", err)
	}
	tok, authWarns, err := bearer.BuildClientToken(c.Auth)
	if err != nil {
		return nil, nil, fmt.Errorf("edge: client auth: %w", err)
	}
	return dialOptions(tlsCfg, tok), joinWarnings(tlsWarns, authWarns), nil
}

// Client is a managed gRPC connection.
type Client struct {
	*grpc.ClientConn
	tlsCredentials  *credential.Group
	authCredentials *credential.Group
}

// NewEdgeClient builds a lazy managed gRPC client bound to a validated target.
func NewEdgeClient(c edge.ClientConfig, extra ...grpc.DialOption) (*Client, []edge.Warning, error) {
	if err := edge.CheckClient(c); err != nil {
		return nil, nil, err
	}
	tlsResult, err := tlsconf.MaterializeClient(c.TLS, tlsconf.Lifecycle{
		Interval: c.ReloadInterval,
		Observer: c.Observer,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("edge: client TLS: %w", err)
	}
	authResult, err := bearer.MaterializeClientToken(c.Auth, bearer.Lifecycle{
		Interval: c.ReloadInterval,
		Observer: c.Observer,
	})
	if err != nil {
		_ = tlsResult.Close()
		return nil, nil, fmt.Errorf("edge: client auth: %w", err)
	}

	var dialOpts []grpc.DialOption
	if tlsResult.Provider != nil {
		dialOpts = append(dialOpts, grpc.WithTransportCredentials(&providerCredentials{
			provider: tlsResult.Provider,
		}))
	} else {
		dialOpts = append(dialOpts, grpc.WithTransportCredentials(insecure.NewCredentials()))
	}
	if authResult.Provider.Current() != "" {
		dialOpts = append(dialOpts, grpc.WithPerRPCCredentials(providerTokenCredentials{
			provider: authResult.Provider,
			secure:   tlsResult.Provider != nil,
		}))
	}
	conn, err := grpc.NewClient(c.Target, append(dialOpts, extra...)...)
	if err != nil {
		_ = authResult.Close()
		_ = tlsResult.Close()
		return nil, nil, err
	}
	return &Client{
		ClientConn:      conn,
		tlsCredentials:  tlsResult.Credentials,
		authCredentials: authResult.Credentials,
	}, joinWarnings(tlsResult.Warnings, authResult.Warnings), nil
}

// CredentialStatus returns TLS and bearer lifecycle snapshots.
func (c *Client) CredentialStatus() []credential.Status {
	if c == nil {
		return nil
	}
	return append(c.tlsCredentials.Statuses(), c.authCredentials.Statuses()...)
}

// ReloadCredentials immediately checks all file-backed TLS and bearer
// credentials. Background reload remains active after the call.
func (c *Client) ReloadCredentials() error {
	if c == nil {
		return nil
	}
	return errors.Join(c.tlsCredentials.ReloadNow(), c.authCredentials.ReloadNow())
}

// Close closes the gRPC connection and stops background reload.
func (c *Client) Close() error {
	if c == nil {
		return nil
	}
	return errors.Join(c.ClientConn.Close(), c.authCredentials.Close(), c.tlsCredentials.Close())
}

// NewClient builds the lazy client connection from the two low-level config
// blocks plus any extra options.
func NewClient(target string, tc *tlsconf.ClientConfig, ac *bearer.ClientConfig, extra ...grpc.DialOption) (*grpc.ClientConn, error) {
	dialOpts, err := DialOptions(tc, ac)
	if err != nil {
		return nil, err
	}
	return grpc.NewClient(target, append(dialOpts, extra...)...)
}

// Dial is kept for source compatibility. grpc.NewClient connects lazily, so
// ctx has never controlled connection establishment.
//
// Deprecated: use NewClient, or NewEdgeClient for enforceable edge policy.
func Dial(_ context.Context, target string, tc *tlsconf.ClientConfig, ac *bearer.ClientConfig, extra ...grpc.DialOption) (*grpc.ClientConn, error) {
	return NewClient(target, tc, ac, extra...)
}

func unaryAuth(v *bearer.Verifier, set bearer.Settings, exempt map[string]bool) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		principal, err := authorize(ctx, v, set, exempt, info.FullMethod)
		if err != nil {
			return nil, err
		}
		if principal != "" {
			ctx = bearer.ContextWithPrincipal(ctx, principal)
		}
		return handler(ctx, req)
	}
}

func streamAuth(v *bearer.Verifier, set bearer.Settings, exempt map[string]bool) grpc.StreamServerInterceptor {
	return func(srv any, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		principal, err := authorize(ss.Context(), v, set, exempt, info.FullMethod)
		if err != nil {
			return err
		}
		if principal != "" {
			ss = &principalServerStream{
				ServerStream: ss,
				ctx:          bearer.ContextWithPrincipal(ss.Context(), principal),
			}
		}
		return handler(srv, ss)
	}
}

type principalServerStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (s *principalServerStream) Context() context.Context { return s.ctx }

// authorize gates one RPC. Exempt methods (bearer.ExemptPaths, matched against
// the full method name "/pkg.Service/Method") skip auth entirely — the gRPC
// analogue of the HTTP middleware's exempt paths, e.g. the health service.
func authorize(
	ctx context.Context,
	v *bearer.Verifier,
	set bearer.Settings,
	exempt map[string]bool,
	method string,
) (string, error) {
	if exempt[method] {
		return "", nil
	}
	if md, ok := metadata.FromIncomingContext(ctx); ok {
		for _, h := range md.Get("authorization") {
			if tok, ok := bearer.FromHeader(h); ok {
				if principal, valid := v.VerifyPrincipal(tok); valid {
					if set.OnSuccess != nil {
						set.OnSuccess(remoteAddress(ctx), method, principal)
					}
					return principal, nil
				}
			}
		}
	}
	if set.OnFailure != nil {
		set.OnFailure(remoteAddress(ctx), method)
	}
	return "", status.Error(codes.Unauthenticated, "unauthorized")
}

func remoteAddress(ctx context.Context) string {
	if p, ok := peer.FromContext(ctx); ok && p.Addr != nil {
		return p.Addr.String()
	}
	return ""
}

type tokenCreds struct {
	header string
	secure bool
}

func (c tokenCreds) GetRequestMetadata(context.Context, ...string) (map[string]string, error) {
	return map[string]string{"authorization": c.header}, nil
}

func (c tokenCreds) RequireTransportSecurity() bool { return c.secure }

type providerTokenCredentials struct {
	provider *bearer.TokenProvider
	secure   bool
}

func (c providerTokenCredentials) GetRequestMetadata(context.Context, ...string) (map[string]string, error) {
	return map[string]string{"authorization": "Bearer " + c.provider.Current()}, nil
}

func (c providerTokenCredentials) RequireTransportSecurity() bool { return c.secure }

type providerCredentials struct {
	provider   *tlsconf.ClientProvider
	serverName string
}

func (c *providerCredentials) Info() credentials.ProtocolInfo {
	return credentials.ProtocolInfo{
		SecurityProtocol: "tls",
		SecurityVersion:  "1.3",
		ServerName:       c.serverName,
	}
}

func (c *providerCredentials) ClientHandshake(
	ctx context.Context,
	authority string,
	rawConn net.Conn,
) (net.Conn, credentials.AuthInfo, error) {
	serverName := c.serverName
	if serverName == "" {
		var err error
		serverName, _, err = net.SplitHostPort(authority)
		if err != nil {
			serverName = authority
		}
	}
	cfg := c.provider.ConfigForServer(serverName)
	if !containsProtocol(cfg.NextProtos, "h2") {
		cfg.NextProtos = append(cfg.NextProtos, "h2")
	}
	conn := tls.Client(rawConn, cfg)
	if err := conn.HandshakeContext(ctx); err != nil {
		_ = conn.Close()
		return nil, nil, err
	}
	state := conn.ConnectionState()
	if state.NegotiatedProtocol != "h2" {
		_ = conn.Close()
		return nil, nil, fmt.Errorf("grpcreef: TLS peer did not negotiate h2")
	}
	return conn, credentials.TLSInfo{
		State: state,
		CommonAuthInfo: credentials.CommonAuthInfo{
			SecurityLevel: credentials.PrivacyAndIntegrity,
		},
	}, nil
}

func (c *providerCredentials) ServerHandshake(net.Conn) (net.Conn, credentials.AuthInfo, error) {
	return nil, nil, errors.New("grpcreef: client transport credentials cannot accept server handshakes")
}

func (c *providerCredentials) Clone() credentials.TransportCredentials {
	return &providerCredentials{provider: c.provider, serverName: c.serverName}
}

func (c *providerCredentials) OverrideServerName(serverName string) error {
	c.serverName = serverName
	return nil
}

func containsProtocol(protocols []string, want string) bool {
	for _, protocol := range protocols {
		if protocol == want {
			return true
		}
	}
	return false
}

func joinWarnings(tlsWarns []tlsconf.Warning, authWarns []bearer.Warning) []edge.Warning {
	out := make([]edge.Warning, 0, len(tlsWarns)+len(authWarns))
	for _, warning := range tlsWarns {
		out = append(out, edge.Warning("tls: "+string(warning)))
	}
	for _, warning := range authWarns {
		out = append(out, edge.Warning("auth: "+string(warning)))
	}
	return out
}
