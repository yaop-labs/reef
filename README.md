# Reef

Current development target: **v0.3.0** (internal production-readiness
milestone). See [CHANGELOG.md](CHANGELOG.md) for release gates and
[SECURITY.md](SECURITY.md) for reporting guidance.

Reef is the shared TLS, mTLS, and bearer-token security layer for YAOP
service edges.

## Recommended high-level API

Production callers should declare the complete bind/target boundary through
`edge`. The policy rejects ambiguous external plaintext and bearer tokens over
plaintext before a server or client is created.

```go
// HTTP server.
secured, err := edge.NewHTTPServer(edge.ServerConfig{
    Bind: "0.0.0.0:4318",
    TLS:  cfg.TLS,
    Auth: cfg.Auth,
})
if err != nil {
    return err
}
for _, warning := range secured.Warnings {
    log.Warn("reef configuration warning", "warning", warning)
}
srv := &http.Server{
    Addr:      "0.0.0.0:4318",
    Handler:   secured.Middleware(mux),
    TLSConfig: secured.TLSConfig,
}
```

The production HTTP profile leaves `/healthz` and `/readyz` open but protects
`/metrics`. Products can explicitly replace the exemptions with
`bearer.ExemptPaths`.

```go
// HTTP client. The transport is bound to this origin, so redirects or reuse
// cannot send its bearer token to another service.
rt, warnings, err := reefclient.EdgeTransport(edge.ClientConfig{
    Target: "https://coral.internal:4318",
    TLS:    cfg.Client.TLS,
    Auth:   cfg.Client.Auth,
}, nil)
client := &http.Client{Transport: rt}
```

```go
// gRPC server.
opts, warnings, err := grpcreef.EdgeServerOptions(edge.ServerConfig{
    Bind: "0.0.0.0:4317",
    TLS:  cfg.TLS,
    Auth: cfg.Auth,
})
server := grpc.NewServer(opts...)

// gRPC client.
conn, warnings, err := grpcreef.NewEdgeClient(edge.ClientConfig{
    Target: "coral.internal:4317",
    TLS:    cfg.Client.TLS,
    Auth:   cfg.Client.Auth,
})
```

Only literal loopback IPs such as `127.0.0.1` and `::1` receive an automatic
plaintext allowance. DNS names, `localhost`, wildcard binds, resolver targets,
and unparsed addresses fail closed. External plaintext requires
`insecure: true`; bearer over any plaintext transport additionally requires
`danger_allow_bearer_over_plaintext: true`.

## Low-level compatibility API

`tlsconf`, `bearer`, `reefclient.Transport`, `grpcreef.ServerOptions`, and
`grpcreef.NewClient` remain available for embedded and test scenarios. They do
not know the bind/target address and therefore cannot enforce the complete edge
policy themselves.
