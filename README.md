# reef — платформенная библиотека безопасности yaop

## TL;DR интеграции

```go
// HTTP-сервер (любой продукт)
tlsCfg, err := tlsconf.Server(cfg.TLS) // *tls.Config или nil (plaintext только при полностью пустом блоке)
mw, err := bearer.Require(cfg.Auth)    // exempt по умолчанию: /healthz, /readyz, /metrics
srv := &http.Server{Handler: mw(mux), TLSConfig: tlsCfg}

// gRPC-сервер
opts, err := grpcreef.ServerOptions(cfg.TLS, cfg.Auth)
s := grpc.NewServer(opts...)

// HTTP-клиент (экспортёр)
rt, err := reefclient.Transport(reefclient.Config{TLS: cfg.Client.TLS, Auth: cfg.Client.Auth})

// gRPC-клиент
conn, err := grpcreef.Dial(ctx, addr, cfg.Client.TLS, cfg.Client.Auth)
```
