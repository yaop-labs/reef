# reef — платформенная библиотека безопасности yaop

> Статус: **M1–M3 реализованы**: `tlsconf`, `bearer`, `grpcreef`,
> `reefclient`, `reeftest` + hot-reload сертификатов без рестарта (mtime-кэш
> в `GetCertificate`/`GetClientCertificate`, TTL 5s, без новых зависимостей).
> build/vet/`go test -race`/golangci-lint v2 чистые. Осталось: **M4**
> (миграции продуктов). Решение о создании: безопасность встроенная, общая
> библиотека, не сервис.

**Что это:** один Go-модуль, который даёт всем продуктам платформы
(wisp / coral / amber / fathom) одинаковые TLS/mTLS и bearer-auth на каждом
ребре — сервер и клиент, HTTP и gRPC — с одинаковой YAML-схемой конфига и
одинаковой семантикой ошибок.

**Почему библиотека, а не сервис:** платформа single-node; отдельный
auth-сервис — лишний процесс, лишний хоп и лишняя точка отказа. Ядро уже
существует и проверено в wisp (`wisp/internal/tlsconfig` + bearer в
receiver) — reef это его выделение, хардениг и распространение на всех.

**Имя:** «reef» — риф, естественный защитный барьер вокруг лагуны; морская
семья с coral/fathom. Альтернативы, если не ляжет: `hull` (корпус судна),
`keel`. Перед публичным анонсом проверить коллизии доменов/проектов (как и
для fathom).

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

**Что перезагружается на лету:** TLS-сертификаты (`cert_file`/`key_file`)
подхватываются без рестарта — mtime-кэш в `GetCertificate`/
`GetClientCertificate`, TTL 5s. Bearer-**токены** так не работают: `token_file`
читается один раз при старте, ротация токена требует перезапуска процесса.

