# reef — платформенная библиотека безопасности yaop

> Статус: **M1+M2 реализованы** (2026-07-07): `tlsconf`, `bearer`,
> `grpcreef`, `reefclient`, `reeftest` — build/vet/`go test -race` чистые.
> Осталось: M3 (hot-reload сертификатов) и M4 (миграции продуктов) — см.
> [docs/04-spec.md](docs/04-spec.md). Решение о создании:
> `platform-review/contract.md` §8 — «безопасность встроенная, общая
> библиотека, не сервис».

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

## Документы

| Файл | Что внутри |
|---|---|
| [docs/01-product.md](docs/01-product.md) | Цели, скоуп/не-скоуп, потребители |
| [docs/02-architecture.md](docs/02-architecture.md) | Пакеты, зависимости, интеграция с продуктами |
| [docs/03-api.md](docs/03-api.md) | **API-контракт**: Go-сигнатуры, YAML-схема, семантика ошибок |
| [docs/04-spec.md](docs/04-spec.md) | **ТЗ**: функциональные требования, критерии приёмки, тест-план, майлстоуны |

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
