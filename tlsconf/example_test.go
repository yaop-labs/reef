package tlsconf_test

import (
	"log/slog"
	"net/http"

	"github.com/yaop-labs/reef/bearer"
	"github.com/yaop-labs/reef/tlsconf"
)

// ExampleServer wires TLS and bearer auth onto an HTTP receiver — the shape
// every server edge on the platform uses.
func ExampleServer() {
	tlsCfg, err := tlsconf.Server(&tlsconf.ServerConfig{
		Enabled:  true,
		CertFile: "/etc/yaop/tls/server.crt",
		KeyFile:  "/etc/yaop/tls/server.key",
	})
	if err != nil {
		panic(err)
	}
	tlsconf.WarnIfPlaintext(slog.Default(), "otlp-receiver", tlsCfg != nil)

	mw, err := bearer.Require(&bearer.ServerConfig{
		Bearer: []bearer.Key{{Name: "wisp-agents", TokenFile: "/etc/yaop/tokens/wisp"}},
	})
	if err != nil {
		panic(err)
	}

	mux := http.NewServeMux()
	srv := &http.Server{Addr: ":5318", Handler: mw(mux), TLSConfig: tlsCfg}
	_ = srv
}
