package edge_test

import (
	"net/http"

	"github.com/yaop-labs/reef/bearer"
	"github.com/yaop-labs/reef/edge"
	"github.com/yaop-labs/reef/tlsconf"
)

// ExampleNewHTTPServer materializes a production HTTP server edge. Metrics are
// protected by default; health and readiness remain exempt.
func ExampleNewHTTPServer() {
	secured, err := edge.NewHTTPServer(edge.ServerConfig{
		Bind: "0.0.0.0:4318",
		TLS: &tlsconf.ServerConfig{
			Enabled:  true,
			CertFile: "server.crt",
			KeyFile:  "server.key",
		},
		Auth: &bearer.ServerConfig{Bearer: []bearer.Key{{
			Name:      "wisp-agents",
			TokenFile: "/etc/yaop/tokens/wisp",
		}}},
	})
	if err != nil {
		panic(err)
	}
	server := &http.Server{
		Addr:      "0.0.0.0:4318",
		Handler:   secured.Middleware(http.NewServeMux()),
		TLSConfig: secured.TLSConfig,
	}
	_ = server
}
