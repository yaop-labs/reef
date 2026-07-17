package reefclient_test

import (
	"net/http"

	"github.com/yaop-labs/reef/bearer"
	"github.com/yaop-labs/reef/edge"
	"github.com/yaop-labs/reef/reefclient"
	"github.com/yaop-labs/reef/tlsconf"
)

// ExampleTransport assembles an exporter's HTTP transport — TLS plus bearer —
// in a single call, which is what most exporters need.
func ExampleTransport() {
	rt, err := reefclient.Transport(reefclient.Config{
		TLS:  &tlsconf.ClientConfig{Enabled: true, CAFile: "/etc/yaop/tls/ca.crt", ServerName: "coral.internal"},
		Auth: &bearer.ClientConfig{TokenFile: "/etc/yaop/tokens/this-agent"},
	})
	if err != nil {
		panic(err)
	}
	client := &http.Client{Transport: rt}
	_ = client
}

// ExampleEdgeTransport builds a target-bound production transport.
func ExampleEdgeTransport() {
	rt, warnings, err := reefclient.EdgeTransport(edge.ClientConfig{
		Target: "https://coral.internal:4318",
		TLS:    &tlsconf.ClientConfig{Enabled: true, CAFile: "/etc/yaop/tls/ca.crt", ServerName: "coral.internal"},
		Auth:   &bearer.ClientConfig{TokenFile: "/etc/yaop/tokens/this-agent"},
	}, nil)
	if err != nil {
		panic(err)
	}
	_ = warnings
	client := &http.Client{Transport: rt}
	_ = client
}
