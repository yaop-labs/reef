package reefclient_test

import (
	"net/http"

	"github.com/yaop-labs/reef/bearer"
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
