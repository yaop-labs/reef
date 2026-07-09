package bearer_test

import (
	"net/http"

	"github.com/yaop-labs/reef/bearer"
)

// ExampleRequire guards a mux with bearer auth; /healthz, /readyz and /metrics
// stay open by default so orchestrators and scrapers carry no secret.
func ExampleRequire() {
	mw, err := bearer.Require(&bearer.ServerConfig{
		Bearer: []bearer.Key{{Name: "ci", TokenEnv: "YAOP_CI_TOKEN"}},
	})
	if err != nil {
		panic(err)
	}
	mux := http.NewServeMux()
	_ = http.ListenAndServe(":8080", mw(mux))
}

// ExampleTransport injects the exporter's bearer token on every outgoing
// request that does not already carry an Authorization header.
func ExampleTransport() {
	rt, err := bearer.Transport(&bearer.ClientConfig{TokenFile: "/etc/yaop/tokens/this-agent"}, nil)
	if err != nil {
		panic(err)
	}
	// Every request this client makes now carries Authorization: Bearer <token>,
	// unless the request already sets the header itself.
	client := &http.Client{Transport: rt}
	resp, err := client.Get("https://coral.internal/v1/push")
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()
}
