package edge_test

import (
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/yaop-labs/reef/edge"
)

func TestPolicyYAMLTags(t *testing.T) {
	const doc = `
bind: 0.0.0.0:4318
insecure: true
danger_allow_bearer_over_plaintext: true
auth:
  bearer:
    - name: local-dev
      token: secret
`
	var cfg edge.ServerConfig
	if err := yaml.Unmarshal([]byte(doc), &cfg); err != nil {
		t.Fatal(err)
	}
	if cfg.Bind != "0.0.0.0:4318" || !cfg.Insecure || !cfg.DangerAllowBearerOverPlaintext {
		t.Fatalf("policy fields not decoded: %+v", cfg)
	}
	if len(cfg.Auth.Bearer) != 1 || cfg.Auth.Bearer[0].Name != "local-dev" {
		t.Fatalf("auth fields not decoded: %+v", cfg.Auth)
	}
	if _, err := edge.ValidateServer(cfg); err != nil {
		t.Fatalf("decoded explicit-danger config should validate: %v", err)
	}
}
