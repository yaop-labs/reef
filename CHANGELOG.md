# Changelog

## Unreleased (target: v0.3.0)

The v0.3 release is the internal production-readiness milestone for Reef.

Already present in this working baseline:

- unified `edge` HTTP and gRPC policy entry points;
- fail-closed handling for external plaintext and bearer credentials;
- managed TLS and bearer file loading with atomic last-known-good state;
- race-tested HTTP, gRPC, TLS, bearer, and credential packages;
- CI checks for formatting, build, race tests, coverage, lint, and vulnerabilities.

Remaining release gates:

- observable credential lifecycle (generation, last success/failure, expiry,
  callback and `Close` semantics);
- bearer and CA rotation without process restart, including half-written and
  delete/restore cases;
- provider-aware HTTP and gRPC transport/credential integration;
- principal/audit hooks and final token-hygiene limits;
- rotation, concurrency, and fuzz coverage on a clean CI runner.

## v0.1.0

Initial Reef security primitives.
