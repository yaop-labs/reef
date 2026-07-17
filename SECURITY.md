# Security policy

Reef is an internal YAOP security layer. Report suspected vulnerabilities
privately to the YAOP maintainers; do not open a public issue containing
credentials, private keys, or a working exploit.

Security fixes are verified with the race-enabled test suite and the
`govulncheck` job before release. A release is not considered production-ready
until credential rotation failures are observable and the last-known-good
configuration remains active.
