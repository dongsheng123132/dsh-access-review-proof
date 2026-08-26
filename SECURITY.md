# Security Policy

Security fixes target the latest release on `main`.

This verifier is offline and non-destructive. It does not approve, keep, revoke or authenticate access; query a live identity provider; or prove that a supplied entitlement inventory is exhaustive. An `active` or `revoked` closure is only a claim inside supplied evidence until independently authenticated.

Inputs are capped at 4 MiB. Paths must be workspace-relative. Manifest and artifact paths reject symlinks. Report writes are exclusive, content-addressed and verified by read-back. Secret-shaped fields and values, account names, tokens, raw logs, prompts, bodies, content and chat text are rejected.

Report vulnerabilities privately through GitHub Security Advisories. Never attach credentials, account identifiers, production manifests, raw identity exports or private business data.
