# dsh-access-review-proof

**Maintainer / Author：He Fangsheng (贺方升 / 贺去病; also known as Dosen) · [hequbing.com](https://www.hequbing.com)**

Offline, deterministic evidence for one narrow question: **does the supplied access-review campaign cover every declared entitlement, satisfy its risk-based review stages, and close each keep/revoke decision into a fresh post-review inventory?**

The same headless core is exposed as a DSH bundle, standalone MCP stdio server, JavaScript API and CLI. Reports are redacted, content-addressed and verified after writing.

## Complementary boundary

Microsoft Entra access reviews govern and recertify access to groups, applications, access packages and roles. This plugin only verifies supplied structured evidence; it is not an identity-governance platform.

- `dsh-principal-binding-proof` verifies which authority and principal an evidence chain binds.
- `dsh-policy-waiver-proof` verifies a declared policy exception.
- `dsh-break-glass-settlement-proof` verifies closure of one emergency-access session.
- This plugin checks a complete declared entitlement inventory, staged reviewer decisions, applied keep/revoke closure and a post-review snapshot.

It never approves, keeps or revokes access; authenticates receipts; queries live identity infrastructure; or proves the supplied inventory contains every real entitlement. A supplied closure or snapshot is evidence to authenticate elsewhere.

## Checks

- review start, completion, due date, closure, snapshot and evaluation chronology;
- exact coverage of the declared entitlement set;
- risk-based stage counts and contiguous ordered decisions;
- independent reviewers for configured high-risk classes, excluding self-review;
- a common review binding across decisions, closures and snapshot;
- one closure per entitlement, after review completion;
- final `keep`/`revoke` decisions matching `active`/`revoked` closures;
- non-zero application receipts for revocations;
- exact active/revoked partition in the post-review snapshot;
- observer diversity and evidence freshness;
- secret/raw rejection, workspace confinement, symlink defense and content-addressed read-back.

## Use

```bash
npm test
npm run check
node bin/dsh-access-review-proof.mjs inspect examples/closed.json
node bin/dsh-access-review-proof.mjs verify examples/closed.json
```

```bash
dsh plugin --profile <profile> add /absolute/path/to/dsh-access-review-proof
dsh plugin --profile <profile> add github:dongsheng123132/dsh-access-review-proof#<commit>
```

DSH tools are `dsh_access_review_inspect` and `dsh_access_review_verify`. MCP tools are `access_review_inspect` and `access_review_verify`.

See [`examples/closed.json`](examples/closed.json). Only public IDs, timestamps, counts and SHA-256 bindings belong in a manifest. Never put credentials, account names, tokens, raw identity exports or business text in it.

References: [Microsoft Entra access reviews overview](https://learn.microsoft.com/en-us/entra/id-governance/access-reviews-overview), [plan an access reviews deployment](https://learn.microsoft.com/en-us/entra/id-governance/deploy-access-reviews), [complete an access review](https://learn.microsoft.com/en-us/entra/id-governance/complete-access-review).
