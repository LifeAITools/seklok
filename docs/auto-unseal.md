# Auto-unseal — design, threat model, and roadmap

## Background

Seklok stores every secret encrypted with a per-project **master key**. The
master key is generated when the project is created, shown to the operator
*once*, and then never persisted in plaintext on the server. The server stores
only `SHA-256(master_key)` so it can later verify a key the operator provides.

This is a deliberate **sealed-by-default** model: an attacker who steals the
SQLite database (`/app/data/seklok.db`) cannot decrypt any secrets unless they
also obtain the master keys, which exist only in admin memory after a manual
`POST /admin/projects/:id/unseal`.

The trade-off is operational: every server restart re-seals every project, so
the operator must unseal each one again before the admin UI can decrypt or
issue new service tokens. **API consumers (those holding service tokens) are
unaffected** — the master key is encoded in the public token itself.

This document describes the four-tier strategy Seklok offers for managing this
trade-off, ordered from "no security loss but high ops cost" to
"defence-in-depth via external KMS".

---

## Tier 1 — Manual unseal (default)

What it is: the original Vault-style flow. After every restart an admin opens
each sealed project in the UI and pastes its master key, or POSTs the key to
`/admin/projects/:id/unseal`.

When to use:
- Multi-tenant deployments where the operator does not legitimately know all
  master keys (e.g. self-service SaaS tier of Seklok).
- Compliance environments where "no plaintext key on the host filesystem" is
  a hard requirement.

Cost: an admin must be available within the consumer-tolerance window after
every restart. Acceptable for environments with rare, scheduled restarts.

Status: always available, no flags needed.

---

## Tier 2 — Manual unseal helper script

What it is: `scripts/seklok-unseal.sh` — a thin client that fetches master
keys from the operator's password vault (1Password CLI, `pass`, or a JSON
keyfile) and POSTs them to `/admin/projects/:id/unseal` for every sealed
project.

Why this is meaningfully different from Tier 3: the keys live in the
*operator's* secret manager (which is presumably what holds the operator's
own credentials anyway). They never persist on the seklok host. The script is
run interactively after a restart, so the human-in-the-loop trust boundary
is preserved.

When to use:
- Single-operator self-hosted deployments (e.g. `secrets.muid.io`).
- Operators who already keep master keys in 1Password / `pass` / Bitwarden.

Cost: operator must run the script after each restart. ~5 seconds of attention.

Status: provided. See script `--help` for invocation.

```bash
SEKLOK_ADMIN_USER=admin SEKLOK_ADMIN_PASS='***' \
  scripts/seklok-unseal.sh --url https://secrets.muid.io --1password "Personal"
```

---

## Tier 3 — Keyfile-based auto-unseal at boot

What it is: `SEKLOK_AUTO_UNSEAL_FILE=/path/to/keys.json` — at startup, after
DB migrations, the server reads this file and unseals every listed project.

File format:
```json
{
  "1": "MhTwd7y9...master-key-for-project-1=",
  "2": "8KP3fGz...master-key-for-project-2="
}
```

File requirements:
- Mode **0600** or **0400** (no group/other access). Looser modes are refused
  at boot with a logged error and the feature deactivates for that run.
- Keys are validated against `master_key_hash` from the DB. Stale or wrong
  keys are skipped with a log line and the project remains sealed.
- Plaintext keys are never logged. Status logs show only project IDs and
  outcomes.

Threat model — what auto-unseal protects against:
- ✅ DB-only theft (e.g. restored backup of `seklok.db` to attacker's host)
- ✅ Container image theft (if the keyfile is bind-mounted from the host, not
  baked into the image)

Threat model — what auto-unseal does NOT protect against:
- ❌ Host filesystem compromise (attacker reads both the DB and the keyfile)
- ❌ Container compromise via volume mount (attacker reads the bind-mounted
  keyfile from inside the container)
- ❌ Malicious operator with shell access to the host

In short: **auto-unseal trades the seal-by-default guarantee for ops
convenience**. It is appropriate when the host's overall security boundary is
already trusted (single-tenant, dedicated host, restrictive ingress).

When to use:
- Self-hosted single-tenant deployments where the operator is the only person
  with shell access to the host.
- CI/CD ephemeral environments where projects auto-unseal after each redeploy.

When NOT to use:
- Multi-tenant SaaS deployments.
- Hosts shared with services/admins outside your trust boundary.
- Anywhere "compliance: no plaintext keys at rest" applies.

Implementation:
- Code: `src/lib/master-keys.ts::autoUnseal()` (production wiring) and
  `autoUnsealWithDeps()` (DI variant for testing).
- Status: surfaced in `GET /api/v1/status` as `auto_unseal_enabled: bool`.
- Tests: `tests/auto-unseal.test.ts` — 19 cases covering happy path, mode
  refusal, hash mismatch, malformed JSON, partial success, log-leak prevention.

Recommended setup on a host running seklok in Docker:
```bash
sudo install -m 0600 -o ubuntu -g ubuntu /dev/null /opt/seklok/secrets/unseal.json
# Edit /opt/seklok/secrets/unseal.json with project keys
# Then mount it read-only into the container:
```
```yaml
# docker-compose.prod.yml addition
services:
  seklok:
    volumes:
      - ./data:/app/data
      - ./secrets/unseal.json:/run/seklok/unseal.json:ro
    environment:
      SEKLOK_AUTO_UNSEAL_FILE: /run/seklok/unseal.json
```

After every `seklok rotate` (key rotation), update the keyfile or the next
restart will leave that project sealed (the `master_key_hash` will no longer
match the old key, and auto-unseal will refuse to load the stale value).

---

## Tier 4 — External KMS unwrap (designed, not implemented)

### Problem

Tiers 1–3 keep master keys either in operator memory, in a password manager,
or on the seklok host filesystem. None of them defend against host compromise
without losing ops convenience.

External KMS (AWS KMS, GCP KMS, HashiCorp Vault transit, HSM) provides a
fourth option: the seklok host stores only **wrapped (encrypted) master keys**
plus the IAM credentials needed to call `Unwrap` on the KMS at boot. An
attacker who steals the host gets the wrapped keys, but can't unwrap them
without also compromising the KMS or the IAM credentials.

### Sketch

1. New env var `SEKLOK_KMS_PROVIDER` (one of: `aws`, `gcp`, `vault-transit`).
2. New env var `SEKLOK_KMS_WRAPPED_KEYS_FILE` — path to a JSON file:
   `{ "<projectId>": "base64(wrapped-master-key)" }`. This file CAN be world-readable
   (mode 0644) because the wrapped keys are unusable without KMS access.
3. New env vars per provider:
   - AWS: `AWS_REGION`, `SEKLOK_KMS_KEY_ARN`, plus standard AWS SDK auth chain
   - GCP: `GOOGLE_APPLICATION_CREDENTIALS`, `SEKLOK_KMS_KEY_NAME`
   - Vault: `VAULT_ADDR`, `VAULT_TOKEN`, `SEKLOK_KMS_TRANSIT_KEY`
4. At boot, after `initDb`, call `kmsUnwrap(wrappedKey)` for each entry and
   feed the unwrapped key into `setMasterKey`.
5. New admin endpoint `POST /admin/projects/:id/wrap` — takes a plaintext
   master key, calls `kmsWrap()`, appends the result to the wrapped-keys
   file, and acknowledges. Operator runs this once per project to enrol it
   into KMS-managed auto-unseal.

### Module shape

```typescript
// src/lib/kms/index.ts
export interface KmsProvider {
  wrap(plaintext: string): Promise<string>;   // returns base64 ciphertext
  unwrap(ciphertext: string): Promise<string>; // returns plaintext
  describe(): { provider: string; keyId: string };
}
export function getKmsProvider(): KmsProvider | null;

// src/lib/kms/aws.ts        — implements via @aws-sdk/client-kms
// src/lib/kms/gcp.ts        — implements via @google-cloud/kms
// src/lib/kms/vault.ts      — implements via fetch() to /v1/transit/...
// src/lib/kms/null.ts       — fallback when SEKLOK_KMS_PROVIDER unset
```

`autoUnsealWithDeps` already takes `unseal()` and `validate()` callbacks, so
the KMS path can be wired in by composing a different dependency set without
changing the core auto-unseal logic.

### Why not implement now

1. Adds 1–2 new transitive dependencies (AWS SDK ~5 MB, GCP SDK similar).
2. Requires actual KMS credentials to test meaningfully — current ops setup
   does not have KMS provisioned.
3. Tier 3 already solves the immediate ops pain for `secrets.muid.io`.
4. The interface should be designed against a real KMS, not in the abstract.

Track this as future work in SynqTask: tag with "phase-4 / kms".

---

## Decision matrix

| Deployment | Recommended tier | Why |
|------------|------------------|-----|
| Local dev | Tier 1 | Restarts are cheap; dev secrets are throwaway |
| Single-tenant, single-operator self-hosted (e.g. `secrets.muid.io`) | Tier 2 or Tier 3 | Pick Tier 2 if you don't want any plaintext on host. Tier 3 if you want true zero-touch restarts. |
| Multi-tenant SaaS | Tier 1 only (until Tier 4 ships) | Can't store other tenants' keys on host |
| Compliance-bound (SOC 2, ISO 27001 with cryptography controls) | Tier 1 + audit log, or Tier 4 with KMS | Plaintext-at-rest typically forbidden |

---

## Operator runbook

### Enabling Tier 3 on `secrets.muid.io`

1. Log in as admin and unseal every project as you normally would.
2. From a trusted local machine (NOT the server), run:
   ```bash
   SEKLOK_ADMIN_USER=admin SEKLOK_ADMIN_PASS=*** \
     scripts/seklok-unseal-export.sh > unseal.json   # NOTE: this script doesn't exist yet — see TODO
   ```
   (Until that script exists, build the JSON manually from your password
   vault.)
3. Verify file permissions: `ls -l unseal.json` → must show `-rw-------`.
4. Copy the file to the server with restrictive perms:
   ```bash
   scp -p unseal.json muid.io:/opt/seklok/secrets/unseal.json
   ssh muid.io "chmod 0600 /opt/seklok/secrets/unseal.json && chown ubuntu:ubuntu /opt/seklok/secrets/unseal.json"
   ```
5. Update `/opt/seklok/.env.prod`:
   ```
   SEKLOK_AUTO_UNSEAL_FILE=/run/seklok/unseal.json
   ```
6. Update `/opt/seklok/docker-compose.prod.yml` to bind-mount the file (see
   recommended setup above).
7. Restart: `docker compose -f docker-compose.prod.yml up -d --force-recreate`.
8. Verify: `curl https://secrets.muid.io/api/v1/status` should show
   `"projects_unsealed": <total>` and `"auto_unseal_enabled": true`.

### After every key rotation

The keyfile becomes stale immediately. Rotate the entry in your password
vault, regenerate `unseal.json`, scp it back to the server, and **either**
restart seklok **or** call `POST /admin/projects/:id/unseal` with the new
key — the next restart will then auto-unseal correctly.

If you forget to update the keyfile, auto-unseal will simply skip the rotated
project (logged: `HASH MISMATCH for project id=N`). The project remains
sealed and the operator can unseal manually.

---

## Audit log signature

Every auto-unseal attempt logs (one per project, plus a summary):

```
[seklok][auto-unseal] unsealed project id=3 (kiberos-bot)
[seklok][auto-unseal] HASH MISMATCH for project id=2 (torq-platform) — keyfile contains a stale or wrong key. Skipped. Update keyfile after rotation.
[seklok][auto-unseal] summary: 4 unsealed, 1 hash_mismatch, 0 unknown_project, 0 warnings
```

These lines appear in `docker logs seklok-ts` and are safe to ship to a
log aggregator: they contain no plaintext keys.
