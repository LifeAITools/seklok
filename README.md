# Seklok

Open-source secrets manager for developers. Simple, fast, self-hosted.

## Features

- Zero-config secret storage
- Environment-based access control
- CLI & API access
- Self-hosted — your secrets stay on your infrastructure

## Quick Start

```bash
docker run -p 8099:8099 ghcr.io/lifeaitools/seklok
```

## Development

```bash
bun install
bun run index.ts
```

## API

### Health Check
```
GET /health
```

### Waitlist (Pre-launch)
```
POST /api/waitlist
Content-Type: application/json

{"email": "user@example.com"}
```

## Operations

### Auto-unseal (opt-in)

By default Seklok is **sealed-by-default**: master keys live only in admin
memory after a manual unseal. Restarting the server re-seals every project,
which means an admin must re-unseal each one before the admin UI can issue
new service tokens.

Existing service tokens **continue working without re-unseal** — they embed
the master key in the token itself.

Three patterns are supported, each with different security trade-offs:

| Pattern | What | When to use |
|---------|------|-------------|
| Manual | Admin unseal via UI / API after each restart | Multi-tenant; compliance |
| Helper script | `scripts/seklok-unseal.sh` fetches keys from your password vault and POSTs to `/admin/projects/:id/unseal` | Single-tenant self-hosted |
| Auto-unseal at boot | `SEKLOK_AUTO_UNSEAL_FILE=/path/to/keys.json` (mode 0600) | Single-tenant; zero-touch restarts |

**Important:** auto-unseal trades the seal-by-default guarantee for ops
convenience. An attacker with host access can decrypt all secrets. See
[`docs/auto-unseal.md`](docs/auto-unseal.md) for the full threat model and
operator runbook.

### Status endpoint

```bash
curl https://your-seklok-host/api/v1/status
```

Reports `projects_unsealed`, `auto_unseal_enabled`, `auto_reseal_enabled`,
`master_key_expiration_seconds`, and DB liveness — useful for monitoring and
post-deploy verification.

## Support

- [GitHub Sponsors](https://github.com/sponsors/LifeAITools)
- [Ko-fi](https://ko-fi.com/seklok)
- Star this repo — it helps more than you think

## License

[![License: AGPL-3.0](https://img.shields.io/badge/License-AGPL%20v3-blue.svg)](https://www.gnu.org/licenses/agpl-3.0)

This project is licensed under the [GNU Affero General Public License v3.0](LICENSE).

If you modify Seklok and deploy it as a network service, you must publish your source code under the same license.

### Commercial License

For proprietary or commercial use without AGPL-3.0 copyleft obligations, a commercial license is available. Contact [info@lifeaitools.com](mailto:info@lifeaitools.com) or visit [seklok.com](https://seklok.com) for details.
