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
