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

MIT
