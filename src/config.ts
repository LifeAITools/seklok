export const config = {
  port: Number(Bun.env.PORT ?? "4430"),
  adminUser: Bun.env.ADMIN_BASIC_AUTH_USERNAME ?? "",
  adminPass: Bun.env.ADMIN_BASIC_AUTH_PASSWORD ?? "",
  masterKeyExpiration: Number(Bun.env.MASTER_KEY_EXPIRATION ?? "300"),
  availableEnvironments: (
    Bun.env.AVAILABLE_ENVIRONMENTS ?? "development,staging,production"
  ).split(","),
  dbPath: Bun.env.DB_PATH ?? "./data/seklok.db",
  sessionSecret: Bun.env.SESSION_SECRET ?? "change-me-in-production",
  sessionTtl: Number(Bun.env.SESSION_TTL ?? "604800"),
  googleClientId: Bun.env.GOOGLE_CLIENT_ID ?? "",
  googleClientSecret: Bun.env.GOOGLE_CLIENT_SECRET ?? "",
  googleRedirectUri: Bun.env.GOOGLE_REDIRECT_URI ?? "",
  smtpHost: Bun.env.SMTP_HOST ?? "smtp.muid.io",
  smtpPort: Number(Bun.env.SMTP_PORT ?? "587"),
  smtpUser: Bun.env.SMTP_USER ?? "",
  smtpPass: Bun.env.SMTP_PASS ?? "",
  smtpFrom: Bun.env.SMTP_FROM ?? "noreply@seklok.com",
  appUrl: Bun.env.APP_URL ?? "http://localhost:8099",
} as const;
