export const config = {
  port: Number(Bun.env.PORT ?? "4430"),
  adminUser: Bun.env.ADMIN_BASIC_AUTH_USERNAME ?? "",
  adminPass: Bun.env.ADMIN_BASIC_AUTH_PASSWORD ?? "",
  masterKeyExpiration: Number(Bun.env.MASTER_KEY_EXPIRATION ?? "300"),
  availableEnvironments: (
    Bun.env.AVAILABLE_ENVIRONMENTS ?? "development,staging,production"
  ).split(","),
  dbPath: Bun.env.DB_PATH ?? "./data/seklok.db",
} as const;
