/**
 * Lazy config: every property is computed from `Bun.env` at access time.
 *
 * Why lazy? Eagerly reading env at module-eval baked values into the module
 * cache before tests had a chance to set them, causing cross-file test bleed.
 * Lazy access also lets late-loaded secret-manager providers (e.g. Doppler,
 * Vault agent) inject values after the module graph is built but before the
 * server starts handling requests.
 */
export const config = {
  get port() { return Number(Bun.env.PORT ?? "4430"); },
  get adminUser() { return Bun.env.ADMIN_BASIC_AUTH_USERNAME ?? ""; },
  get adminPass() { return Bun.env.ADMIN_BASIC_AUTH_PASSWORD ?? ""; },
  /** TTL after which an unsealed master key is purged from memory (seconds). */
  get masterKeyExpiration() { return Number(Bun.env.MASTER_KEY_EXPIRATION ?? "300"); },
  /**
   * If true, master keys never auto-expire and are kept in memory until process exit.
   * Useful for self-hosted single-tenant deployments where consumers need uninterrupted
   * access via the admin UI between restarts. Auto-reseal still happens on process exit
   * (in-memory map is gone). Default false (Vault-style auto-reseal preserved).
   */
  get masterKeyDisableAutoReseal() {
    return (Bun.env.MASTER_KEY_DISABLE_AUTO_RESEAL ?? "").toLowerCase() === "true";
  },
  get availableEnvironments() {
    return (Bun.env.AVAILABLE_ENVIRONMENTS ?? "development,staging,production").split(",");
  },
  get dbPath() { return Bun.env.DB_PATH ?? "./data/seklok.db"; },
  /**
   * Path to a JSON keyfile used for opt-in auto-unseal at startup.
   * File format: { "<projectId>": "<masterKey>", ... }
   * File MUST be mode 0600 (or 0400). Wider modes are refused at startup.
   * Empty value disables the feature (default).
   *
   * SECURITY TRADE-OFF: enabling auto-unseal means an attacker with host access
   * gains the same access as a legitimate admin who has unsealed every project.
   * The Vault-style sealed-by-default model is sacrificed for ops convenience.
   * See README §Auto-unseal for full threat-model discussion.
   */
  get autoUnsealFile() { return Bun.env.SEKLOK_AUTO_UNSEAL_FILE ?? ""; },
  get sessionSecret() { return Bun.env.SESSION_SECRET ?? "change-me-in-production"; },
  get sessionTtl() { return Number(Bun.env.SESSION_TTL ?? "604800"); },
  get googleClientId() { return Bun.env.GOOGLE_CLIENT_ID ?? ""; },
  get googleClientSecret() { return Bun.env.GOOGLE_CLIENT_SECRET ?? ""; },
  get googleRedirectUri() { return Bun.env.GOOGLE_REDIRECT_URI ?? ""; },
  get smtpHost() { return Bun.env.SMTP_HOST ?? "smtp.muid.io"; },
  get smtpPort() { return Number(Bun.env.SMTP_PORT ?? "587"); },
  get smtpUser() { return Bun.env.SMTP_USER ?? ""; },
  get smtpPass() { return Bun.env.SMTP_PASS ?? ""; },
  get smtpFrom() { return Bun.env.SMTP_FROM ?? "noreply@seklok.com"; },
  get appUrl() { return Bun.env.APP_URL ?? "http://localhost:8099"; },
};
