import { Hono } from "hono";
import { config } from "./config.js";
import { initDb } from "./db.js";

// API routes
import statusRoutes from "./routes/api/status.js";
import secretsRoutes from "./routes/api/secrets.js";
import projectsRoutes from "./routes/api/projects.js";
import serviceTokensRoutes from "./routes/api/service-tokens.js";
import environmentsRoutes from "./routes/api/environments.js";

// Auth routes
import authRegister from "./routes/auth/register.js";
import authLogin from "./routes/auth/login.js";
import authGoogle from "./routes/auth/google.js";
import authVerify from "./routes/auth/verify.js";

// Rate limiting
import { rateLimit } from "./middleware/rate-limit.js";

// Admin routes
import adminProjectsRoutes from "./routes/admin/projects.js";
import adminSecretsRoutes from "./routes/admin/secrets.js";
import adminServiceTokensRoutes from "./routes/admin/service-tokens.js";

// Middleware
import { getCookie } from "hono/cookie";
import { getDb } from "./db.js";
import type { MiddlewareHandler } from "hono";
import type { AuthUser } from "./middleware/session.js";

// Views
import { HomePage } from "./views/home.js";

const app = new Hono();

// Global error handler - CN-01: NEVER serialize decrypted secret values
app.onError((err, c) => {
  console.error(`[seklok] Error: ${err.message}`);
  if (c.req.path.startsWith("/api/")) {
    return c.json({ error: "Internal Server Error", message: err.message }, 500);
  }
  const referer = c.req.header("referer") || "/admin/projects";
  return c.redirect(referer);
});

// Session-or-BasicAuth middleware for admin routes
const sessionOrBasicAuth: MiddlewareHandler = async (c, next) => {
  // 1. Try session cookie
  const sessionCookie = getCookie(c, "seklok_session");
  if (sessionCookie) {
    const hasher = new Bun.CryptoHasher("sha256");
    hasher.update(sessionCookie);
    const tokenHash = hasher.digest("hex");
    const db = getDb();
    const now = Math.floor(Date.now() / 1000);
    const row = db
      .query(
        `SELECT u.id, u.email, u.name, u.role, u.email_verified
         FROM sessions s JOIN users u ON s.user_id = u.id
         WHERE s.token_hash = ? AND s.expires_at > ?`
      )
      .get(tokenHash, now) as { id: string; email: string; name: string; role: string; email_verified: number } | null;

    if (row) {
      c.set("user", {
        id: row.id,
        email: row.email,
        name: row.name,
        role: row.role,
        emailVerified: row.email_verified === 1,
      } as AuthUser);
      return next();
    }
  }

  // 2. Try Basic Auth header (super-admin fallback)
  const authHeader = c.req.header("Authorization");
  if (authHeader && authHeader.startsWith("Basic ") && config.adminUser) {
    const decoded = Buffer.from(authHeader.slice(6), "base64").toString("utf-8");
    const sepIdx = decoded.indexOf(":");
    if (sepIdx !== -1) {
      const username = decoded.slice(0, sepIdx);
      const password = decoded.slice(sepIdx + 1);
      if (username === config.adminUser && password === config.adminPass) {
        const db = getDb();
        let adminRow = db
          .query("SELECT id, email, name, role, email_verified FROM users WHERE email = ? AND role = 'admin'")
          .get(config.adminUser) as { id: string; email: string; name: string; role: string; email_verified: number } | null;

        if (!adminRow) {
          const adminId = crypto.randomUUID();
          const passwordHash = await Bun.password.hash(config.adminPass, { algorithm: "argon2id" });
          db.prepare(
            "INSERT OR IGNORE INTO users (id, email, password_hash, name, role, email_verified) VALUES (?, ?, ?, ?, 'admin', 1)"
          ).run(adminId, config.adminUser, passwordHash, config.adminUser);
          adminRow = { id: adminId, email: config.adminUser, name: config.adminUser, role: "admin", email_verified: 1 };
        }

        c.set("user", {
          id: adminRow.id,
          email: adminRow.email,
          name: adminRow.name,
          role: adminRow.role,
          emailVerified: adminRow.email_verified === 1,
        } as AuthUser);
        return next();
      }
    }
  }

  // 3. No auth — redirect to login (for browser) or 401 (for API-like requests)
  if (c.req.header("Accept")?.includes("text/html")) {
    return c.redirect("/auth/login");
  }
  return c.newResponse("Unauthorized", 401, {
    "WWW-Authenticate": 'Basic realm="Login Required"',
  });
};

// Home page
app.get("/", (c) => c.html(<HomePage />));

// API routes (service token auth applied inside each route file)
app.route("/api/v1/status", statusRoutes);
app.route("/api/v1/secrets", secretsRoutes);
app.route("/api/v1/projects", projectsRoutes);
app.route("/api/v1/service-tokens", serviceTokensRoutes);
app.route("/api/v1/environments", environmentsRoutes);

// Auth rate limiting
app.use("/auth/login", rateLimit({ windowMs: 60_000, max: 10 }));
app.use("/auth/register", rateLimit({ windowMs: 60_000, max: 5 }));
app.use("/auth/resend-verification", rateLimit({ windowMs: 60_000, max: 3 }));
app.use("/auth/google", rateLimit({ windowMs: 60_000, max: 10 }));

// Auth routes
app.route("/auth", authRegister);
app.route("/auth", authLogin);
app.route("/auth", authGoogle);
app.route("/auth", authVerify);

// Admin routes (sessionOrBasicAuth applied at mount level)
app.use("/admin/*", sessionOrBasicAuth);
app.route("/admin/projects", adminProjectsRoutes);
app.route("/admin", adminSecretsRoutes);
app.route("/admin", adminServiceTokensRoutes);

// Initialize database
initDb(config.availableEnvironments);

console.log(`[seklok] Starting on port ${config.port}`);

// Graceful shutdown
process.on("SIGTERM", () => {
  console.log("[seklok] Shutting down...");
  process.exit(0);
});

export default {
  port: config.port,
  fetch: app.fetch,
};
