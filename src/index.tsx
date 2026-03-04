import { Hono } from "hono";
import { config } from "./config.js";
import { initDb } from "./db.js";

// API routes
import statusRoutes from "./routes/api/status.js";
import secretsRoutes from "./routes/api/secrets.js";
import projectsRoutes from "./routes/api/projects.js";
import serviceTokensRoutes from "./routes/api/service-tokens.js";
import environmentsRoutes from "./routes/api/environments.js";

// Admin routes
import adminProjectsRoutes from "./routes/admin/projects.js";
import adminSecretsRoutes from "./routes/admin/secrets.js";
import adminServiceTokensRoutes from "./routes/admin/service-tokens.js";

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

// Home page
app.get("/", (c) => c.html(<HomePage />));

// API routes (service token auth applied inside each route file)
app.route("/api/v1/status", statusRoutes);
app.route("/api/v1/secrets", secretsRoutes);
app.route("/api/v1/projects", projectsRoutes);
app.route("/api/v1/service-tokens", serviceTokensRoutes);
app.route("/api/v1/environments", environmentsRoutes);

// Admin routes (basic auth applied inside each route file)
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
