import { Hono } from "hono";
import { getDb, type Project } from "../../db.js";
import { isProjectSealed } from "../../lib/master-keys.js";
import { config } from "../../config.js";

const startedAt = Math.floor(Date.now() / 1000);

const app = new Hono();

app.get("/", (c) => {
  try {
    const db = getDb();
    db.query("SELECT 1").get();

    const projects = db
      .query<Pick<Project, "id" | "name">, []>("SELECT id, name FROM projects")
      .all();

    const unsealed = projects.filter((p) => !isProjectSealed(p.id));

    return c.json({
      db: "up",
      uptime_seconds: Math.floor(Date.now() / 1000) - startedAt,
      projects_total: projects.length,
      projects_unsealed: unsealed.length,
      master_key_expiration_seconds: config.masterKeyExpiration,
    });
  } catch {
    return c.json({ db: "down" }, 500);
  }
});

export default app;
