import { Hono } from "hono";
import { getDb, type Project } from "../../db.js";
import { generateKeyB64 } from "../../lib/encryption.js";
import {
  prepareMasterKey,
  validateMasterKey,
  setMasterKey,
} from "../../lib/master-keys.js";
import { serviceTokenAuth } from "../../middleware/service-token.js";
import { requireRight } from "../../middleware/rbac.js";

const app = new Hono();

app.use("*", serviceTokenAuth);

// GET / — list projects
app.get("/", requireRight("read"), (c) => {
  try {
    const db = getDb();
    const projects = db
      .query<Project, []>("SELECT id, name, description, parent_id FROM projects")
      .all();
    return c.json({ projects });
  } catch (e) {
    return c.json(
      { error: "BadRequest", message: e instanceof Error ? e.message : "Unknown error" },
      400
    );
  }
});

// POST / — create project
app.post("/", requireRight("admin"), async (c) => {
  try {
    const body = await c.req.json<{
      name: string;
      description?: string;
      parent_id?: number;
    }>();

    if (!body.name) {
      return c.json({ error: "BadRequest", message: "name is required" }, 400);
    }

    const db = getDb();
    const masterKey = generateKeyB64();

    const stmt = db.prepare<void, [string, string, number | null]>(
      `INSERT INTO projects (name, description, parent_id) VALUES (?, ?, ?)`
    );
    stmt.run(body.name, body.description ?? "", body.parent_id ?? null);

    const project = db
      .query<Project, [string]>("SELECT * FROM projects WHERE name = ?")
      .get(body.name);

    if (!project) {
      return c.json({ error: "InternalError", message: "Failed to create project" }, 500);
    }

    return c.json(
      { project: { id: project.id, name: project.name }, master_key: masterKey },
      201
    );
  } catch (e) {
    return c.json(
      { error: "BadRequest", message: e instanceof Error ? e.message : "Unknown error" },
      400
    );
  }
});

// DELETE /:id — delete project
app.delete("/:id", requireRight("admin"), (c) => {
  try {
    const projectId = Number(c.req.param("id"));
    const db = getDb();

    const project = db
      .query<Project, [number]>("SELECT * FROM projects WHERE id = ?")
      .get(projectId);

    if (!project) {
      return c.json({ error: "NotFound", message: "Project not found" }, 404);
    }

    db.prepare<void, [number]>("DELETE FROM projects WHERE id = ?").run(projectId);

    return c.json({ deleted: true });
  } catch (e) {
    return c.json(
      { error: "BadRequest", message: e instanceof Error ? e.message : "Unknown error" },
      400
    );
  }
});

// POST /:id/unseal — unseal project with master key
app.post("/:id/unseal", requireRight("read"), async (c) => {
  try {
    const projectId = Number(c.req.param("id"));
    const body = await c.req.json<{ master_key: string }>();

    if (!body.master_key) {
      return c.json({ error: "BadRequest", message: "master_key is required" }, 400);
    }

    const preparedKey = prepareMasterKey(body.master_key);
    const valid = validateMasterKey(projectId, preparedKey);

    if (!valid) {
      return c.json(
        { error: "BadRequest", message: "Invalid master key" },
        400
      );
    }

    setMasterKey(projectId, preparedKey);

    return c.json({ unsealed: true });
  } catch (e) {
    return c.json(
      { error: "BadRequest", message: e instanceof Error ? e.message : "Unknown error" },
      400
    );
  }
});

export default app;
