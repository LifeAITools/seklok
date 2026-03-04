import { Hono } from "hono";
import type { SQLQueryBindings } from "bun:sqlite";
import { getDb, type Secret, type SecretValueHistory, type Project, type Environment } from "../../db.js";
import { encrypt, decrypt } from "../../lib/encryption.js";
import { serviceTokenAuth } from "../../middleware/service-token.js";
import { requireRight } from "../../middleware/rbac.js";

const app = new Hono();

app.use("*", serviceTokenAuth);

/**
 * Retrieve hierarchy secrets: query secrets for project + parent project,
 * deduplicate so child overrides parent when same name exists.
 * Port of Python retrieve_hierarchy_secrets().
 */
function retrieveHierarchySecrets(
  projectIds: number[],
  environmentId: number
): Secret[] {
  const db = getDb();
  const placeholders = projectIds.map(() => "?").join(",");
  const params: SQLQueryBindings[] = [...projectIds, environmentId];
  const rows = db
    .query<Secret, SQLQueryBindings[]>(
      `SELECT * FROM secrets
       WHERE project_id IN (${placeholders}) AND environment_id = ?
       ORDER BY name DESC, id ASC`
    )
    .all(...params);

  // Remove parent secret if child with same name exists (adjacent after sort)
  const toRemoveIndices = new Set<number>();
  for (let i = 1; i < rows.length; i++) {
    if (rows[i].name === rows[i - 1].name) {
      toRemoveIndices.add(i - 1);
    }
  }
  return rows.filter((_, idx) => !toRemoveIndices.has(idx));
}

/**
 * Get latest secret_value_histories entry for each secret_id.
 */
function latestValueHistories(
  secretIds: number[]
): Map<number, SecretValueHistory> {
  if (secretIds.length === 0) return new Map();

  const db = getDb();
  const placeholders = secretIds.map(() => "?").join(",");
  const params: SQLQueryBindings[] = [...secretIds];
  const rows = db
    .query<SecretValueHistory, SQLQueryBindings[]>(
      `SELECT svh.* FROM secret_value_histories svh
       INNER JOIN (
         SELECT secret_id, MAX(id) AS max_id
         FROM secret_value_histories
         WHERE secret_id IN (${placeholders})
         GROUP BY secret_id
       ) sub ON svh.secret_id = sub.secret_id AND svh.id = sub.max_id`
    )
    .all(...params);

  const map = new Map<number, SecretValueHistory>();
  for (const row of rows) {
    map.set(row.secret_id, row);
  }
  return map;
}

// GET / — list & decrypt secrets
app.get("/", requireRight("read"), (c) => {
  try {
    const auth = c.get("auth");
    const db = getDb();

    const project = db
      .query<Project, [number]>("SELECT * FROM projects WHERE id = ?")
      .get(auth.projectId);
    if (!project) {
      return c.json({ error: "NotFound", message: "Project not found" }, 404);
    }

    const projectIds = [auth.projectId];
    if (project.parent_id) {
      projectIds.push(project.parent_id);
    }

    const secrets = retrieveHierarchySecrets(projectIds, auth.environmentId);
    const secretIds = secrets.map((s) => s.id);
    const historyMap = latestValueHistories(secretIds);

    const result: { id: number; name: string; value: string | null }[] = [];
    for (const s of secrets) {
      const history = historyMap.get(s.id);
      let value: string | null = null;
      if (history) {
        try {
          value = decrypt(auth.masterKey, history.encrypted_value, history.iv_value);
        } catch {
          return c.json(
            {
              error: "DecryptionFailed",
              message:
                "Master key in token cannot decrypt secrets. Project may have been re-keyed. Create a new service token.",
            },
            400
          );
        }
      }
      result.push({ id: s.id, name: s.name, value });
    }

    return c.json({ secrets: result });
  } catch (e) {
    return c.json(
      { error: "BadRequest", message: e instanceof Error ? e.message : "Unknown error" },
      400
    );
  }
});

// POST / — create secret
app.post("/", requireRight("write"), async (c) => {
  try {
    const auth = c.get("auth");
    const body = await c.req.json<{ name: string; value: string; comment?: string }>();

    if (!body.name || body.value === undefined) {
      return c.json({ error: "BadRequest", message: "name and value are required" }, 400);
    }

    const db = getDb();

    const insertSecret = db.prepare<void, [number, number, string, string]>(
      `INSERT INTO secrets (project_id, environment_id, name, comment) VALUES (?, ?, ?, ?)`
    );
    insertSecret.run(auth.projectId, auth.environmentId, body.name, body.comment ?? "");

    const secret = db
      .query<Secret, [number, number, string]>(
        `SELECT * FROM secrets WHERE project_id = ? AND environment_id = ? AND name = ? ORDER BY id DESC LIMIT 1`
      )
      .get(auth.projectId, auth.environmentId, body.name);

    if (!secret) {
      return c.json({ error: "InternalError", message: "Failed to create secret" }, 500);
    }

    const { cipheredData, iv } = encrypt(auth.masterKey, body.value);

    const insertHistory = db.prepare<void, [number, string, string, string]>(
      `INSERT INTO secret_value_histories (secret_id, encrypted_value, iv_value, comment) VALUES (?, ?, ?, ?)`
    );
    insertHistory.run(secret.id, cipheredData, iv, body.comment ?? "");

    return c.json({ secret: { id: secret.id, name: secret.name } }, 201);
  } catch (e) {
    return c.json(
      { error: "BadRequest", message: e instanceof Error ? e.message : "Unknown error" },
      400
    );
  }
});

// PUT /:id — update secret value
app.put("/:id", requireRight("write"), async (c) => {
  try {
    const auth = c.get("auth");
    const secretId = Number(c.req.param("id"));
    const body = await c.req.json<{ value: string; comment?: string }>();

    if (body.value === undefined) {
      return c.json({ error: "BadRequest", message: "value is required" }, 400);
    }

    const db = getDb();
    const secret = db
      .query<Secret, [number, number, number]>(
        `SELECT * FROM secrets WHERE id = ? AND project_id = ? AND environment_id = ?`
      )
      .get(secretId, auth.projectId, auth.environmentId);

    if (!secret) {
      return c.json(
        { error: "NotFound", message: "Secret not found or does not belong to this project/environment" },
        404
      );
    }

    const { cipheredData, iv } = encrypt(auth.masterKey, body.value);

    const insertHistory = db.prepare<void, [number, string, string, string]>(
      `INSERT INTO secret_value_histories (secret_id, encrypted_value, iv_value, comment) VALUES (?, ?, ?, ?)`
    );
    insertHistory.run(secret.id, cipheredData, iv, body.comment ?? "");

    return c.json({ secret: { id: secret.id, name: secret.name } });
  } catch (e) {
    return c.json(
      { error: "BadRequest", message: e instanceof Error ? e.message : "Unknown error" },
      400
    );
  }
});

// DELETE /:id — delete secret
app.delete("/:id", requireRight("admin"), (c) => {
  try {
    const auth = c.get("auth");
    const secretId = Number(c.req.param("id"));

    const db = getDb();
    const secret = db
      .query<Secret, [number, number]>(
        `SELECT * FROM secrets WHERE id = ? AND project_id = ?`
      )
      .get(secretId, auth.projectId);

    if (!secret) {
      return c.json({ error: "NotFound", message: "Secret not found" }, 404);
    }

    db.prepare<void, [number]>("DELETE FROM secrets WHERE id = ?").run(secretId);

    return c.json({ deleted: true });
  } catch (e) {
    return c.json(
      { error: "BadRequest", message: e instanceof Error ? e.message : "Unknown error" },
      400
    );
  }
});

// GET /:id/history — value change history (timestamps only, no decrypted values)
app.get("/:id/history", requireRight("admin"), (c) => {
  try {
    const auth = c.get("auth");
    const secretId = Number(c.req.param("id"));

    const db = getDb();
    const secret = db
      .query<Secret, [number, number]>(
        `SELECT * FROM secrets WHERE id = ? AND project_id = ?`
      )
      .get(secretId, auth.projectId);

    if (!secret) {
      return c.json({ error: "NotFound", message: "Secret not found" }, 404);
    }

    const history = db
      .query<Pick<SecretValueHistory, "id" | "comment" | "created_at" | "updated_at">, [number]>(
        `SELECT id, comment, created_at, updated_at FROM secret_value_histories
         WHERE secret_id = ? ORDER BY id DESC`
      )
      .all(secretId);

    return c.json({ history });
  } catch (e) {
    return c.json(
      { error: "BadRequest", message: e instanceof Error ? e.message : "Unknown error" },
      400
    );
  }
});

// GET /missing — detect missing secrets across environments
app.get("/missing", requireRight("read"), (c) => {
  try {
    const auth = c.get("auth");
    const db = getDb();

    const project = db
      .query<Project, [number]>("SELECT * FROM projects WHERE id = ?")
      .get(auth.projectId);
    if (!project) {
      return c.json({ error: "NotFound", message: "Project not found" }, 404);
    }

    const projectIds = [auth.projectId];
    if (project.parent_id) {
      projectIds.push(project.parent_id);
    }

    const currentSecrets = retrieveHierarchySecrets(projectIds, auth.environmentId);
    const currentNames = new Set(currentSecrets.map((s) => s.name));

    const otherEnvs = db
      .query<Environment, [number]>(
        "SELECT * FROM environments WHERE id != ?"
      )
      .all(auth.environmentId);

    const missingMap = new Map<string, string[]>();

    for (const env of otherEnvs) {
      const envSecrets = retrieveHierarchySecrets(projectIds, env.id);
      for (const secret of envSecrets) {
        if (!currentNames.has(secret.name)) {
          const existing = missingMap.get(secret.name);
          if (existing) {
            existing.push(env.name);
          } else {
            missingMap.set(secret.name, [env.name]);
          }
        }
      }
    }

    const missing = Array.from(missingMap.entries()).map(([name, exists_in]) => ({
      name,
      exists_in,
    }));

    return c.json({ missing });
  } catch (e) {
    return c.json(
      { error: "BadRequest", message: e instanceof Error ? e.message : "Unknown error" },
      400
    );
  }
});

export default app;
