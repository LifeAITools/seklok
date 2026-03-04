import { Hono } from "hono";
import { getDb, type ServiceToken } from "../../db.js";
import {
  createServiceToken,
  encodePublicToken,
  type Right,
} from "../../lib/service-tokens.js";
import { getMasterKey } from "../../lib/master-keys.js";
import { serviceTokenAuth } from "../../middleware/service-token.js";
import { requireRight } from "../../middleware/rbac.js";

const app = new Hono();

app.use("*", serviceTokenAuth);

// GET / — list service tokens for project
app.get("/", requireRight("admin"), (c) => {
  try {
    const auth = c.get("auth");
    const db = getDb();

    const tokens = db
      .query<
        Pick<ServiceToken, "id" | "friendly_name" | "environment_id" | "rights">,
        [number]
      >(
        `SELECT id, friendly_name, environment_id, rights FROM service_tokens WHERE project_id = ?`
      )
      .all(auth.projectId);

    return c.json({ tokens });
  } catch (e) {
    return c.json(
      { error: "BadRequest", message: e instanceof Error ? e.message : "Unknown error" },
      400
    );
  }
});

// POST / — create service token
app.post("/", requireRight("admin"), async (c) => {
  try {
    const auth = c.get("auth");
    const body = await c.req.json<{
      friendly_name: string;
      environment_id: number;
      rights: Right[];
    }>();

    if (!body.friendly_name || !body.environment_id || !body.rights) {
      return c.json(
        { error: "BadRequest", message: "friendly_name, environment_id, and rights are required" },
        400
      );
    }

    const masterKey = getMasterKey(auth.projectId);
    if (!masterKey) {
      return c.json(
        { error: "Sealed", message: "Project is sealed. Unseal first." },
        400
      );
    }

    const { record, generatedToken } = createServiceToken(
      auth.projectId,
      body.environment_id,
      body.friendly_name,
      body.rights
    );

    const publicToken = encodePublicToken(masterKey, generatedToken);

    return c.json(
      {
        token: { id: record.id, friendly_name: record.friendly_name },
        public_token: publicToken,
      },
      201
    );
  } catch (e) {
    return c.json(
      { error: "BadRequest", message: e instanceof Error ? e.message : "Unknown error" },
      400
    );
  }
});

// DELETE /:id — revoke token
app.delete("/:id", requireRight("admin"), (c) => {
  try {
    const tokenId = Number(c.req.param("id"));
    const auth = c.get("auth");
    const db = getDb();

    const token = db
      .query<ServiceToken, [number, number]>(
        "SELECT * FROM service_tokens WHERE id = ? AND project_id = ?"
      )
      .get(tokenId, auth.projectId);

    if (!token) {
      return c.json({ error: "NotFound", message: "Token not found" }, 404);
    }

    db.prepare<void, [number]>("DELETE FROM service_tokens WHERE id = ?").run(tokenId);

    return c.json({ deleted: true });
  } catch (e) {
    return c.json(
      { error: "BadRequest", message: e instanceof Error ? e.message : "Unknown error" },
      400
    );
  }
});

export default app;
