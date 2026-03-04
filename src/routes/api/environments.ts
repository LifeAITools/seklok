import { Hono } from "hono";
import { getDb, type Environment } from "../../db.js";
import { serviceTokenAuth } from "../../middleware/service-token.js";
import { requireRight } from "../../middleware/rbac.js";

const app = new Hono();

app.use("*", serviceTokenAuth);

// GET / — list environments
app.get("/", requireRight("read"), (c) => {
  try {
    const db = getDb();
    const environments = db
      .query<Environment, []>("SELECT id, name FROM environments")
      .all();
    return c.json({ environments });
  } catch (e) {
    return c.json(
      { error: "BadRequest", message: e instanceof Error ? e.message : "Unknown error" },
      400
    );
  }
});

export default app;
