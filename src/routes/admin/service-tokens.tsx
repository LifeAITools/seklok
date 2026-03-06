import { Hono } from "hono";
import type { FC } from "hono/jsx";
import { getDb, type Project, type Environment, type ServiceToken } from "../../db.js";
import { getMasterKey, isProjectSealed } from "../../lib/master-keys.js";
import {
  createServiceToken,
  encodePublicToken,
  type Right,
} from "../../lib/service-tokens.js";
import { Layout } from "../../views/layout.js";
import { requireAuth } from "../../middleware/session.js";
import { requireOwnerOrAdmin } from "../../middleware/ownership.js";

const app = new Hono();

app.use("*", requireAuth);

// --- helpers ---

function flashRedirect(path: string, type: string, message: string): string {
  return `${path}?flash_type=${type}&flash_msg=${encodeURIComponent(message)}`;
}

function flashFromQuery(c: { req: { query: (k: string) => string | undefined } }): { type: string; message: string } | undefined {
  const msg = c.req.query("flash_msg");
  const typ = c.req.query("flash_type") ?? "success";
  if (msg) return { type: typ, message: decodeURIComponent(msg) };
  return undefined;
}

// --- Views ---

const TokenListPage: FC<{
  project: Project;
  tokens: (ServiceToken & { environment_name: string })[];
  newPublicToken?: string;
  flash?: { type: string; message: string };
}> = (props) => {
  return (
    <Layout title="Service Tokens" flash={props.flash} projectId={props.project.id} projectName={props.project.name}>
      <h1>Service Tokens for {props.project.name}</h1>

      {props.newPublicToken && (
        <div class="warning">
          <strong>New service token generated. Back it up and keep it secret.</strong>
          <div class="copyable">
            <input id="service_token_input" type="password" value={props.newPublicToken} readonly />
            <button type="button" class="btn btn-sm" onclick="copyToClipboard('service_token_input')">Copy</button>
          </div>
        </div>
      )}

      <div class="controls">
        <a class="btn" href={`/admin/projects/${props.project.id}/service-tokens/new`}>+ New Token</a>
        <a class="btn" href={`/admin/projects/${props.project.id}`}>Back to project</a>
      </div>

      {props.tokens.length > 0 ? (
        <table>
          <thead>
            <tr>
              <th>#</th>
              <th>Name</th>
              <th>Environment</th>
              <th>Rights</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            {props.tokens.map((t) => (
              <tr>
                <td>{t.id}</td>
                <td>{t.friendly_name}</td>
                <td>{t.environment_name}</td>
                <td>{t.rights}</td>
                <td>
                  <form method="post" action={`/admin/projects/${props.project.id}/service-tokens/${t.id}/destroy`} style="display:inline">
                    <button type="submit" class="btn btn-sm btn-danger" onclick="return confirm('Are you sure?')">Delete</button>
                  </form>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      ) : (
        <p>No service tokens for this project.</p>
      )}
    </Layout>
  );
};

const NewTokenPage: FC<{
  project: Project;
  environments: Environment[];
  flash?: { type: string; message: string };
}> = (props) => {
  return (
    <Layout title="New Service Token" flash={props.flash} projectId={props.project.id} projectName={props.project.name}>
      <h1>New Service Token for {props.project.name}</h1>

      <form method="post" action={`/admin/projects/${props.project.id}/service-tokens`}>
        <fieldset>
          <div class="form-group">
            <label for="friendly_name">Friendly Name *</label>
            <input type="text" name="friendly_name" id="friendly_name" placeholder="Token name" required />
          </div>
          <div class="form-group">
            <label for="environment_id">Environment *</label>
            <select name="environment_id" id="environment_id">
              {props.environments.map((e) => (
                <option value={String(e.id)}>{e.name}</option>
              ))}
            </select>
          </div>
          <div class="form-group">
            <label for="rights">Rights *</label>
            <select name="rights" id="rights" multiple>
              <option value="read" selected>Read</option>
              <option value="write">Write</option>
              <option value="admin">Admin</option>
            </select>
          </div>
          <div class="form-actions">
            <button type="submit" class="btn btn-primary">Create</button>
            <a href={`/admin/projects/${props.project.id}/service-tokens`} class="btn">Cancel</a>
          </div>
        </fieldset>
      </form>
    </Layout>
  );
};

// --- Routes ---

// GET /projects/:pid/service-tokens
app.get("/projects/:pid/service-tokens", requireOwnerOrAdmin("pid"), (c) => {
  const projectId = Number(c.req.param("pid"));
  const db = getDb();

  const project = db
    .query<Project, [number]>("SELECT * FROM projects WHERE id = ?")
    .get(projectId);
  if (!project) {
    return c.redirect(flashRedirect("/admin/projects", "error", "Project not found"));
  }

  const tokens = db
    .query<ServiceToken & { environment_name: string }, [number]>(
      `SELECT st.*, e.name as environment_name
       FROM service_tokens st
       JOIN environments e ON e.id = st.environment_id
       WHERE st.project_id = ?
       ORDER BY st.id DESC`
    )
    .all(projectId);

  const flash = flashFromQuery(c);
  const newPublicToken = c.req.query("new_token");

  return c.html(
    <TokenListPage
      project={project}
      tokens={tokens}
      newPublicToken={newPublicToken}
      flash={flash}
    />
  );
});

// GET /projects/:pid/service-tokens/new
app.get("/projects/:pid/service-tokens/new", requireOwnerOrAdmin("pid"), (c) => {
  const projectId = Number(c.req.param("pid"));
  const db = getDb();

  const project = db
    .query<Project, [number]>("SELECT * FROM projects WHERE id = ?")
    .get(projectId);
  if (!project) {
    return c.redirect(flashRedirect("/admin/projects", "error", "Project not found"));
  }

  if (isProjectSealed(projectId)) {
    return c.redirect(flashRedirect(`/admin/projects/${projectId}`, "error", "Unseal the project first"));
  }

  const environments = db.query<Environment, []>("SELECT * FROM environments").all();

  return c.html(
    <NewTokenPage project={project} environments={environments} />
  );
});

// POST /projects/:pid/service-tokens — create token
app.post("/projects/:pid/service-tokens", requireOwnerOrAdmin("pid"), async (c) => {
  const projectId = Number(c.req.param("pid"));
  const db = getDb();

  const project = db
    .query<Project, [number]>("SELECT * FROM projects WHERE id = ?")
    .get(projectId);
  if (!project) {
    return c.redirect(flashRedirect("/admin/projects", "error", "Project not found"));
  }

  const masterKey = getMasterKey(projectId);
  if (!masterKey) {
    return c.redirect(flashRedirect(`/admin/projects/${projectId}`, "error", "Unseal the project first"));
  }

  const body = await c.req.parseBody();
  const friendlyName = String(body["friendly_name"] ?? "").trim();
  const envId = Number(body["environment_id"]);

  // Rights can come as single string or array
  let rightsRaw = body["rights"];
  let rights: Right[];
  if (Array.isArray(rightsRaw)) {
    rights = rightsRaw.map((r) => String(r) as Right);
  } else if (rightsRaw) {
    rights = [String(rightsRaw) as Right];
  } else {
    rights = ["read"];
  }

  if (!friendlyName || isNaN(envId)) {
    return c.redirect(flashRedirect(`/admin/projects/${projectId}/service-tokens/new`, "error", "Name and environment are required"));
  }

  const { record: _record, generatedToken } = createServiceToken(projectId, envId, friendlyName, rights);
  const publicToken = encodePublicToken(masterKey, generatedToken);

  return c.redirect(
    `/admin/projects/${projectId}/service-tokens?new_token=${encodeURIComponent(publicToken)}&flash_type=success&flash_msg=${encodeURIComponent("Service token created successfully")}`
  );
});

// POST /projects/:pid/service-tokens/:tid/destroy — revoke
app.post("/projects/:pid/service-tokens/:tid/destroy", requireOwnerOrAdmin("pid"), (c) => {
  const projectId = Number(c.req.param("pid"));
  const tokenId = Number(c.req.param("tid"));
  const db = getDb();

  db.prepare<void, [number]>("DELETE FROM service_tokens WHERE id = ?").run(tokenId);

  return c.redirect(flashRedirect(`/admin/projects/${projectId}/service-tokens`, "success", "Service token deleted"));
});

export default app;
