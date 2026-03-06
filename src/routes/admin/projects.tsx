import { Hono } from "hono";
import type { FC } from "hono/jsx";
import type { SQLQueryBindings } from "bun:sqlite";
import { getDb, type Project, type Environment, type Secret, type SecretValueHistory, type ServiceToken } from "../../db.js";
import { generateKeyB64, encrypt, decrypt } from "../../lib/encryption.js";
import {
  setMasterKey,
  getMasterKey,
  isProjectSealed,
  deleteMasterKey,
  prepareMasterKey,
  validateMasterKey,
} from "../../lib/master-keys.js";
import { Layout } from "../../views/layout.js";
import { requireAuth, type AuthUser } from "../../middleware/session.js";
import { requireOwnerOrAdmin, getProjectFilter } from "../../middleware/ownership.js";

const app = new Hono();

app.use("*", requireAuth);

// --- Helper: parse flash from query string ---
function flashFromQuery(c: { req: { query: (k: string) => string | undefined } }): { type: string; message: string } | undefined {
  const msg = c.req.query("flash_msg");
  const typ = c.req.query("flash_type") ?? "success";
  if (msg) return { type: typ, message: decodeURIComponent(msg) };
  return undefined;
}

function flashRedirect(path: string, type: string, message: string): string {
  return `${path}?flash_type=${type}&flash_msg=${encodeURIComponent(message)}`;
}

// ===== Views =====

const ProjectListPage: FC<{
  projects: (Project & { sealed: boolean })[];
  flash?: { type: string; message: string };
  newMasterKey?: string;
  newProjectName?: string;
}> = (props) => {
  return (
    <Layout title="Projects" flash={props.flash}>
      <h1>Projects ({props.projects.length})</h1>

      {props.newMasterKey && (
        <div class="warning">
          <p>
            <strong>New master key generated for project {props.newProjectName}.</strong><br />
            Back it up and keep it secret. Alternatively you can use your own master key/passphrase.
          </p>
          <div class="copyable">
            <input id="master_key_input" type="password" value={props.newMasterKey} readonly />
            <button type="button" class="btn btn-sm" onclick="copyToClipboard('master_key_input')">Copy</button>
          </div>
        </div>
      )}

      <div class="controls">
        <a class="btn" href="/admin/projects/new">+ New Project</a>
      </div>

      <table>
        <thead>
          <tr>
            <th>#</th>
            <th>Name</th>
            <th>Status</th>
            <th>Actions</th>
          </tr>
        </thead>
        <tbody>
          {props.projects.map((p) => (
            <tr>
              <td>{p.id}</td>
              <td>
                {p.parent_id ? <span>&nbsp;&nbsp;&nbsp;&nbsp;</span> : null}
                {p.name}
              </td>
              <td>{p.sealed ? "sealed" : <strong>[unsealed]</strong>}</td>
              <td>
                <div class="inline-actions">
                  <a class="btn btn-sm" href={`/admin/projects/${p.id}`}>View</a>
                  <form method="post" action={`/admin/projects/${p.id}/destroy`} style="display:inline">
                    <button type="submit" class="btn btn-sm btn-danger" onclick="return confirm('Are you sure?')">Delete</button>
                  </form>
                </div>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </Layout>
  );
};

const NewProjectPage: FC<{
  projects: Project[];
  flash?: { type: string; message: string };
}> = (props) => {
  return (
    <Layout title="New Project" flash={props.flash}>
      <h1>New Project</h1>
      <form method="post" action="/admin/projects">
        <fieldset>
          <div class="form-group">
            <label for="name">Name *</label>
            <input type="text" name="name" id="name" maxlength={50} placeholder="Project name" required />
          </div>
          <div class="form-group">
            <label for="description">Description</label>
            <textarea name="description" id="description" rows={3} placeholder="Description"></textarea>
          </div>
          <div class="form-group">
            <label for="parent_id">Parent Project</label>
            <select name="parent_id" id="parent_id">
              <option value="">-- None (root project) --</option>
              {props.projects.map((p) => (
                <option value={String(p.id)}>{p.name}</option>
              ))}
            </select>
          </div>
          <div class="form-actions">
            <button type="submit" class="btn btn-primary">Create</button>
            <a href="/admin/projects" class="btn">Cancel</a>
          </div>
        </fieldset>
      </form>
    </Layout>
  );
};

const ProjectDetailPage: FC<{
  project: Project;
  environments: (Environment & { secretCount: number })[];
  sealed: boolean;
  flash?: { type: string; message: string };
}> = (props) => {
  return (
    <Layout title={props.project.name} flash={props.flash} projectId={props.project.id} projectName={props.project.name}>
      <h1>{props.project.name} Project</h1>

      {props.sealed && (
        <div>
          <p>Project master key is not currently set. Fill it below to keep it stored temporarily in memory.</p>
          <form method="post" action={`/admin/projects/${props.project.id}/unseal`}>
            <fieldset>
              <div class="form-group">
                <label for="master_key">Project master key/passphrase *</label>
                <input type="password" name="master_key" id="master_key" placeholder="Master key" />
              </div>
              <div class="form-actions">
                <button type="submit" class="btn btn-primary">Store (unseal)</button>
              </div>
            </fieldset>
          </form>
        </div>
      )}

      <hr />
      <div class="controls">
        <a class="btn" href={`/admin/projects/${props.project.id}/rotate`}>Rotate Master Key</a>
        <a class="btn" href={`/admin/projects/${props.project.id}/service-tokens`}>Service Tokens</a>
      </div>
      <hr />

      <h3>Environments</h3>
      <div class="env-grid">
        {props.environments.map((env) => (
          <div class="env-card">
            <h3>{env.name}</h3>
            <a href={`/admin/projects/${props.project.id}/environments/${env.id}/secrets`}>
              Secrets ({env.secretCount})
            </a>
          </div>
        ))}
      </div>
    </Layout>
  );
};

const RotatePage: FC<{
  project: Project;
  currentMasterKey: string;
  newMasterKey: string;
  flash?: { type: string; message: string };
}> = (props) => {
  return (
    <Layout title="Rotate Master Key" flash={props.flash} projectId={props.project.id} projectName={props.project.name}>
      <h1>Rotate Master Key for project {props.project.name}</h1>

      <div class="warning">
        <strong>Warning!</strong> This will re-encrypt all secrets with the new master key.<br />
        Service tokens will be invalidated and need to be re-created.
      </div>

      <form method="post" action={`/admin/projects/${props.project.id}/rotate`}>
        <fieldset>
          <div class="form-group">
            <label for="current_master_key">Current Master Key *</label>
            <input type="password" name="current_master_key" id="current_master_key" value={props.currentMasterKey} />
          </div>
          <div class="form-group">
            <label for="new_master_key">New Master Key *</label>
            <input type="password" name="new_master_key" id="new_master_key" value={props.newMasterKey} />
            <button type="button" class="btn btn-sm" onclick="copyToClipboard('new_master_key')">Copy</button>
          </div>
          <div class="form-actions">
            <button type="submit" class="btn btn-primary">Rotate</button>
            <a href={`/admin/projects/${props.project.id}`} class="btn">Cancel</a>
          </div>
        </fieldset>
      </form>
    </Layout>
  );
};

const RotatePostPage: FC<{
  project: Project;
  serviceTokens: (ServiceToken & { environment_name?: string })[];
}> = (props) => {
  return (
    <Layout title="Rotation Complete" projectId={props.project.id} projectName={props.project.name}
            flash={{ type: "success", message: "Master key rotated successfully. All secrets re-encrypted." }}>
      <h1>Rotation Complete for {props.project.name}</h1>

      {props.serviceTokens.length > 0 ? (
        <div>
          <div class="warning">
            <strong>These tokens encode the old master key. They must be regenerated.</strong>
          </div>
          <table>
            <thead>
              <tr>
                <th>#</th>
                <th>Name</th>
                <th>Environment</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {props.serviceTokens.map((t) => (
                <tr>
                  <td>{t.id}</td>
                  <td>{t.friendly_name}</td>
                  <td>{t.environment_name ?? String(t.environment_id)}</td>
                  <td>
                    <form method="post" action={`/admin/projects/${props.project.id}/service-tokens/${t.id}/destroy`} style="display:inline">
                      <button type="submit" class="btn btn-sm btn-danger" onclick="return confirm('Delete this token?')">Delete</button>
                    </form>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : (
        <p>No service tokens were affected.</p>
      )}

      <div style="margin-top: 16px;">
        <a class="btn" href={`/admin/projects/${props.project.id}`}>Back to project</a>
      </div>
    </Layout>
  );
};

// ===== Routes =====

// GET /projects — list projects (filtered by ownership)
app.get("/", (c) => {
  const db = getDb();
  const user = c.get("user") as AuthUser;
  const { clause, params } = getProjectFilter(user);
  const projects = db
    .query<Project, string[]>(
      `SELECT * FROM projects WHERE 1=1 ${clause} ORDER BY CASE WHEN parent_id IS NULL THEN id ELSE parent_id END, id`
    )
    .all(...params);

  const enriched = projects.map((p) => ({
    ...p,
    sealed: isProjectSealed(p.id),
  }));

  const flash = flashFromQuery(c);
  const newMasterKey = c.req.query("new_master_key");
  const newProjectName = c.req.query("new_project_name");

  return c.html(
    <ProjectListPage
      projects={enriched}
      flash={flash}
      newMasterKey={newMasterKey}
      newProjectName={newProjectName}
    />
  );
});

// GET /projects/new — new project form
app.get("/new", (c) => {
  const db = getDb();
  const user = c.get("user") as AuthUser;
  const { clause, params } = getProjectFilter(user);
  const rootProjects = db
    .query<Project, string[]>(`SELECT * FROM projects WHERE parent_id IS NULL ${clause}`)
    .all(...params);
  return c.html(<NewProjectPage projects={rootProjects} />);
});

// POST /projects — create project
app.post("/", async (c) => {
  const user = c.get("user") as AuthUser;

  if (!user.emailVerified && user.role !== "admin") {
    return c.redirect(flashRedirect("/admin/projects/new", "error", "Please verify your email before creating projects"));
  }

  const body = await c.req.parseBody();
  const name = String(body["name"] ?? "").trim();
  const description = String(body["description"] ?? "").trim();
  const parentIdRaw = body["parent_id"];
  const parentId = parentIdRaw ? Number(parentIdRaw) : null;

  if (!name) {
    return c.redirect("/admin/projects/new");
  }

  const db = getDb();

  db.prepare<void, [string, string, number | null, string]>(
    "INSERT INTO projects (name, description, parent_id, owner_id) VALUES (?, ?, ?, ?)"
  ).run(name, description, parentId, user.id);

  const project = db
    .query<Project, [string]>("SELECT * FROM projects WHERE name = ?")
    .get(name);

  if (!project) {
    return c.redirect(flashRedirect("/admin/projects", "error", "Failed to create project"));
  }

  // Generate master key only for root projects
  if (!parentId) {
    const masterKey = generateKeyB64();
    setMasterKey(project.id, masterKey);
    return c.redirect(
      `/admin/projects?new_master_key=${encodeURIComponent(masterKey)}&new_project_name=${encodeURIComponent(name)}&flash_type=success&flash_msg=${encodeURIComponent("Project created. New master key generated.")}`
    );
  }

  return c.redirect(flashRedirect("/admin/projects", "success", `Project "${name}" created.`));
});

// GET /projects/:id — project detail
app.get("/:id", requireOwnerOrAdmin("id"), (c) => {
  const projectId = Number(c.req.param("id"));
  const db = getDb();

  const project = db
    .query<Project, [number]>("SELECT * FROM projects WHERE id = ?")
    .get(projectId);

  if (!project) {
    return c.redirect(flashRedirect("/admin/projects", "error", "Project not found"));
  }

  const environments = db.query<Environment, []>("SELECT * FROM environments").all();

  const projectIds = [project.id];
  if (project.parent_id) projectIds.push(project.parent_id);

  const placeholders = projectIds.map(() => "?").join(",");
  const params: SQLQueryBindings[] = [...projectIds];

  const counts = db
    .query<{ environment_id: number; cnt: number }, SQLQueryBindings[]>(
      `SELECT environment_id, COUNT(*) as cnt FROM secrets WHERE project_id IN (${placeholders}) GROUP BY environment_id`
    )
    .all(...params);

  const countMap = new Map(counts.map((r) => [r.environment_id, r.cnt]));

  const enrichedEnvs = environments.map((e) => ({
    ...e,
    secretCount: countMap.get(e.id) ?? 0,
  }));

  const sealed = isProjectSealed(project.id);
  const flash = flashFromQuery(c);

  return c.html(
    <ProjectDetailPage
      project={project}
      environments={enrichedEnvs}
      sealed={sealed}
      flash={flash}
    />
  );
});

// POST /projects/:id/unseal — store master key
app.post("/:id/unseal", requireOwnerOrAdmin("id"), async (c) => {
  const projectId = Number(c.req.param("id"));
  const body = await c.req.parseBody();
  const masterKey = String(body["master_key"] ?? "").trim();

  if (!masterKey) {
    return c.redirect(flashRedirect(`/admin/projects/${projectId}`, "error", "Master key is required"));
  }

  const preparedKey = prepareMasterKey(masterKey);
  const valid = validateMasterKey(projectId, preparedKey);

  if (!valid) {
    return c.redirect(flashRedirect(`/admin/projects/${projectId}`, "error", "Invalid master key"));
  }

  setMasterKey(projectId, preparedKey);
  return c.redirect(flashRedirect(`/admin/projects/${projectId}`, "success", "Master key has been set successfully"));
});

// POST /projects/:id/destroy — delete project + cascaded data
app.post("/:id/destroy", requireOwnerOrAdmin("id"), (c) => {
  const projectId = Number(c.req.param("id"));
  const db = getDb();

  const project = db
    .query<Project, [number]>("SELECT * FROM projects WHERE id = ?")
    .get(projectId);

  if (!project) {
    return c.redirect(flashRedirect("/admin/projects", "error", "Project not found"));
  }

  // Collect IDs: this project + sub-projects
  const subProjects = db
    .query<Project, [number]>("SELECT * FROM projects WHERE parent_id = ?")
    .all(projectId);

  const allProjectIds = [projectId, ...subProjects.map((p) => p.id)];

  for (const pid of allProjectIds) {
    // Delete secret histories via cascade (secrets have ON DELETE CASCADE for histories)
    db.prepare<void, [number]>("DELETE FROM secrets WHERE project_id = ?").run(pid);
    db.prepare<void, [number]>("DELETE FROM service_tokens WHERE project_id = ?").run(pid);
    db.prepare<void, [number]>("DELETE FROM projects WHERE id = ?").run(pid);
    deleteMasterKey(pid);
  }

  return c.redirect(flashRedirect("/admin/projects", "success", "Project deleted successfully"));
});

// GET /projects/:id/rotate — rotation form
app.get("/:id/rotate", requireOwnerOrAdmin("id"), (c) => {
  const projectId = Number(c.req.param("id"));
  const db = getDb();

  const project = db
    .query<Project, [number]>("SELECT * FROM projects WHERE id = ?")
    .get(projectId);

  if (!project) {
    return c.redirect(flashRedirect("/admin/projects", "error", "Project not found"));
  }

  const currentMasterKey = getMasterKey(projectId);
  if (!currentMasterKey) {
    return c.redirect(flashRedirect(`/admin/projects/${projectId}`, "error", "Unseal the project first"));
  }

  const newMasterKey = generateKeyB64();
  const flash = flashFromQuery(c);

  return c.html(
    <RotatePage
      project={project}
      currentMasterKey={currentMasterKey}
      newMasterKey={newMasterKey}
      flash={flash}
    />
  );
});

// POST /projects/:id/rotate — perform rotation
app.post("/:id/rotate", requireOwnerOrAdmin("id"), async (c) => {
  const projectId = Number(c.req.param("id"));
  const body = await c.req.parseBody();
  const currentMasterKeyRaw = String(body["current_master_key"] ?? "");
  const newMasterKeyRaw = String(body["new_master_key"] ?? "");

  if (!currentMasterKeyRaw || !newMasterKeyRaw) {
    return c.redirect(flashRedirect(`/admin/projects/${projectId}/rotate`, "error", "Both keys are required"));
  }

  const newMasterKey = prepareMasterKey(newMasterKeyRaw);

  const db = getDb();
  const project = db
    .query<Project, [number]>("SELECT * FROM projects WHERE id = ?")
    .get(projectId);

  if (!project) {
    return c.redirect(flashRedirect("/admin/projects", "error", "Project not found"));
  }

  // Get all secrets for project (+ parent)
  const projectIds = [projectId];
  if (project.parent_id) projectIds.push(project.parent_id);

  const placeholders = projectIds.map(() => "?").join(",");
  const params: SQLQueryBindings[] = [...projectIds];

  const secrets = db
    .query<Secret, SQLQueryBindings[]>(
      `SELECT * FROM secrets WHERE project_id IN (${placeholders})`
    )
    .all(...params);

  // Re-encrypt each secret's latest value
  for (const secret of secrets) {
    const latestHistory = db
      .query<SecretValueHistory, [number]>(
        "SELECT * FROM secret_value_histories WHERE secret_id = ? ORDER BY id DESC LIMIT 1"
      )
      .get(secret.id);

    if (!latestHistory) continue;

    let plaintext: string;
    try {
      plaintext = decrypt(currentMasterKeyRaw, latestHistory.encrypted_value, latestHistory.iv_value);
    } catch {
      continue;
    }

    // Delete old history entries
    db.prepare<void, [number]>("DELETE FROM secret_value_histories WHERE secret_id = ?").run(secret.id);

    // Re-encrypt with new key
    const { cipheredData, iv } = encrypt(newMasterKey, plaintext);
    db.prepare<void, [number, string, string]>(
      "INSERT INTO secret_value_histories (secret_id, encrypted_value, iv_value, comment) VALUES (?, ?, ?, '')"
    ).run(secret.id, cipheredData, iv);
  }

  deleteMasterKey(projectId);
  setMasterKey(projectId, newMasterKey);

  return c.redirect(`/admin/projects/${projectId}/rotate-post`);
});

// GET /projects/:id/rotate-post — post-rotation page (G-04)
app.get("/:id/rotate-post", requireOwnerOrAdmin("id"), (c) => {
  const projectId = Number(c.req.param("id"));
  const db = getDb();

  const project = db
    .query<Project, [number]>("SELECT * FROM projects WHERE id = ?")
    .get(projectId);

  if (!project) {
    return c.redirect(flashRedirect("/admin/projects", "error", "Project not found"));
  }

  const projectIds = [projectId];
  if (project.parent_id) projectIds.push(project.parent_id);

  const placeholders = projectIds.map(() => "?").join(",");
  const params: SQLQueryBindings[] = [...projectIds];

  const tokens = db
    .query<ServiceToken & { environment_name: string }, SQLQueryBindings[]>(
      `SELECT st.*, e.name as environment_name
       FROM service_tokens st
       JOIN environments e ON e.id = st.environment_id
       WHERE st.project_id IN (${placeholders})`
    )
    .all(...params);

  return c.html(
    <RotatePostPage project={project} serviceTokens={tokens} />
  );
});

export default app;
