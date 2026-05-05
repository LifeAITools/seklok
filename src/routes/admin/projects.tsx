import { Hono } from "hono";
import type { FC } from "hono/jsx";
import type { SQLQueryBindings } from "bun:sqlite";
import { getDb, type Project, type Environment, type Secret, type SecretValueHistory, type ServiceToken } from "../../db.js";
import { generateKeyB64, encrypt, decrypt } from "../../lib/encryption.js";
import {
  setMasterKey,
  isProjectSealed,
  deleteMasterKey,
  prepareMasterKey,
  validateMasterKey,
} from "../../lib/master-keys.js";
import { Layout } from "../../views/layout.js";
import { SecretRevealPage } from "../../views/secret-reveal.js";
import { t, type Locale, detectLocale } from "../../lib/i18n.js";
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
  locale: Locale;
  projects: (Project & { sealed: boolean })[];
  flash?: { type: string; message: string };
}> = (props) => {
  const { locale } = props;
  return (
    <Layout title={t(locale, "projects.title", { count: props.projects.length })} locale={locale} flash={props.flash}>
      <h1>{t(locale, "projects.title", { count: props.projects.length })}</h1>

      <div class="controls">
        <a class="btn" href="/admin/projects/new">{t(locale, "projects.new_project")}</a>
      </div>

      <table>
        <thead>
          <tr>
            <th>{t(locale, "projects.col_id")}</th>
            <th>{t(locale, "projects.col_name")}</th>
            <th>{t(locale, "projects.col_status")}</th>
            <th>{t(locale, "projects.col_actions")}</th>
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
              <td>{p.sealed ? t(locale, "projects.status_sealed") : <strong>{t(locale, "projects.status_unsealed")}</strong>}</td>
              <td>
                <div class="inline-actions">
                  <a class="btn btn-sm" href={`/admin/projects/${p.id}`}>{t(locale, "projects.btn_view")}</a>
                  <form method="post" action={`/admin/projects/${p.id}/destroy`} style="display:inline">
                    <button type="submit" class="btn btn-sm btn-danger" onclick={`return confirm('${t(locale, "projects.confirm_delete")}')`}>{t(locale, "projects.btn_delete")}</button>
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
  locale: Locale;
  projects: Project[];
  flash?: { type: string; message: string };
}> = (props) => {
  const { locale } = props;
  return (
    <Layout title={t(locale, "projects.new.title")} locale={locale} flash={props.flash}>
      <h1>{t(locale, "projects.new.title")}</h1>
      <form method="post" action="/admin/projects">
        <fieldset>
          <div class="form-group">
            <label for="name">{t(locale, "projects.new.name_label")}</label>
            <input type="text" name="name" id="name" maxlength={50} placeholder={t(locale, "projects.new.name_placeholder")} required />
          </div>
          <div class="form-group">
            <label for="description">{t(locale, "projects.new.desc_label")}</label>
            <textarea name="description" id="description" rows={3} placeholder={t(locale, "projects.new.desc_label")}></textarea>
          </div>
          <div class="form-group">
            <label for="parent_id">{t(locale, "projects.new.parent_label")}</label>
            <select name="parent_id" id="parent_id">
              <option value="">{t(locale, "projects.new.parent_none")}</option>
              {props.projects.map((p) => (
                <option value={String(p.id)}>{p.name}</option>
              ))}
            </select>
          </div>
          <div class="form-actions">
            <button type="submit" class="btn btn-primary">{t(locale, "projects.new.submit")}</button>
            <a href="/admin/projects" class="btn">{t(locale, "projects.new.cancel")}</a>
          </div>
        </fieldset>
      </form>
    </Layout>
  );
};

const ProjectDetailPage: FC<{
  locale: Locale;
  project: Project;
  environments: (Environment & { secretCount: number })[];
  sealed: boolean;
  flash?: { type: string; message: string };
}> = (props) => {
  const { locale } = props;
  return (
    <Layout title={props.project.name} locale={locale} flash={props.flash} projectId={props.project.id} projectName={props.project.name}>
      <h1>{t(locale, "projects.detail.title", { name: props.project.name })}</h1>

      {props.sealed && (
        <div>
          <p>{t(locale, "projects.detail.sealed_msg")}</p>
          <form method="post" action={`/admin/projects/${props.project.id}/unseal`}>
            <fieldset>
              <div class="form-group">
                <label for="master_key">{t(locale, "projects.detail.key_label")}</label>
                <input type="password" name="master_key" id="master_key" placeholder={t(locale, "projects.detail.key_placeholder")} />
              </div>
              <div class="form-actions">
                <button type="submit" class="btn btn-primary">{t(locale, "projects.detail.unseal")}</button>
              </div>
            </fieldset>
          </form>
        </div>
      )}

      <hr />
      <div class="controls">
        <a class="btn" href={`/admin/projects/${props.project.id}/rotate`}>{t(locale, "projects.detail.rotate_key")}</a>
        <a class="btn" href={`/admin/projects/${props.project.id}/service-tokens`}>{t(locale, "projects.detail.service_tokens")}</a>
      </div>
      <hr />

      <h3>{t(locale, "projects.detail.environments")}</h3>
      <div class="env-grid">
        {props.environments.map((env) => (
          <div class="env-card">
            <h3>{env.name}</h3>
            <a href={`/admin/projects/${props.project.id}/environments/${env.id}/secrets`}>
              {t(props.locale, "secrets.count_link", { count: env.secretCount })}
            </a>
          </div>
        ))}
      </div>
    </Layout>
  );
};

const RotatePage: FC<{
  locale: Locale;
  project: Project;
  flash?: { type: string; message: string };
}> = (props) => {
  const { locale } = props;
  return (
    <Layout title={t(locale, "projects.rotate.title", { name: props.project.name })} locale={locale} flash={props.flash} projectId={props.project.id} projectName={props.project.name}>
      <h1>{t(locale, "projects.rotate.title", { name: props.project.name })}</h1>

      <div class="warning">
        <strong>{t(locale, "projects.rotate.warning_title")}</strong> {t(locale, "projects.rotate.warning_text")}<br />
        {t(locale, "projects.rotate.warning_tokens")}
      </div>

      <form method="post" action={`/admin/projects/${props.project.id}/rotate`}>
        <fieldset>
          <div class="form-group">
            <label for="current_master_key">{t(locale, "projects.rotate.current_key")}</label>
            <input type="password" name="current_master_key" id="current_master_key" placeholder={t(locale, "projects.detail.key_placeholder")} required />
            <p style="font-size: 12px; color: #666; margin-top: 4px;">{t(locale, "projects.rotate.current_key_hint")}</p>
          </div>
          <div class="form-group">
            <label for="new_master_key">{t(locale, "projects.rotate.new_key")}</label>
            <input type="password" name="new_master_key" id="new_master_key" placeholder={t(locale, "projects.rotate.new_key_placeholder")} />
            <p style="font-size: 12px; color: #666; margin-top: 4px;">{t(locale, "projects.rotate.new_key_hint")}</p>
          </div>
          <div class="form-actions">
            <button type="submit" class="btn btn-primary">{t(locale, "projects.rotate.submit")}</button>
            <a href={`/admin/projects/${props.project.id}`} class="btn">{t(locale, "projects.rotate.cancel")}</a>
          </div>
        </fieldset>
      </form>
    </Layout>
  );
};

const RotatePostPage: FC<{
  locale: Locale;
  project: Project;
  serviceTokens: (ServiceToken & { environment_name?: string })[];
}> = (props) => {
  const { locale } = props;
  return (
    <Layout title={t(locale, "projects.rotate_post.title", { name: props.project.name })} locale={locale} projectId={props.project.id} projectName={props.project.name}
            flash={{ type: "success", message: t(locale, "projects.rotate_post.flash") }}>
      <h1>{t(locale, "projects.rotate_post.title", { name: props.project.name })}</h1>

      {props.serviceTokens.length > 0 ? (
        <div>
          <div class="warning">
            <strong>{t(locale, "projects.rotate_post.warning")}</strong>
          </div>
          <table>
            <thead>
              <tr>
                <th>{t(locale, "projects.col_id")}</th>
                <th>{t(locale, "projects.col_name")}</th>
                <th>{t(locale, "projects.rotate_post.col_environment")}</th>
                <th>{t(locale, "projects.col_actions")}</th>
              </tr>
            </thead>
            <tbody>
              {props.serviceTokens.map((tk) => (
                <tr>
                  <td>{tk.id}</td>
                  <td>{tk.friendly_name}</td>
                  <td>{tk.environment_name ?? String(tk.environment_id)}</td>
                  <td>
                    <form method="post" action={`/admin/projects/${props.project.id}/service-tokens/${tk.id}/destroy`} style="display:inline">
                      <button type="submit" class="btn btn-sm btn-danger" onclick={`return confirm('${t(locale, "projects.rotate_post.confirm_delete")}')`}>{t(locale, "projects.btn_delete")}</button>
                    </form>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : (
        <p>{t(locale, "projects.rotate_post.no_tokens")}</p>
      )}

      <div style="margin-top: 16px;">
        <a class="btn" href={`/admin/projects/${props.project.id}`}>{t(locale, "projects.rotate_post.back")}</a>
      </div>
    </Layout>
  );
};

// ===== Routes =====

// GET /projects — list projects (filtered by ownership)
app.get("/", (c) => {
  const locale = detectLocale(c);
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

  return c.html(
    <ProjectListPage
      locale={locale}
      projects={enriched}
      flash={flash}
    />
  );
});

// GET /projects/new — new project form
app.get("/new", (c) => {
  const locale = detectLocale(c);
  const db = getDb();
  const user = c.get("user") as AuthUser;
  const { clause, params } = getProjectFilter(user);
  const rootProjects = db
    .query<Project, string[]>(`SELECT * FROM projects WHERE parent_id IS NULL ${clause}`)
    .all(...params);
  const flash = flashFromQuery(c);
  return c.html(<NewProjectPage locale={locale} projects={rootProjects} flash={flash} />);
});

// POST /projects — create project
app.post("/", async (c) => {
  const locale = detectLocale(c);
  const user = c.get("user") as AuthUser;

  if (!user.emailVerified && user.role !== "admin") {
    return c.redirect(flashRedirect("/admin/projects/new", "error", t(locale, "flash.verify_email")));
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
    return c.redirect(flashRedirect("/admin/projects", "error", t(locale, "flash.project_create_failed")));
  }

  // Generate master key only for root projects.
  // CRITICAL: master key is rendered directly in this POST response — NEVER placed in a redirect URL.
  // Putting secrets in Location/query strings leaks them into reverse-proxy logs, browser history,
  // and Referer headers. See bug 9c497016 / d664fbf2.
  if (!parentId) {
    const masterKey = generateKeyB64();
    setMasterKey(project.id, masterKey);
    const hasher = new Bun.CryptoHasher("sha256");
    hasher.update(masterKey);
    db.prepare("UPDATE projects SET master_key_hash = ? WHERE id = ?").run(hasher.digest("hex"), project.id);
    return c.html(
      <SecretRevealPage
        locale={locale}
        title={t(locale, "secret_reveal.master_key_title", { name })}
        description={t(locale, "secret_reveal.master_key_description")}
        warning={t(locale, "secret_reveal.master_key_warning")}
        secret={masterKey}
        downloadFilename={`seklok-master-key-${name.replace(/[^a-zA-Z0-9-_]/g, "_")}`}
        continueUrl={`/admin/projects/${project.id}`}
      />
    );
  }

  return c.redirect(flashRedirect("/admin/projects", "success", t(locale, "flash.project_created", { name })));
});

// GET /projects/:id — project detail
app.get("/:id", requireOwnerOrAdmin("id"), (c) => {
  const locale = detectLocale(c);
  const projectId = Number(c.req.param("id"));
  const db = getDb();

  const project = db
    .query<Project, [number]>("SELECT * FROM projects WHERE id = ?")
    .get(projectId);

  if (!project) {
    return c.redirect(flashRedirect("/admin/projects", "error", t(locale, "flash.project_not_found")));
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
      locale={locale}
      project={project}
      environments={enrichedEnvs}
      sealed={sealed}
      flash={flash}
    />
  );
});

// POST /projects/:id/unseal — store master key
app.post("/:id/unseal", requireOwnerOrAdmin("id"), async (c) => {
  const locale = detectLocale(c);
  const projectId = Number(c.req.param("id"));
  const body = await c.req.parseBody();
  const masterKey = String(body["master_key"] ?? "").trim();

  if (!masterKey) {
    return c.redirect(flashRedirect(`/admin/projects/${projectId}`, "error", t(locale, "flash.key_required")));
  }

  const preparedKey = prepareMasterKey(masterKey);
  const valid = validateMasterKey(projectId, preparedKey);

  if (!valid) {
    return c.redirect(flashRedirect(`/admin/projects/${projectId}`, "error", t(locale, "flash.invalid_key")));
  }

  setMasterKey(projectId, preparedKey);
  return c.redirect(flashRedirect(`/admin/projects/${projectId}`, "success", t(locale, "flash.key_set")));
});

// POST /projects/:id/destroy — delete project + cascaded data
app.post("/:id/destroy", requireOwnerOrAdmin("id"), (c) => {
  const locale = detectLocale(c);
  const projectId = Number(c.req.param("id"));
  const db = getDb();

  const project = db
    .query<Project, [number]>("SELECT * FROM projects WHERE id = ?")
    .get(projectId);

  if (!project) {
    return c.redirect(flashRedirect("/admin/projects", "error", t(locale, "flash.project_not_found")));
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

  return c.redirect(flashRedirect("/admin/projects", "success", t(locale, "flash.project_deleted")));
});

// GET /projects/:id/rotate — rotation form
app.get("/:id/rotate", requireOwnerOrAdmin("id"), (c) => {
  const locale = detectLocale(c);
  const projectId = Number(c.req.param("id"));
  const db = getDb();

  const project = db
    .query<Project, [number]>("SELECT * FROM projects WHERE id = ?")
    .get(projectId);

  if (!project) {
    return c.redirect(flashRedirect("/admin/projects", "error", t(locale, "flash.project_not_found")));
  }

  // Project must be unsealed to rotate (we need the current key in memory to re-encrypt)
  if (isProjectSealed(projectId)) {
    return c.redirect(flashRedirect(`/admin/projects/${projectId}`, "error", t(locale, "flash.unseal_first")));
  }

  const flash = flashFromQuery(c);

  return c.html(
    <RotatePage
      locale={locale}
      project={project}
      flash={flash}
    />
  );
});

// POST /projects/:id/rotate — perform rotation, then render new key via SecretRevealPage
app.post("/:id/rotate", requireOwnerOrAdmin("id"), async (c) => {
  const locale = detectLocale(c);
  const projectId = Number(c.req.param("id"));
  const body = await c.req.parseBody();
  const currentMasterKeyRaw = String(body["current_master_key"] ?? "").trim();
  const newMasterKeyInput = String(body["new_master_key"] ?? "").trim();

  if (!currentMasterKeyRaw) {
    return c.redirect(flashRedirect(`/admin/projects/${projectId}/rotate`, "error", t(locale, "flash.keys_required")));
  }

  const db = getDb();
  const project = db
    .query<Project, [number]>("SELECT * FROM projects WHERE id = ?")
    .get(projectId);

  if (!project) {
    return c.redirect(flashRedirect("/admin/projects", "error", t(locale, "flash.project_not_found")));
  }

  // Validate the supplied current key against stored hash before doing anything destructive
  const preparedCurrent = prepareMasterKey(currentMasterKeyRaw);
  if (!validateMasterKey(projectId, preparedCurrent)) {
    return c.redirect(flashRedirect(`/admin/projects/${projectId}/rotate`, "error", t(locale, "flash.invalid_key")));
  }

  // New key: user-supplied (custom passphrase) OR server-generated
  const newMasterKey = newMasterKeyInput
    ? prepareMasterKey(newMasterKeyInput)
    : generateKeyB64();

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
      plaintext = decrypt(preparedCurrent, latestHistory.encrypted_value, latestHistory.iv_value);
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
  const rotateHasher = new Bun.CryptoHasher("sha256");
  rotateHasher.update(newMasterKey);
  db.prepare("UPDATE projects SET master_key_hash = ? WHERE id = ?").run(rotateHasher.digest("hex"), projectId);

  // Render new master key directly — never via redirect URL.
  return c.html(
    <SecretRevealPage
      locale={locale}
      title={t(locale, "secret_reveal.master_key_title", { name: project.name })}
      description={t(locale, "secret_reveal.rotated_description")}
      warning={t(locale, "secret_reveal.master_key_warning")}
      secret={newMasterKey}
      downloadFilename={`seklok-master-key-${project.name.replace(/[^a-zA-Z0-9-_]/g, "_")}-rotated`}
      continueUrl={`/admin/projects/${projectId}/rotate-post`}
      continueLabel={t(locale, "secret_reveal.continue_to_tokens")}
    />
  );
});

// GET /projects/:id/rotate-post — post-rotation page (G-04)
app.get("/:id/rotate-post", requireOwnerOrAdmin("id"), (c) => {
  const locale = detectLocale(c);
  const projectId = Number(c.req.param("id"));
  const db = getDb();

  const project = db
    .query<Project, [number]>("SELECT * FROM projects WHERE id = ?")
    .get(projectId);

  if (!project) {
    return c.redirect(flashRedirect("/admin/projects", "error", t(locale, "flash.project_not_found")));
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
    <RotatePostPage locale={locale} project={project} serviceTokens={tokens} />
  );
});

export default app;
