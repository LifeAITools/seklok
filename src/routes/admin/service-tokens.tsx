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
import { SecretRevealPage } from "../../views/secret-reveal.js";
import { t, type Locale, detectLocale } from "../../lib/i18n.js";
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
  locale: Locale;
  project: Project;
  tokens: (ServiceToken & { environment_name: string })[];
  flash?: { type: string; message: string };
}> = (props) => {
  const { locale } = props;
  return (
    <Layout title={t(locale, "tokens.title", { name: props.project.name })} locale={locale} flash={props.flash} projectId={props.project.id} projectName={props.project.name}>
      <h1>{t(locale, "tokens.title", { name: props.project.name })}</h1>

      <div class="controls">
        <a class="btn" href={`/admin/projects/${props.project.id}/service-tokens/new`}>{t(locale, "tokens.new_token")}</a>
        <a class="btn" href={`/admin/projects/${props.project.id}`}>{t(locale, "tokens.back")}</a>
      </div>

      {props.tokens.length > 0 ? (
        <table>
          <thead>
            <tr>
              <th>{t(locale, "tokens.col_id")}</th>
              <th>{t(locale, "tokens.col_name")}</th>
              <th>{t(locale, "tokens.col_environment")}</th>
              <th>{t(locale, "tokens.col_rights")}</th>
              <th>{t(locale, "tokens.col_actions")}</th>
            </tr>
          </thead>
          <tbody>
            {props.tokens.map((tk) => (
              <tr>
                <td>{tk.id}</td>
                <td>{tk.friendly_name}</td>
                <td>{tk.environment_name}</td>
                <td>{tk.rights}</td>
                <td>
                  <form method="post" action={`/admin/projects/${props.project.id}/service-tokens/${tk.id}/destroy`} style="display:inline">
                    <button type="submit" class="btn btn-sm btn-danger" onclick={`return confirm('${t(locale, "tokens.confirm_delete")}')`}>Delete</button>
                  </form>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      ) : (
        <p>{t(locale, "tokens.no_tokens")}</p>
      )}
    </Layout>
  );
};

const NewTokenPage: FC<{
  locale: Locale;
  project: Project;
  environments: Environment[];
  flash?: { type: string; message: string };
}> = (props) => {
  const { locale } = props;
  return (
    <Layout title={t(locale, "tokens.new.title", { name: props.project.name })} locale={locale} flash={props.flash} projectId={props.project.id} projectName={props.project.name}>
      <h1>{t(locale, "tokens.new.title", { name: props.project.name })}</h1>

      <form method="post" action={`/admin/projects/${props.project.id}/service-tokens`}>
        <fieldset>
          <div class="form-group">
            <label for="friendly_name">{t(locale, "tokens.new.name_label")}</label>
            <input type="text" name="friendly_name" id="friendly_name" placeholder={t(locale, "tokens.new.name_placeholder")} required />
          </div>
          <div class="form-group">
            <label for="environment_id">{t(locale, "tokens.new.env_label")}</label>
            <select name="environment_id" id="environment_id">
              {props.environments.map((e) => (
                <option value={String(e.id)}>{e.name}</option>
              ))}
            </select>
          </div>
          <div class="form-group">
            <label for="rights">{t(locale, "tokens.new.rights_label")}</label>
            <select name="rights" id="rights" multiple>
              <option value="read" selected>{t(locale, "tokens.new.right_read")}</option>
              <option value="write">{t(locale, "tokens.new.right_write")}</option>
              <option value="admin">{t(locale, "tokens.new.right_admin")}</option>
            </select>
          </div>
          <div class="form-actions">
            <button type="submit" class="btn btn-primary">{t(locale, "tokens.new.submit")}</button>
            <a href={`/admin/projects/${props.project.id}/service-tokens`} class="btn">{t(locale, "tokens.new.cancel")}</a>
          </div>
        </fieldset>
      </form>
    </Layout>
  );
};

// --- Routes ---

// GET /projects/:pid/service-tokens
app.get("/projects/:pid/service-tokens", requireOwnerOrAdmin("pid"), (c) => {
  const locale = detectLocale(c);
  const projectId = Number(c.req.param("pid"));
  const db = getDb();

  const project = db
    .query<Project, [number]>("SELECT * FROM projects WHERE id = ?")
    .get(projectId);
  if (!project) {
    return c.redirect(flashRedirect("/admin/projects", "error", t(locale, "flash.project_not_found")));
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

  return c.html(
    <TokenListPage
      locale={locale}
      project={project}
      tokens={tokens}
      flash={flash}
    />
  );
});

// GET /projects/:pid/service-tokens/new
app.get("/projects/:pid/service-tokens/new", requireOwnerOrAdmin("pid"), (c) => {
  const locale = detectLocale(c);
  const projectId = Number(c.req.param("pid"));
  const db = getDb();

  const project = db
    .query<Project, [number]>("SELECT * FROM projects WHERE id = ?")
    .get(projectId);
  if (!project) {
    return c.redirect(flashRedirect("/admin/projects", "error", t(locale, "flash.project_not_found")));
  }

  if (isProjectSealed(projectId)) {
    return c.redirect(flashRedirect(`/admin/projects/${projectId}`, "error", t(locale, "flash.unseal_first")));
  }

  const environments = db.query<Environment, []>("SELECT * FROM environments").all();

  return c.html(
    <NewTokenPage locale={locale} project={project} environments={environments} />
  );
});

// POST /projects/:pid/service-tokens — create token
app.post("/projects/:pid/service-tokens", requireOwnerOrAdmin("pid"), async (c) => {
  const locale = detectLocale(c);
  const projectId = Number(c.req.param("pid"));
  const db = getDb();

  const project = db
    .query<Project, [number]>("SELECT * FROM projects WHERE id = ?")
    .get(projectId);
  if (!project) {
    return c.redirect(flashRedirect("/admin/projects", "error", t(locale, "flash.project_not_found")));
  }

  const masterKey = getMasterKey(projectId);
  if (!masterKey) {
    return c.redirect(flashRedirect(`/admin/projects/${projectId}`, "error", t(locale, "flash.unseal_first")));
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
    return c.redirect(flashRedirect(`/admin/projects/${projectId}/service-tokens/new`, "error", t(locale, "tokens.err_required")));
  }

  const { record: _record, generatedToken } = createServiceToken(projectId, envId, friendlyName, rights);
  const publicToken = encodePublicToken(masterKey, generatedToken);

  // Render token directly — NEVER via redirect URL. The public token embeds the master key,
  // so leaking it via Location header is equally severe. See bug 9c497016 / d664fbf2.
  return c.html(
    <SecretRevealPage
      locale={locale}
      title={t(locale, "secret_reveal.service_token_title", { name: friendlyName })}
      description={t(locale, "secret_reveal.service_token_description")}
      warning={t(locale, "secret_reveal.service_token_warning")}
      secret={publicToken}
      downloadFilename={`seklok-service-token-${friendlyName.replace(/[^a-zA-Z0-9-_]/g, "_")}`}
      continueUrl={`/admin/projects/${projectId}/service-tokens`}
    />
  );
});

// POST /projects/:pid/service-tokens/:tid/destroy — revoke
app.post("/projects/:pid/service-tokens/:tid/destroy", requireOwnerOrAdmin("pid"), (c) => {
  const locale = detectLocale(c);
  const projectId = Number(c.req.param("pid"));
  const tokenId = Number(c.req.param("tid"));
  const db = getDb();

  db.prepare<void, [number]>("DELETE FROM service_tokens WHERE id = ?").run(tokenId);

  return c.redirect(flashRedirect(`/admin/projects/${projectId}/service-tokens`, "success", t(locale, "tokens.flash_deleted")));
});

export default app;
