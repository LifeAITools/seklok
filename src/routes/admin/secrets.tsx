import { Hono } from "hono";
import type { FC } from "hono/jsx";
import type { SQLQueryBindings } from "bun:sqlite";
import { getDb, type Project, type Environment, type Secret, type SecretValueHistory } from "../../db.js";
import { encrypt, decrypt } from "../../lib/encryption.js";
import { getMasterKey, isProjectSealed } from "../../lib/master-keys.js";
import { Layout } from "../../views/layout.js";
import { basicAuth } from "../../middleware/basic-auth.js";

const app = new Hono();

app.use("*", basicAuth);

const SECRET_DEFAULT_VALUE = "--------";

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

function retrieveHierarchySecrets(projectIds: number[], environmentId: number): Secret[] {
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

  const toRemove = new Set<number>();
  for (let i = 1; i < rows.length; i++) {
    if (rows[i].name === rows[i - 1].name) {
      toRemove.add(i - 1);
    }
  }
  return rows.filter((_, idx) => !toRemove.has(idx));
}

function findMissingSecrets(
  projectIds: number[],
  environmentId: number
): Map<string, { secretName: string; envNames: string[] }> {
  const db = getDb();
  const currentSecrets = retrieveHierarchySecrets(projectIds, environmentId);
  const currentNames = new Set(currentSecrets.map((s) => s.name));

  const otherEnvs = db
    .query<Environment, [number]>("SELECT * FROM environments WHERE id != ?")
    .all(environmentId);

  const missing = new Map<string, { secretName: string; envNames: string[] }>();

  for (const env of otherEnvs) {
    const envSecrets = retrieveHierarchySecrets(projectIds, env.id);
    for (const secret of envSecrets) {
      if (!currentNames.has(secret.name)) {
        const existing = missing.get(secret.name);
        if (existing) {
          existing.envNames.push(env.name);
        } else {
          missing.set(secret.name, { secretName: secret.name, envNames: [env.name] });
        }
      }
    }
  }

  return missing;
}

// --- Views ---

interface SecretRow {
  id: number;
  name: string;
  value: string;
}

const SecretsPage: FC<{
  project: Project;
  environment: Environment;
  secrets: SecretRow[];
  missingSecrets: { secretName: string; envNames: string[] }[];
  withDecryption: boolean;
  flash?: { type: string; message: string };
}> = (props) => {
  const baseUrl = `/admin/projects/${props.project.id}/environments/${props.environment.id}/secrets`;

  return (
    <Layout
      title={`Secrets - ${props.environment.name}`}
      flash={props.flash}
      projectId={props.project.id}
      projectName={props.project.name}
    >
      <h1>Secrets for {props.project.name} / {props.environment.name}</h1>

      {props.missingSecrets.length > 0 && (
        <div class="warning">
          <strong>Missing secrets</strong> (exist in other environments but not here):
          <ul>
            {props.missingSecrets.map((ms) => (
              <li>
                {ms.secretName} (from: {ms.envNames.join(", ")})
                {" "}
                <button type="button" class="btn btn-sm"
                  onclick={`addSecretRow('${ms.secretName}', '')`}>Add</button>
              </li>
            ))}
          </ul>
        </div>
      )}

      <div class="controls">
        <button type="button" class="btn" onclick="addSecretRow('', '')">+ Add Secret</button>
        {!props.withDecryption
          ? <a class="btn" href={`${baseUrl}?decrypt=true`}>Decrypt Secrets</a>
          : <a class="btn" href={baseUrl}>Hide Values</a>
        }
      </div>

      <form method="post" action={baseUrl} id="secrets-form">
        <input type="hidden" name="deleted_ids" id="deleted-ids" value="" />
        <div id="secrets-container">
          {props.secrets.map((s) => (
            <div class="secret-row" id={`secret-row-${s.id}`}>
              <div class="name-col">
                <input type="text" name={`secrets[${s.id}][name]`} value={s.name} placeholder="SECRET_NAME" required />
              </div>
              <div class="value-col">
                <input type="text" name={`secrets[${s.id}][value]`} value={s.value} placeholder="value" />
              </div>
              <div class="actions-col">
                <button type="button" class="btn btn-sm btn-danger"
                  onclick={`removeSecretRow('${s.id}')`}>Delete</button>
              </div>
            </div>
          ))}
        </div>
        <div class="form-actions">
          <button type="submit" class="btn btn-primary">Save</button>
          <a href={`/admin/projects/${props.project.id}`} class="btn">Back to project</a>
        </div>
      </form>
    </Layout>
  );
};

// --- Routes ---

// GET /projects/:pid/environments/:eid/secrets
app.get("/projects/:pid/environments/:eid/secrets", (c) => {
  const projectId = Number(c.req.param("pid"));
  const envId = Number(c.req.param("eid"));
  const withDecrypt = c.req.query("decrypt") === "true";

  const db = getDb();

  const project = db
    .query<Project, [number]>("SELECT * FROM projects WHERE id = ?")
    .get(projectId);
  if (!project) {
    return c.redirect(flashRedirect("/admin/projects", "error", "Project not found"));
  }

  const environment = db
    .query<Environment, [number]>("SELECT * FROM environments WHERE id = ?")
    .get(envId);
  if (!environment) {
    return c.redirect(flashRedirect(`/admin/projects/${projectId}`, "error", "Environment not found"));
  }

  if (isProjectSealed(projectId) && withDecrypt) {
    return c.redirect(flashRedirect(`/admin/projects/${projectId}`, "error", "Unseal the project first"));
  }

  const projectIds = [projectId];
  if (project.parent_id) projectIds.push(project.parent_id);

  const secrets = retrieveHierarchySecrets(projectIds, envId);

  // Get latest history values
  const masterKey = withDecrypt ? getMasterKey(projectId) : null;

  const secretRows: SecretRow[] = secrets.map((s) => {
    let value = SECRET_DEFAULT_VALUE;
    if (masterKey) {
      const history = db
        .query<SecretValueHistory, [number]>(
          "SELECT * FROM secret_value_histories WHERE secret_id = ? ORDER BY id DESC LIMIT 1"
        )
        .get(s.id);
      if (history) {
        try {
          value = decrypt(masterKey, history.encrypted_value, history.iv_value);
        } catch {
          value = "[decrypt error]";
        }
      }
    }
    return { id: s.id, name: s.name, value };
  });

  const missingMap = findMissingSecrets(projectIds, envId);
  const missingSecrets = Array.from(missingMap.values());

  const flash = flashFromQuery(c);

  return c.html(
    <SecretsPage
      project={project}
      environment={environment}
      secrets={secretRows}
      missingSecrets={missingSecrets}
      withDecryption={withDecrypt}
      flash={flash}
    />
  );
});

// POST /projects/:pid/environments/:eid/secrets — save secrets
app.post("/projects/:pid/environments/:eid/secrets", async (c) => {
  const projectId = Number(c.req.param("pid"));
  const envId = Number(c.req.param("eid"));
  const baseUrl = `/admin/projects/${projectId}/environments/${envId}/secrets`;

  const masterKey = getMasterKey(projectId);
  if (!masterKey) {
    return c.redirect(flashRedirect(`/admin/projects/${projectId}`, "error", "Unseal the project first"));
  }

  const body = await c.req.parseBody();
  const db = getDb();

  // Parse deleted IDs
  const deletedIdsRaw = String(body["deleted_ids"] ?? "");
  const deletedIds = deletedIdsRaw
    ? deletedIdsRaw.split(",").map((id) => Number(id.trim())).filter((id) => !isNaN(id))
    : [];

  // Delete marked secrets
  for (const sid of deletedIds) {
    db.prepare<void, [number]>("DELETE FROM secrets WHERE id = ?").run(sid);
  }

  // Parse secrets from form: secrets[ID][name] and secrets[ID][value]
  const secretsMap = new Map<string, { name: string; value: string }>();

  for (const [key, val] of Object.entries(body)) {
    const match = key.match(/^secrets\[([^\]]+)\]\[(name|value)\]$/);
    if (!match) continue;
    const id = match[1];
    const field = match[2];
    if (!secretsMap.has(id)) {
      secretsMap.set(id, { name: "", value: "" });
    }
    const entry = secretsMap.get(id)!;
    if (field === "name") entry.name = String(val);
    if (field === "value") entry.value = String(val);
  }

  for (const [id, data] of secretsMap) {
    if (!data.name.trim()) continue;
    if (data.value === SECRET_DEFAULT_VALUE) continue;

    const strippedName = data.name.trim().toUpperCase();

    if (id.startsWith("new")) {
      // Create new secret
      if (!data.value) continue;

      db.prepare<void, [number, number, string]>(
        "INSERT INTO secrets (project_id, environment_id, name, comment) VALUES (?, ?, ?, '')"
      ).run(projectId, envId, strippedName);

      const newSecret = db
        .query<Secret, [number, number, string]>(
          "SELECT * FROM secrets WHERE project_id = ? AND environment_id = ? AND name = ? ORDER BY id DESC LIMIT 1"
        )
        .get(projectId, envId, strippedName);

      if (newSecret) {
        const { cipheredData, iv } = encrypt(masterKey, data.value);
        db.prepare<void, [number, string, string]>(
          "INSERT INTO secret_value_histories (secret_id, encrypted_value, iv_value, comment) VALUES (?, ?, ?, '')"
        ).run(newSecret.id, cipheredData, iv);
      }
    } else {
      // Update existing secret
      const secretId = Number(id);
      if (isNaN(secretId)) continue;

      if (deletedIds.includes(secretId)) continue;

      // Check if value actually changed
      if (!data.value) continue;

      const latestHistory = db
        .query<SecretValueHistory, [number]>(
          "SELECT * FROM secret_value_histories WHERE secret_id = ? ORDER BY id DESC LIMIT 1"
        )
        .get(secretId);

      let valueChanged = true;
      if (latestHistory) {
        try {
          const existingValue = decrypt(masterKey, latestHistory.encrypted_value, latestHistory.iv_value);
          if (existingValue === data.value) {
            valueChanged = false;
          }
        } catch {
          // Can't decrypt = value is different from perspective
        }
      }

      if (valueChanged) {
        // Delete old history (non-versioned mode matching Python behavior)
        db.prepare<void, [number]>("DELETE FROM secret_value_histories WHERE secret_id = ?").run(secretId);

        const { cipheredData, iv } = encrypt(masterKey, data.value);
        db.prepare<void, [number, string, string]>(
          "INSERT INTO secret_value_histories (secret_id, encrypted_value, iv_value, comment) VALUES (?, ?, ?, '')"
        ).run(secretId, cipheredData, iv);
      }

      // Update name if changed
      db.prepare<void, [string, number]>("UPDATE secrets SET name = ? WHERE id = ?").run(strippedName, secretId);
    }
  }

  return c.redirect(flashRedirect(baseUrl, "success", "Secrets updated successfully"));
});

export default app;
