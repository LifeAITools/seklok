import { describe, test, expect, beforeAll, afterAll } from "bun:test";
import { unlinkSync, existsSync } from "node:fs";

const TEST_DB = "/tmp/seklok-test.db";
const ADMIN_USER = "admin";
const ADMIN_PASS = "test123";

// Set env vars BEFORE any app imports
process.env.PORT = "4499";
process.env.DB_PATH = TEST_DB;
process.env.ADMIN_BASIC_AUTH_USERNAME = ADMIN_USER;
process.env.ADMIN_BASIC_AUTH_PASSWORD = ADMIN_PASS;
process.env.AVAILABLE_ENVIRONMENTS = "development,staging,production";
process.env.MASTER_KEY_EXPIRATION = "300";

// Clean up before import
if (existsSync(TEST_DB)) unlinkSync(TEST_DB);

// Import app after env vars are set
const appModule = await import("../src/index.js");
const appFetch = appModule.default.fetch;

function req(path: string, init?: RequestInit): Promise<Response> {
  return appFetch(new Request(`http://localhost${path}`, init));
}

function basicAuthHeader(): string {
  return "Basic " + Buffer.from(`${ADMIN_USER}:${ADMIN_PASS}`).toString("base64");
}

afterAll(() => {
  if (existsSync(TEST_DB)) {
    try { unlinkSync(TEST_DB); } catch {}
  }
});

describe("API Integration Tests", () => {
  let masterKey: string;
  let projectId: number;
  let publicToken: string; // admin token
  let readOnlyPublicToken: string;
  let writePublicToken: string;
  let secretId: number;

  // ===== 1. Health check =====
  test("GET /api/v1/status returns 200 and db up", async () => {
    const res = await req("/api/v1/status");
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.db).toBe("up");
  });

  // ===== 2. Admin UI requires auth =====
  test("GET /admin/projects without auth returns 401", async () => {
    const res = await req("/admin/projects");
    expect(res.status).toBe(401);
  });

  // ===== 3. Admin UI with auth =====
  test("GET /admin/projects with Basic auth returns 200", async () => {
    const res = await req("/admin/projects", {
      headers: { Authorization: basicAuthHeader() },
    });
    expect(res.status).toBe(200);
    const text = await res.text();
    expect(text).toContain("Projects");
  });

  // ===== 4. Create project via admin POST =====
  test("POST /admin/projects creates project and returns master key in HTML body (NOT in URL)", async () => {
    const formBody = new URLSearchParams({
      name: "test-project",
      description: "Test project for E2E",
    });

    const res = await req("/admin/projects", {
      method: "POST",
      headers: {
        Authorization: basicAuthHeader(),
        "Content-Type": "application/x-www-form-urlencoded",
      },
      body: formBody.toString(),
      redirect: "manual",
    });

    // Security: master key must be rendered directly in the response body,
    // never in Location header / redirect URL (would leak to proxy logs).
    expect(res.status).toBe(200);
    expect(res.headers.get("Location")).toBeNull();

    const html = await res.text();
    // Extract master key from the readonly input value="..."
    const match = html.match(/id="reveal_secret_input"[^>]*value="([^"]+)"/);
    expect(match).not.toBeNull();
    masterKey = match![1] ?? "";
    expect(masterKey.length).toBeGreaterThan(0);

    // Verify project exists
    const listRes = await req("/admin/projects", {
      headers: { Authorization: basicAuthHeader() },
    });
    const listText = await listRes.text();
    expect(listText).toContain("test-project");
  });

  // ===== 5. Get project ID from DB =====
  test("project ID is available", async () => {
    // Get project ID by loading the admin detail page
    // Project should be id=1 since it's the first
    const { Database } = await import("bun:sqlite");
    const db = new Database(TEST_DB, { readonly: true });
    const row = db.query<{ id: number }, []>("SELECT id FROM projects WHERE name = 'test-project'").get();
    db.close();
    expect(row).not.toBeNull();
    projectId = row!.id;
    expect(projectId).toBeGreaterThan(0);
  });

  // ===== 6. Create admin service token via admin UI =====
  test("POST admin service-tokens creates token", async () => {
    // First, we need to make sure master key is in memory (it was set during project creation)
    // Get environment ID for 'development'
    const { Database } = await import("bun:sqlite");
    const db = new Database(TEST_DB, { readonly: true });
    const env = db.query<{ id: number }, []>("SELECT id FROM environments WHERE name = 'development'").get();
    db.close();
    expect(env).not.toBeNull();
    const envId = env!.id;

    const formBody = new URLSearchParams({
      friendly_name: "admin-token",
      environment_id: String(envId),
      rights: "admin",
    });

    const res = await req(`/admin/projects/${projectId}/service-tokens`, {
      method: "POST",
      headers: {
        Authorization: basicAuthHeader(),
        "Content-Type": "application/x-www-form-urlencoded",
      },
      body: formBody.toString(),
      redirect: "manual",
    });

    // Security: token must be rendered directly in HTML, never via Location header.
    expect(res.status).toBe(200);
    expect(res.headers.get("Location")).toBeNull();

    const html = await res.text();
    const match = html.match(/id="reveal_secret_input"[^>]*value="([^"]+)"/);
    expect(match).not.toBeNull();
    publicToken = match![1] ?? "";
    expect(publicToken.length).toBeGreaterThan(0);
  });

  // ===== 7. API with service token: list secrets (empty) =====
  test("GET /api/v1/secrets with Bearer token returns secrets", async () => {
    const res = await req("/api/v1/secrets", {
      headers: { Authorization: `Bearer ${publicToken}` },
    });
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.secrets).toBeInstanceOf(Array);
    expect(body.secrets.length).toBe(0);
  });

  // ===== 8. API: list environments =====
  test("GET /api/v1/environments returns environments", async () => {
    const res = await req("/api/v1/environments", {
      headers: { Authorization: `Bearer ${publicToken}` },
    });
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.environments).toBeInstanceOf(Array);
    expect(body.environments.length).toBe(3);
    const names = body.environments.map((e: { name: string }) => e.name);
    expect(names).toContain("development");
    expect(names).toContain("staging");
    expect(names).toContain("production");
  });

  // ===== 9. API: list projects =====
  test("GET /api/v1/projects returns projects", async () => {
    const res = await req("/api/v1/projects", {
      headers: { Authorization: `Bearer ${publicToken}` },
    });
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.projects).toBeInstanceOf(Array);
    expect(body.projects.length).toBeGreaterThanOrEqual(1);
  });

  // ===== 10. API: create secret =====
  test("POST /api/v1/secrets creates a secret", async () => {
    const res = await req("/api/v1/secrets", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${publicToken}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        name: "DB_PASSWORD",
        value: "super-secret-123",
        comment: "database password",
      }),
    });
    expect(res.status).toBe(201);
    const body = await res.json();
    expect(body.secret.name).toBe("DB_PASSWORD");
    secretId = body.secret.id;
    expect(secretId).toBeGreaterThan(0);
  });

  // ===== 11. API: read secrets back (decrypted) =====
  test("GET /api/v1/secrets returns decrypted secret", async () => {
    const res = await req("/api/v1/secrets", {
      headers: { Authorization: `Bearer ${publicToken}` },
    });
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.secrets.length).toBe(1);
    expect(body.secrets[0].name).toBe("DB_PASSWORD");
    expect(body.secrets[0].value).toBe("super-secret-123");
  });

  // ===== 12. Invalid token returns 401 =====
  test("GET /api/v1/secrets with garbage token returns 401", async () => {
    const res = await req("/api/v1/secrets", {
      headers: { Authorization: "Bearer garbage-invalid-token" },
    });
    expect(res.status).toBe(401);
  });

  // ===== 13. No auth header returns 401 =====
  test("GET /api/v1/secrets without auth returns 401", async () => {
    const res = await req("/api/v1/secrets");
    expect(res.status).toBe(401);
  });

  // ===== 14. Create read-only token for RBAC tests =====
  test("create read-only service token", async () => {
    const { Database } = await import("bun:sqlite");
    const db = new Database(TEST_DB, { readonly: true });
    const env = db.query<{ id: number }, []>("SELECT id FROM environments WHERE name = 'development'").get();
    db.close();

    const formBody = new URLSearchParams({
      friendly_name: "read-token",
      environment_id: String(env!.id),
      rights: "read",
    });

    const res = await req(`/admin/projects/${projectId}/service-tokens`, {
      method: "POST",
      headers: {
        Authorization: basicAuthHeader(),
        "Content-Type": "application/x-www-form-urlencoded",
      },
      body: formBody.toString(),
      redirect: "manual",
    });

    expect(res.status).toBe(200);
    expect(res.headers.get("Location")).toBeNull();
    const html = await res.text();
    const match = html.match(/id="reveal_secret_input"[^>]*value="([^"]+)"/);
    expect(match).not.toBeNull();
    readOnlyPublicToken = match![1] ?? "";
    expect(readOnlyPublicToken.length).toBeGreaterThan(0);
  });

  // ===== 15. RBAC: read-only can GET secrets =====
  test("read-only token can GET /api/v1/secrets", async () => {
    const res = await req("/api/v1/secrets", {
      headers: { Authorization: `Bearer ${readOnlyPublicToken}` },
    });
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.secrets.length).toBeGreaterThanOrEqual(1);
  });

  // ===== 16. RBAC: read-only cannot POST secrets =====
  test("read-only token cannot POST /api/v1/secrets", async () => {
    const res = await req("/api/v1/secrets", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${readOnlyPublicToken}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ name: "FORBIDDEN", value: "nope" }),
    });
    expect(res.status).toBe(403);
  });

  // ===== 17. RBAC: read-only cannot DELETE secrets =====
  test("read-only token cannot DELETE /api/v1/secrets/:id", async () => {
    const res = await req(`/api/v1/secrets/${secretId}`, {
      method: "DELETE",
      headers: { Authorization: `Bearer ${readOnlyPublicToken}` },
    });
    expect(res.status).toBe(403);
  });

  // ===== 18. Create write token =====
  test("create write service token", async () => {
    const { Database } = await import("bun:sqlite");
    const db = new Database(TEST_DB, { readonly: true });
    const env = db.query<{ id: number }, []>("SELECT id FROM environments WHERE name = 'development'").get();
    db.close();

    const formBody = new URLSearchParams({
      friendly_name: "write-token",
      environment_id: String(env!.id),
      rights: "write",
    });

    const res = await req(`/admin/projects/${projectId}/service-tokens`, {
      method: "POST",
      headers: {
        Authorization: basicAuthHeader(),
        "Content-Type": "application/x-www-form-urlencoded",
      },
      body: formBody.toString(),
      redirect: "manual",
    });

    expect(res.status).toBe(200);
    expect(res.headers.get("Location")).toBeNull();
    const html = await res.text();
    const match = html.match(/id="reveal_secret_input"[^>]*value="([^"]+)"/);
    expect(match).not.toBeNull();
    writePublicToken = match![1] ?? "";
    expect(writePublicToken.length).toBeGreaterThan(0);
  });

  // ===== 19. Secret update via PUT =====
  test("PUT /api/v1/secrets/:id updates secret value", async () => {
    const res = await req(`/api/v1/secrets/${secretId}`, {
      method: "PUT",
      headers: {
        Authorization: `Bearer ${writePublicToken}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ value: "new-password-456", comment: "rotated" }),
    });
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.secret.id).toBe(secretId);
  });

  // ===== 20. Read back updated secret =====
  test("GET /api/v1/secrets returns updated value", async () => {
    const res = await req("/api/v1/secrets", {
      headers: { Authorization: `Bearer ${publicToken}` },
    });
    expect(res.status).toBe(200);
    const body = await res.json();
    const dbPass = body.secrets.find((s: { name: string }) => s.name === "DB_PASSWORD");
    expect(dbPass).toBeDefined();
    expect(dbPass.value).toBe("new-password-456");
  });

  // ===== 21. Secret history has 2 entries =====
  test("GET /api/v1/secrets/:id/history returns 2 entries", async () => {
    const res = await req(`/api/v1/secrets/${secretId}/history`, {
      headers: { Authorization: `Bearer ${publicToken}` },
    });
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.history.length).toBe(2);
  });

  // ===== 22. RBAC: write token cannot access history (requires admin) =====
  test("write token cannot GET /api/v1/secrets/:id/history", async () => {
    const res = await req(`/api/v1/secrets/${secretId}/history`, {
      headers: { Authorization: `Bearer ${writePublicToken}` },
    });
    expect(res.status).toBe(403);
  });

  // ===== 23. Missing secrets detection =====
  test("GET /api/v1/secrets/missing detects missing secrets in other envs", async () => {
    // Create a second admin token for staging env to add a secret there
    const { Database } = await import("bun:sqlite");
    const db = new Database(TEST_DB, { readonly: true });
    const stagingEnv = db.query<{ id: number }, []>(
      "SELECT id FROM environments WHERE name = 'staging'"
    ).get();
    db.close();

    // Create a staging admin token
    const formBody = new URLSearchParams({
      friendly_name: "staging-admin",
      environment_id: String(stagingEnv!.id),
      rights: "admin",
    });

    const tokenRes = await req(`/admin/projects/${projectId}/service-tokens`, {
      method: "POST",
      headers: {
        Authorization: basicAuthHeader(),
        "Content-Type": "application/x-www-form-urlencoded",
      },
      body: formBody.toString(),
      redirect: "manual",
    });

    expect(tokenRes.status).toBe(200);
    const tokenHtml = await tokenRes.text();
    const tokenMatch = tokenHtml.match(/id="reveal_secret_input"[^>]*value="([^"]+)"/);
    expect(tokenMatch).not.toBeNull();
    const stagingToken = tokenMatch![1] ?? "";

    // Add a secret ONLY in staging
    const createRes = await req("/api/v1/secrets", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${stagingToken}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        name: "STAGING_ONLY_KEY",
        value: "staging-value",
      }),
    });
    expect(createRes.status).toBe(201);

    // Now check missing from development's perspective (using admin dev token)
    const missingRes = await req("/api/v1/secrets/missing", {
      headers: { Authorization: `Bearer ${publicToken}` },
    });
    expect(missingRes.status).toBe(200);
    const missingBody = await missingRes.json();
    const stagingOnly = missingBody.missing.find(
      (m: { name: string }) => m.name === "STAGING_ONLY_KEY"
    );
    expect(stagingOnly).toBeDefined();
    expect(stagingOnly.exists_in).toContain("staging");
  });

  // ===== 24. Home page returns HTML =====
  test("GET / returns HTML home page", async () => {
    const res = await req("/");
    expect(res.status).toBe(200);
    const text = await res.text();
    expect(text).toContain("html");
  });

  // ===== 25. RBAC: write token cannot DELETE =====
  test("write token cannot DELETE /api/v1/secrets/:id", async () => {
    const res = await req(`/api/v1/secrets/${secretId}`, {
      method: "DELETE",
      headers: { Authorization: `Bearer ${writePublicToken}` },
    });
    expect(res.status).toBe(403);
  });

  // ===== Integration: status endpoint exposes unseal state and config =====
  test("GET /api/v1/status reports auto-reseal/auto-unseal config flags", async () => {
    const res = await req("/api/v1/status");
    expect(res.status).toBe(200);
    const body = await res.json();

    // Default config: auto-reseal ON, auto-unseal OFF.
    // (test setup at top of file does not set MASTER_KEY_DISABLE_AUTO_RESEAL or SEKLOK_AUTO_UNSEAL_FILE)
    expect(body.auto_reseal_enabled).toBe(true);
    expect(body.auto_unseal_enabled).toBe(false);
    expect(typeof body.master_key_expiration_seconds).toBe("number");

    // After test #4 (POST /admin/projects), at least one project exists and was unsealed
    expect(body.projects_total).toBeGreaterThanOrEqual(1);
    expect(body.projects_unsealed).toBeGreaterThanOrEqual(1);
  });

  // ===== 26. Admin token CAN delete =====
  test("admin token can DELETE /api/v1/secrets/:id", async () => {
    // First create a throwaway secret to delete
    const createRes = await req("/api/v1/secrets", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${publicToken}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ name: "TO_DELETE", value: "temp" }),
    });
    expect(createRes.status).toBe(201);
    const createBody = await createRes.json();
    const tempId = createBody.secret.id;

    const res = await req(`/api/v1/secrets/${tempId}`, {
      method: "DELETE",
      headers: { Authorization: `Bearer ${publicToken}` },
    });
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.deleted).toBe(true);
  });
});
