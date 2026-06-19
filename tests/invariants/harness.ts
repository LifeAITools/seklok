// ---------------------------------------------------------------------------
// Invariant harness — shared seam for the 8 security-invariant probes (CR-05).
//
// PORTABLE BY DESIGN, and a true black box. Every probe is a real HTTP `fetch`
// against a running instance, so the SAME suite gates BOTH deployments:
//   • Public AGPL seklok (this repo) — LOCAL mode: the harness spawns the app as
//     a subprocess on its own port + throwaway DB, the known-green baseline.
//   • The vendored engine (seklok-cloud) — REMOTE mode: set SEKLOK_TARGET_URL to
//     the running engine; the engine ships its own provisioner (control-API) and
//     the invariant assertions run UNCHANGED.
//
// Real-HTTP (not in-process app.fetch) is deliberate: it gives header/transport
// fidelity, matches exactly how the engine will be probed in P2/T2.7, and avoids
// the shared-ESM-module-cache collision that an in-process import causes when
// this file runs alongside tests/api.test.ts in one `bun test` invocation.
//
// The ONLY target-specific piece is provisioning (create a project tree + mint
// an admin token); it is quarantined in `provisionTree()` (LOCAL/admin-UI here,
// control-API in the engine). Everything the invariants assert rides the stable
// data-plane contract (`/api/v1/*`, REQ-C1 backward-compatible).
// ---------------------------------------------------------------------------

import { Database } from 'bun:sqlite'
import { existsSync, unlinkSync } from 'node:fs'
import type { Subprocess } from 'bun'

// --- Test configuration ----------------------------------------------------
const TEST_DB = process.env.SEKLOK_INVARIANT_DB ?? '/tmp/seklok-invariants-test.db'
const PORT = process.env.SEKLOK_INVARIANT_PORT ?? '4488'
export const ADMIN_USER = 'admin'
export const ADMIN_PASS = 'invariant-test-pass'

/** REMOTE: probe a live target (the engine in T2.7). LOCAL: spawn public seklok. */
const REMOTE_URL = process.env.SEKLOK_TARGET_URL ?? ''
export const IS_LOCAL = REMOTE_URL === ''
const BASE = IS_LOCAL ? `http://localhost:${PORT}` : REMOTE_URL

let child: Subprocess | null = null

/** Spawn the public-seklok app as an isolated subprocess (LOCAL mode only). */
export async function startTarget(): Promise<void> {
  if (!IS_LOCAL) return
  if (existsSync(TEST_DB)) unlinkSync(TEST_DB)
  child = Bun.spawn(['bun', 'run', 'src/index.tsx'], {
    cwd: process.cwd(),
    env: {
      ...process.env,
      PORT,
      DB_PATH: TEST_DB,
      ADMIN_BASIC_AUTH_USERNAME: ADMIN_USER,
      ADMIN_BASIC_AUTH_PASSWORD: ADMIN_PASS,
      AVAILABLE_ENVIRONMENTS: 'development,staging,production',
      MASTER_KEY_EXPIRATION: '300',
    },
    stdout: 'ignore',
    stderr: 'ignore',
  })
  await waitForReady()
}

/** Stop the subprocess + remove the throwaway DB (call from afterAll). */
export function stopTarget(): void {
  if (child) {
    child.kill()
    child = null
  }
  if (IS_LOCAL && existsSync(TEST_DB)) {
    try {
      unlinkSync(TEST_DB)
    } catch {
      /* best-effort */
    }
  }
}

/** Transport-agnostic request — always real HTTP against the resolved target. */
export function req(path: string, init?: RequestInit): Promise<Response> {
  return fetch(`${BASE}${path}`, init)
}

export function basicAuthHeader(): string {
  return 'Basic ' + Buffer.from(`${ADMIN_USER}:${ADMIN_PASS}`).toString('base64')
}

/** Scrape the master-key / token value the admin UI renders into the reveal
 *  input (it is deliberately in the BODY, never a header/URL — invariant 1). */
export function extractRevealValue(html: string): string {
  const m = html.match(/id="reveal_secret_input"[^>]*value="([^"]+)"/)
  return m?.[1] ?? ''
}

/**
 * Wait until the target accepts admin-authenticated writes. We poll the status
 * endpoint AND (LOCAL) the seeded admin row: the public seklok seeds its admin
 * from an UN-awaited async `seedAdmin()` (fire-and-forget in initDb), so the
 * first request can race ahead of the seed and hit an empty users table → a FK
 * failure on project creation. We wait for the seed to land deterministically.
 */
export async function waitForReady(timeoutMs = 15_000): Promise<void> {
  const deadline = Date.now() + timeoutMs
  while (Date.now() < deadline) {
    try {
      const res = await req('/api/v1/status')
      if (res.status === 200) {
        if (!IS_LOCAL) return
        const db = new Database(TEST_DB, { readonly: true })
        const row = db.query("SELECT 1 FROM users WHERE role = 'admin' LIMIT 1").get()
        db.close()
        if (row) return
      }
    } catch {
      /* not listening yet — retry */
    }
    await new Promise((r) => setTimeout(r, 100))
  }
  throw new Error('waitForReady: target did not become ready within timeout')
}

/** A provisioned, isolated project tree + its admin service-token. */
export interface Tree {
  label: string
  masterKey: string
  projectId: number
  envId: number
  adminToken: string
}

/**
 * Provision a fresh project tree + admin token. BASELINE (LOCAL) provisioner —
 * it reads the throwaway sqlite to resolve the integer ids the admin UI does not
 * echo (quarantined here; the invariant assertions never touch the DB). The
 * engine adapter (T2.7) replaces this with control-API calls.
 */
export async function provisionTree(label: string): Promise<Tree> {
  if (!IS_LOCAL) {
    throw new Error(
      'provisionTree: REMOTE-target provisioning is supplied by the engine adapter (P2/T2.7), not the baseline harness',
    )
  }

  // 1. Create the project — master key is rendered in the BODY (Location null).
  const createRes = await req('/admin/projects', {
    method: 'POST',
    headers: {
      Authorization: basicAuthHeader(),
      'Content-Type': 'application/x-www-form-urlencoded',
    },
    body: new URLSearchParams({ name: label, description: `invariant tree ${label}` }).toString(),
    redirect: 'manual',
  })
  if (createRes.status !== 200) {
    const loc = createRes.headers.get('Location')
    throw new Error(`provisionTree(${label}): project create returned ${createRes.status} (Location=${loc})`)
  }
  const masterKey = extractRevealValue(await createRes.text())
  if (!masterKey) throw new Error(`provisionTree(${label}): master key not found in body`)

  // 2. Resolve the integer ids the admin UI did not echo (baseline only).
  const db = new Database(TEST_DB, { readonly: true })
  const projectRow = db
    .query<{ id: number }, [string]>('SELECT id FROM projects WHERE name = ? ORDER BY id DESC LIMIT 1')
    .get(label)
  const envRow = db
    .query<{ id: number }, []>("SELECT id FROM environments WHERE name = 'development'")
    .get()
  db.close()
  if (!projectRow || !envRow) throw new Error(`provisionTree(${label}): id resolution failed`)

  // 3. Mint an admin service-token via the admin UI (token rendered in body).
  const tokenRes = await req(`/admin/projects/${projectRow.id}/service-tokens`, {
    method: 'POST',
    headers: {
      Authorization: basicAuthHeader(),
      'Content-Type': 'application/x-www-form-urlencoded',
    },
    body: new URLSearchParams({
      friendly_name: `${label}-admin`,
      environment_id: String(envRow.id),
      rights: 'admin',
    }).toString(),
    redirect: 'manual',
  })
  if (tokenRes.status !== 200) {
    throw new Error(`provisionTree(${label}): token create returned ${tokenRes.status}`)
  }
  const adminToken = extractRevealValue(await tokenRes.text())
  if (!adminToken) throw new Error(`provisionTree(${label}): admin token not found in body`)

  return { label, masterKey, projectId: projectRow.id, envId: envRow.id, adminToken }
}

/** Mint a scoped service-token via the DATA-PLANE API (portable path). The API
 *  decodes the master key from the presenting admin token, so no UI scrape. */
export async function mintToken(tree: Tree, rights: string[], name = 'scoped'): Promise<string> {
  const res = await req('/api/v1/service-tokens', {
    method: 'POST',
    headers: { Authorization: `Bearer ${tree.adminToken}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({ friendly_name: name, environment_id: tree.envId, rights }),
  })
  if (res.status !== 201 && res.status !== 200) {
    throw new Error(`mintToken(${rights.join(',')}): returned ${res.status}`)
  }
  const body = (await res.json()) as { public_token: string }
  return body.public_token
}

/** Create a secret in a tree via the data-plane API (used to set up probes). */
export async function putSecret(token: string, name: string, value: string): Promise<number> {
  const res = await req('/api/v1/secrets', {
    method: 'POST',
    headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({ name, value }),
  })
  if (res.status !== 201) throw new Error(`putSecret(${name}): returned ${res.status}`)
  const body = (await res.json()) as { secret: { id: number } }
  return body.secret.id
}

/** Re-encode an admin token with a different master key (invariant 7 probe).
 *  Token scheme = base64(masterKey + ':' + generatedToken); swap the key half. */
export function tamperMasterKey(publicToken: string, wrongKeyB64: string): string {
  const decoded = Buffer.from(publicToken, 'base64').toString('utf-8')
  const sep = decoded.indexOf(':')
  const generated = decoded.slice(sep + 1)
  return Buffer.from(`${wrongKeyB64}:${generated}`).toString('base64')
}
