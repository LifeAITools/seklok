// ---------------------------------------------------------------------------
// The 8 security invariants — the portable regression gate (CR-05).
//
// These assertions are the seklok security contract. They run GREEN here against
// the public AGPL seklok (the known-good baseline) and are re-pointed at the
// vendored engine in P2/T2.7 (set SEKLOK_TARGET_URL + an engine provisioner) to
// gate the domain port. A red invariant here = a catastrophic, often invisible
// security regression; this suite makes it loud.
//
// Source of the invariant list: PRIME R006 (verified 2026-05-07) + plan T0.1.
// ---------------------------------------------------------------------------

import { describe, test, expect, beforeAll, afterAll } from 'bun:test'
import { randomBytes } from 'node:crypto'
import {
  req,
  basicAuthHeader,
  extractRevealValue,
  provisionTree,
  mintToken,
  putSecret,
  tamperMasterKey,
  startTarget,
  stopTarget,
  type Tree,
} from './harness.js'

let A: Tree
let B: Tree

beforeAll(async () => {
  await startTarget()
  A = await provisionTree('inv-tree-a')
  B = await provisionTree('inv-tree-b')
}, 30_000)

afterAll(stopTarget)

// --- Invariant 1: master-key material is in the BODY, never a header / URL ---
describe('INV-1: master key never in headers or URL', () => {
  test('project creation renders the key in the body, Location is null', async () => {
    const res = await req('/admin/projects', {
      method: 'POST',
      headers: { Authorization: basicAuthHeader(), 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ name: 'inv-1-probe', description: 'probe' }).toString(),
      redirect: 'manual',
    })
    expect(res.status).toBe(200)
    expect(res.headers.get('Location')).toBeNull()
    const key = extractRevealValue(await res.text())
    expect(key.length).toBeGreaterThan(0)
    // The key must not appear in ANY response header.
    for (const [, v] of res.headers.entries()) expect(v).not.toContain(key)
  })

  test('API token issuance returns the token in the JSON body, not a header', async () => {
    const res = await req('/api/v1/service-tokens', {
      method: 'POST',
      headers: { Authorization: `Bearer ${A.adminToken}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({ friendly_name: 'inv1', environment_id: A.envId, rights: ['read'] }),
    })
    expect(res.status).toBe(201)
    const body = (await res.json()) as { public_token: string }
    expect(body.public_token.length).toBeGreaterThan(0)
    for (const [, v] of res.headers.entries()) expect(v).not.toContain(body.public_token)
  })
})

// --- Invariant 2: seal state is observable so the LB can gate on it (REQ-B5) ---
describe('INV-2: seal/unseal state is observable', () => {
  test('GET /api/v1/status exposes db + auto-unseal/reseal + unsealed count', async () => {
    const res = await req('/api/v1/status')
    expect(res.status).toBe(200)
    const body = (await res.json()) as Record<string, unknown>
    expect(body.db).toBe('up')
    expect(body).toHaveProperty('auto_unseal_enabled')
    expect(body).toHaveProperty('auto_reseal_enabled')
    expect(body).toHaveProperty('projects_unsealed')
  })

  test('GET /health is a live alias for the status surface', async () => {
    const res = await req('/health')
    expect(res.status).toBe(200)
  })
})

// --- Invariant 3: plaintext is never served without authorization ----------
describe('INV-3: plaintext secrets never leak unauthenticated', () => {
  const SENTINEL = 'PLAINTEXT-SENTINEL-9c1f'

  beforeAll(async () => {
    await putSecret(A.adminToken, 'INV3_SECRET', SENTINEL)
  })

  test('no auth → 401, no plaintext in body', async () => {
    const res = await req('/api/v1/secrets')
    expect(res.status).toBe(401)
    expect(await res.text()).not.toContain(SENTINEL)
  })

  test('garbage bearer → 401, no plaintext in body', async () => {
    const res = await req('/api/v1/secrets', { headers: { Authorization: 'Bearer garbage-invalid' } })
    expect(res.status).toBe(401)
    expect(await res.text()).not.toContain(SENTINEL)
  })
})

// --- Invariant 4: secret history excludes plaintext (F32-C02) ---------------
describe('INV-4: history never contains plaintext values', () => {
  test('GET /:id/history returns metadata only, no plaintext', async () => {
    const V1 = 'hist-value-one-aa11'
    const V2 = 'hist-value-two-bb22'
    const id = await putSecret(A.adminToken, 'INV4_SECRET', V1)
    const put = await req(`/api/v1/secrets/${id}`, {
      method: 'PUT',
      headers: { Authorization: `Bearer ${A.adminToken}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({ value: V2 }),
    })
    expect(put.status).toBe(200)

    const res = await req(`/api/v1/secrets/${id}/history`, {
      headers: { Authorization: `Bearer ${A.adminToken}` },
    })
    expect(res.status).toBe(200)
    const raw = await res.text()
    expect(raw).not.toContain(V1)
    expect(raw).not.toContain(V2)
  })
})

// --- Invariant 5: RBAC read < write < admin, 403 names the missing right -----
describe('INV-5: RBAC hierarchy enforced with named 403', () => {
  test('read-only token cannot write (403, names "write")', async () => {
    const readToken = await mintToken(A, ['read'], 'inv5-read')
    const res = await req('/api/v1/secrets', {
      method: 'POST',
      headers: { Authorization: `Bearer ${readToken}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({ name: 'INV5_DENIED', value: 'x' }),
    })
    expect(res.status).toBe(403)
    const body = (await res.json()) as { error: string; message: string }
    expect(body.error).toBe('Forbidden')
    expect(body.message).toMatch(/write/i)
  })

  test('write token cannot read history (403, names "admin")', async () => {
    const writeToken = await mintToken(A, ['write'], 'inv5-write')
    const id = await putSecret(A.adminToken, 'INV5_HIST', 'v')
    const res = await req(`/api/v1/secrets/${id}/history`, {
      headers: { Authorization: `Bearer ${writeToken}` },
    })
    expect(res.status).toBe(403)
    const body = (await res.json()) as { message: string }
    expect(body.message).toMatch(/admin/i)
  })

  test('admin token can read history (200)', async () => {
    const id = await putSecret(A.adminToken, 'INV5_HIST_OK', 'v')
    const res = await req(`/api/v1/secrets/${id}/history`, {
      headers: { Authorization: `Bearer ${A.adminToken}` },
    })
    expect(res.status).toBe(200)
  })
})

// --- Invariant 6: a token scoped to tree X cannot read tree Y (US-01) -------
describe('INV-6: cross-tree isolation', () => {
  test("tree A's token never lists tree B's project", async () => {
    const res = await req('/api/v1/projects', { headers: { Authorization: `Bearer ${A.adminToken}` } })
    expect(res.status).toBe(200)
    const body = (await res.json()) as { projects: { id: number; name: string }[] }
    expect(body.projects.some((p) => p.id === A.projectId)).toBe(true)
    expect(body.projects.some((p) => p.name === B.label)).toBe(false)
  })

  test("tree A's token never reads a secret written in tree B", async () => {
    const SENTINEL = 'tree-b-only-7d3e'
    await putSecret(B.adminToken, 'INV6_B_SECRET', SENTINEL)
    const res = await req('/api/v1/secrets', { headers: { Authorization: `Bearer ${A.adminToken}` } })
    expect(res.status).toBe(200)
    expect(await res.text()).not.toContain(SENTINEL)
  })
})

// --- Invariant 7: a wrong master key cannot decrypt (no plaintext leak) -----
describe('INV-7: wrong master key is rejected', () => {
  test('tampered master key yields no plaintext', async () => {
    const SENTINEL = 'inv7-real-value-5a2b'
    await putSecret(A.adminToken, 'INV7_SECRET', SENTINEL)
    const wrongKey = randomBytes(32).toString('base64')
    const tampered = tamperMasterKey(A.adminToken, wrongKey)
    const res = await req('/api/v1/secrets', { headers: { Authorization: `Bearer ${tampered}` } })
    // Either rejected outright or decrypt fails — but NEVER the plaintext.
    expect(res.status).not.toBe(200)
    expect(await res.text()).not.toContain(SENTINEL)
  })
})

// --- Invariant 8: auth endpoints are rate-limited ---------------------------
describe('INV-8: rate limiting on auth endpoints', () => {
  test('POST /auth/login is capped (a burst hits 429)', async () => {
    const statuses: number[] = []
    for (let i = 0; i < 12; i++) {
      const res = await req('/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({ email: 'rl@example.com', password: 'nope' }).toString(),
      })
      statuses.push(res.status)
    }
    expect(statuses).toContain(429)
  })

  test('POST /auth/register is capped (a burst hits 429)', async () => {
    const statuses: number[] = []
    for (let i = 0; i < 8; i++) {
      const res = await req('/auth/register', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({ email: `rl${i}@example.com`, password: 'nope', name: 'x' }).toString(),
      })
      statuses.push(res.status)
    }
    expect(statuses).toContain(429)
  })
})
