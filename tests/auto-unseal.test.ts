/**
 * Tests for auto-unseal subsystem.
 *
 * Uses autoUnsealWithDeps() (the dependency-injected entry point) so each test
 * runs against a fresh in-memory project store and a fresh in-memory unseal
 * map — no shared module state, no singletons, no env-var racing.
 */
import { describe, test, expect, beforeAll, afterAll } from "bun:test";
import { writeFileSync, chmodSync, unlinkSync, existsSync, mkdirSync, rmSync } from "node:fs";
import { join } from "node:path";

// IMPORTANT: do NOT static-import master-keys here. Static imports trigger
// evaluation of config.ts at module load time, which freezes env vars BEFORE
// other test files (e.g. api.test.ts) get a chance to set them. Use lazy
// dynamic import inside beforeAll instead.
type AutoUnsealDeps = import("../src/lib/master-keys").AutoUnsealDeps;
type AutoUnsealResult = import("../src/lib/master-keys").AutoUnsealResult;

let autoUnsealWithDeps: (deps: AutoUnsealDeps) => AutoUnsealResult;

const TMP_DIR = "/tmp/seklok-auto-unseal-tests";

function tmpFile(name: string): string {
  return join(TMP_DIR, name);
}

function cleanup(...paths: string[]) {
  for (const p of paths) {
    try { if (existsSync(p)) unlinkSync(p); } catch { /* ignore */ }
  }
}

beforeAll(async () => {
  if (!existsSync(TMP_DIR)) mkdirSync(TMP_DIR, { recursive: true });

  // Dynamic import — by this time api.test.ts has already had a chance to set
  // its env vars, so config.ts evaluation here uses the unified test config.
  const mod = await import("../src/lib/master-keys");
  autoUnsealWithDeps = mod.autoUnsealWithDeps;
});

afterAll(() => {
  try { rmSync(TMP_DIR, { recursive: true, force: true }); } catch { /* ignore */ }
});

/**
 * Build a synthetic dependency set that simulates the DB and the in-memory
 * unseal Map. Returns the deps plus the underlying mutable state so tests can
 * inspect outcomes (e.g. which projects ended up unsealed).
 */
function makeDeps(opts: {
  filePath: string;
  /** Map of projectId -> {name, expectedKey}. validate() succeeds iff key matches expectedKey. */
  projects: Map<number, { name: string; expectedKey: string }>;
}): {
  deps: AutoUnsealDeps;
  /** Projects whose unseal() was called, mapped to the key that was stored. */
  unsealed: Map<number, string>;
  logs: { info: string[]; warn: string[]; error: string[] };
} {
  const unsealed = new Map<number, string>();
  const logs = { info: [] as string[], warn: [] as string[], error: [] as string[] };
  const deps: AutoUnsealDeps = {
    filePath: opts.filePath,
    lookupProject: (id) => {
      const p = opts.projects.get(id);
      return p ? { id, name: p.name } : null;
    },
    validate: (id, key) => {
      const p = opts.projects.get(id);
      return p ? p.expectedKey === key : false;
    },
    unseal: (id, key) => {
      unsealed.set(id, key);
    },
    logger: {
      info: (m) => logs.info.push(m),
      warn: (m) => logs.warn.push(m),
      error: (m) => logs.error.push(m),
    },
  };
  return { deps, unsealed, logs };
}

describe("autoUnsealWithDeps — feature toggle", () => {
  test("disabled when filePath is empty", () => {
    const { deps, unsealed } = makeDeps({ filePath: "", projects: new Map() });
    const r = autoUnsealWithDeps(deps);

    expect(r.enabled).toBe(false);
    expect(r.unsealed).toEqual([]);
    expect(unsealed.size).toBe(0);
  });
});

describe("autoUnsealWithDeps — file/permission validation", () => {
  test("missing file is non-fatal warning", () => {
    const path = tmpFile("missing.json");
    cleanup(path);

    const { deps } = makeDeps({ filePath: path, projects: new Map() });
    const r = autoUnsealWithDeps(deps);

    expect(r.enabled).toBe(true);
    expect(r.unsealed).toEqual([]);
    expect(r.warnings.length).toBe(1);
    expect(r.warnings[0]).toContain("not found");
  });

  test("refuses keyfile with mode 0644 (group/other readable)", () => {
    const path = tmpFile("mode-0644.json");
    cleanup(path);
    writeFileSync(path, "{}");
    chmodSync(path, 0o644);

    const { deps, unsealed } = makeDeps({ filePath: path, projects: new Map() });
    const r = autoUnsealWithDeps(deps);

    expect(r.unsealed).toEqual([]);
    expect(unsealed.size).toBe(0);
    expect(r.warnings.length).toBe(1);
    expect(r.warnings[0]).toMatch(/mode 0644.*0600 or 0400/);
  });

  test("refuses keyfile with mode 0660", () => {
    const path = tmpFile("mode-0660.json");
    cleanup(path);
    writeFileSync(path, "{}");
    chmodSync(path, 0o660);

    const { deps } = makeDeps({ filePath: path, projects: new Map() });
    const r = autoUnsealWithDeps(deps);

    expect(r.warnings[0]).toMatch(/mode 0660/);
  });

  test("accepts mode 0600", () => {
    const path = tmpFile("mode-0600.json");
    cleanup(path);
    const KEY = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
    const projects = new Map([[1, { name: "p1", expectedKey: KEY }]]);
    writeFileSync(path, JSON.stringify({ "1": KEY }));
    chmodSync(path, 0o600);

    const { deps, unsealed } = makeDeps({ filePath: path, projects });
    const r = autoUnsealWithDeps(deps);

    expect(r.warnings).toEqual([]);
    expect(r.unsealed).toEqual([1]);
    expect(unsealed.get(1)).toBe(KEY);
  });

  test("accepts mode 0400 (read-only)", () => {
    const path = tmpFile("mode-0400.json");
    cleanup(path);
    const KEY = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=";
    const projects = new Map([[2, { name: "p2", expectedKey: KEY }]]);
    writeFileSync(path, JSON.stringify({ "2": KEY }));
    chmodSync(path, 0o400);

    const { deps, unsealed } = makeDeps({ filePath: path, projects });
    const r = autoUnsealWithDeps(deps);

    expect(r.unsealed).toEqual([2]);
    expect(unsealed.get(2)).toBe(KEY);
  });
});

describe("autoUnsealWithDeps — JSON parsing", () => {
  test("malformed JSON is logged and non-fatal", () => {
    const path = tmpFile("malformed.json");
    cleanup(path);
    writeFileSync(path, "{ this is not json");
    chmodSync(path, 0o600);

    const { deps, unsealed } = makeDeps({ filePath: path, projects: new Map() });
    const r = autoUnsealWithDeps(deps);

    expect(r.unsealed).toEqual([]);
    expect(unsealed.size).toBe(0);
    expect(r.warnings.length).toBe(1);
    expect(r.warnings[0]).toContain("parse failed");
  });

  test("array root is refused", () => {
    const path = tmpFile("array-root.json");
    cleanup(path);
    writeFileSync(path, "[1, 2, 3]");
    chmodSync(path, 0o600);

    const { deps } = makeDeps({ filePath: path, projects: new Map() });
    const r = autoUnsealWithDeps(deps);

    expect(r.unsealed).toEqual([]);
    expect(r.warnings[0]).toMatch(/parse failed.*expected JSON object/);
  });

  test("null root is refused", () => {
    const path = tmpFile("null-root.json");
    cleanup(path);
    writeFileSync(path, "null");
    chmodSync(path, 0o600);

    const { deps } = makeDeps({ filePath: path, projects: new Map() });
    const r = autoUnsealWithDeps(deps);

    expect(r.warnings[0]).toMatch(/parse failed.*expected JSON object/);
  });
});

describe("autoUnsealWithDeps — entry validation", () => {
  test("hash mismatch is logged, key NOT unsealed", () => {
    const path = tmpFile("mismatch.json");
    cleanup(path);
    const REAL = "DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD=";
    const WRONG = "EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE=";
    const projects = new Map([[1, { name: "p1", expectedKey: REAL }]]);
    writeFileSync(path, JSON.stringify({ "1": WRONG }));
    chmodSync(path, 0o600);

    const { deps, unsealed } = makeDeps({ filePath: path, projects });
    const r = autoUnsealWithDeps(deps);

    expect(r.unsealed).toEqual([]);
    expect(r.hashMismatch).toEqual([1]);
    expect(unsealed.size).toBe(0);
  });

  test("unknown project id is skipped", () => {
    const path = tmpFile("unknown.json");
    cleanup(path);
    writeFileSync(path, JSON.stringify({ "9999": "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF=" }));
    chmodSync(path, 0o600);

    const { deps } = makeDeps({ filePath: path, projects: new Map() });
    const r = autoUnsealWithDeps(deps);

    expect(r.unknownProjects).toEqual([9999]);
    expect(r.unsealed).toEqual([]);
  });

  test("non-numeric project key is skipped with warning", () => {
    const path = tmpFile("non-numeric.json");
    cleanup(path);
    writeFileSync(path, JSON.stringify({ "abc": "key", "1xyz": "key" }));
    chmodSync(path, 0o600);

    const { deps } = makeDeps({ filePath: path, projects: new Map() });
    const r = autoUnsealWithDeps(deps);

    expect(r.unsealed).toEqual([]);
    expect(r.warnings.length).toBe(2);
    expect(r.warnings[0]).toContain("invalid projectId");
  });

  test("negative or zero project id is rejected", () => {
    const path = tmpFile("neg-zero.json");
    cleanup(path);
    writeFileSync(path, JSON.stringify({ "-1": "key", "0": "key" }));
    chmodSync(path, 0o600);

    const { deps } = makeDeps({ filePath: path, projects: new Map() });
    const r = autoUnsealWithDeps(deps);

    expect(r.unsealed).toEqual([]);
    expect(r.warnings.length).toBe(2);
  });

  test("non-string master key value is rejected", () => {
    const path = tmpFile("non-string.json");
    cleanup(path);
    const projects = new Map([[1, { name: "p1", expectedKey: "any" }]]);
    writeFileSync(path, JSON.stringify({ "1": 12345 }));
    chmodSync(path, 0o600);

    const { deps } = makeDeps({ filePath: path, projects });
    const r = autoUnsealWithDeps(deps);

    expect(r.unsealed).toEqual([]);
    expect(r.warnings.length).toBe(1);
    expect(r.warnings[0]).toMatch(/non-empty string/);
  });

  test("empty string key is rejected", () => {
    const path = tmpFile("empty-key.json");
    cleanup(path);
    const projects = new Map([[1, { name: "p1", expectedKey: "any" }]]);
    writeFileSync(path, JSON.stringify({ "1": "" }));
    chmodSync(path, 0o600);

    const { deps } = makeDeps({ filePath: path, projects });
    const r = autoUnsealWithDeps(deps);

    expect(r.unsealed).toEqual([]);
    expect(r.warnings.length).toBe(1);
  });
});

// Use realistic 32-byte base64 keys (44 chars). These are returned by
// generateKeyB64() in production and pass through prepareMasterKey() unchanged,
// so the test's `expectedKey === preparedKey` comparison holds.
const KEY_A = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
const KEY_B = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=";
const KEY_C = "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC=";
const KEY_WRONG = "ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ=";

describe("autoUnsealWithDeps — multi-project scenarios", () => {
  test("multiple projects: full success", () => {
    const path = tmpFile("multi-success.json");
    cleanup(path);
    const projects = new Map([
      [1, { name: "p1", expectedKey: KEY_A }],
      [2, { name: "p2", expectedKey: KEY_B }],
      [3, { name: "p3", expectedKey: KEY_C }],
    ]);
    writeFileSync(path, JSON.stringify({ "1": KEY_A, "2": KEY_B, "3": KEY_C }));
    chmodSync(path, 0o600);

    const { deps, unsealed } = makeDeps({ filePath: path, projects });
    const r = autoUnsealWithDeps(deps);

    expect([...r.unsealed].sort()).toEqual([1, 2, 3]);
    expect(unsealed.size).toBe(3);
    expect(unsealed.get(1)).toBe(KEY_A);
    expect(unsealed.get(2)).toBe(KEY_B);
  });

  test("partial success: one ok, one mismatch, one unknown", () => {
    const path = tmpFile("partial.json");
    cleanup(path);
    const projects = new Map([
      [1, { name: "ok", expectedKey: KEY_A }],
      [2, { name: "wrong", expectedKey: KEY_B }],
      // 9999 absent
    ]);
    writeFileSync(
      path,
      JSON.stringify({ "1": KEY_A, "2": KEY_WRONG, "9999": KEY_C })
    );
    chmodSync(path, 0o600);

    const { deps, unsealed } = makeDeps({ filePath: path, projects });
    const r = autoUnsealWithDeps(deps);

    expect(r.unsealed).toEqual([1]);
    expect(r.hashMismatch).toEqual([2]);
    expect(r.unknownProjects).toEqual([9999]);
    expect(unsealed.size).toBe(1);
    expect(unsealed.get(1)).toBe(KEY_A);
    expect(unsealed.get(2)).toBeUndefined();
  });

  test("plaintext keys are NEVER passed to the logger", () => {
    const path = tmpFile("no-leak.json");
    cleanup(path);
    const projects = new Map([
      [1, { name: "ok", expectedKey: KEY_A }],
      [2, { name: "mismatch-name", expectedKey: KEY_B }],
    ]);
    writeFileSync(path, JSON.stringify({ "1": KEY_A, "2": KEY_WRONG }));
    chmodSync(path, 0o600);

    const { deps, logs } = makeDeps({ filePath: path, projects });
    autoUnsealWithDeps(deps);

    const allLogs = [...logs.info, ...logs.warn, ...logs.error].join("\n");
    expect(allLogs).not.toContain(KEY_A);
    expect(allLogs).not.toContain(KEY_WRONG);
    expect(allLogs).not.toContain(KEY_B);
  });
});

describe("autoUnsealWithDeps — idempotency", () => {
  test("re-running with same file produces same result", () => {
    const path = tmpFile("idempotent.json");
    cleanup(path);
    const projects = new Map([[1, { name: "p1", expectedKey: KEY_A }]]);
    writeFileSync(path, JSON.stringify({ "1": KEY_A }));
    chmodSync(path, 0o600);

    const a = makeDeps({ filePath: path, projects });
    const b = makeDeps({ filePath: path, projects });
    const r1 = autoUnsealWithDeps(a.deps);
    const r2 = autoUnsealWithDeps(b.deps);

    expect(r1.unsealed).toEqual(r2.unsealed);
    expect(r1.hashMismatch).toEqual(r2.hashMismatch);
    expect(a.unsealed.get(1)).toBe(b.unsealed.get(1));
  });
});
