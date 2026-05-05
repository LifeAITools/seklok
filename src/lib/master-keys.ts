import { statSync, readFileSync, existsSync } from "node:fs";
import { config } from "../config";
import { getDb, type SecretValueHistory } from "../db";
import { generateKeyB64, encrypt, decrypt, isBase64 } from "./encryption";

const KEY_LENGTH = 32;
const KEY_PADDING = "=";

/**
 * Per-process random key used to encrypt master-keys at rest IN MEMORY.
 * Regenerated on every restart (intentional — provides defence-in-depth against
 * core dumps / process memory dumps reading the Map directly).
 */
const baseKey = generateKeyB64();

interface EncryptedMasterKeyEntry {
  key: { cipheredData: string; iv: string };
  setAt: number;
}

const encryptedMasterKeys = new Map<string, EncryptedMasterKeyEntry>();

export function setMasterKey(projectId: number, masterKey: string): void {
  const encryptedKey = encrypt(baseKey, masterKey);
  encryptedMasterKeys.set(String(projectId), {
    key: encryptedKey,
    setAt: Math.floor(Date.now() / 1000),
  });
}

export function getMasterKey(projectId: number): string | null {
  const entry = encryptedMasterKeys.get(String(projectId));
  if (!entry) return null;

  // Auto-reseal after TTL unless explicitly disabled (single-tenant deployments
  // can opt out by setting MASTER_KEY_DISABLE_AUTO_RESEAL=true).
  if (!config.masterKeyDisableAutoReseal) {
    const elapsed = Math.floor(Date.now() / 1000) - entry.setAt;
    if (elapsed > config.masterKeyExpiration) {
      encryptedMasterKeys.delete(String(projectId));
      return null;
    }
  }

  return decrypt(baseKey, entry.key.cipheredData, entry.key.iv);
}

export function isProjectSealed(projectId: number): boolean {
  return getMasterKey(projectId) === null;
}

export function deleteMasterKey(projectId: number): void {
  encryptedMasterKeys.delete(String(projectId));
}

export function prepareMasterKey(input: string): string {
  if (!isBase64(input) || input.length < KEY_LENGTH) {
    const missing = KEY_LENGTH - input.length;
    if (missing > 0 && missing < KEY_LENGTH) {
      return Buffer.from(
        input + KEY_PADDING.repeat(missing),
        "utf-8"
      ).toString("base64");
    }
  }
  return input;
}

export function validateMasterKey(
  projectId: number,
  masterKey: string
): boolean {
  const db = getDb();

  const project = db
    .query<{ master_key_hash: string | null }, [number]>(
      "SELECT master_key_hash FROM projects WHERE id = ?"
    )
    .get(projectId);

  if (project?.master_key_hash) {
    const hasher = new Bun.CryptoHasher("sha256");
    hasher.update(masterKey);
    return hasher.digest("hex") === project.master_key_hash;
  }

  const row = db
    .query<SecretValueHistory, [number]>(
      `SELECT svh.* FROM secret_value_histories svh
       JOIN secrets s ON s.id = svh.secret_id
       WHERE s.project_id = ?
       ORDER BY svh.id ASC
       LIMIT 1`
    )
    .get(projectId);

  if (!row) return false;

  try {
    decrypt(masterKey, row.encrypted_value, row.iv_value);
    return true;
  } catch {
    return false;
  }
}

function checkExpiredKeys(): void {
  if (config.masterKeyDisableAutoReseal) return;
  const now = Math.floor(Date.now() / 1000);
  for (const [projectId, entry] of encryptedMasterKeys) {
    if (now - entry.setAt > config.masterKeyExpiration) {
      encryptedMasterKeys.delete(projectId);
    }
  }
}

const _expirationTimer = setInterval(checkExpiredKeys, 30_000);
export { _expirationTimer };

// =============================================================================
// Auto-unseal — opt-in startup mechanism
// =============================================================================
//
// Reads a JSON keyfile of the form { "<projectId>": "<masterKey>", ... } and
// unseals each listed project at boot. The feature is disabled by default;
// operators must explicitly set SEKLOK_AUTO_UNSEAL_FILE to enable.
//
// SECURITY MODEL
// --------------
// Auto-unseal trades a security guarantee for ops convenience. By default
// Seklok is sealed-by-default: an attacker who steals the SQLite DB cannot
// decrypt secrets without the master keys, which exist only in admin memory
// after a manual unseal.
//
// Enabling auto-unseal means the keys live on the same host as the DB. An
// attacker with host filesystem access (or a stolen container snapshot that
// includes the keyfile) can decrypt everything. This is acceptable in many
// self-hosted single-tenant deployments — but operators MUST consciously
// choose this trade-off, not accidentally inherit it.
//
// MITIGATIONS BUILT INTO THIS IMPLEMENTATION
// ------------------------------------------
// 1. The keyfile must be mode 0600 or 0400. Wider permissions are refused.
// 2. The keyfile path is operator-supplied and should live OUTSIDE the data
//    directory and OUTSIDE any git-tracked tree (see README).
// 3. Each loaded key is validated against the project's stored
//    master_key_hash before being placed in memory. Stale/wrong keys are
//    skipped with a structured log line, never accepted silently.
// 4. The plaintext key is never logged. Status logs show only project IDs
//    and outcomes (loaded / hash_mismatch / project_missing).
// 5. JSON parse errors and missing files are non-fatal. Auto-unseal failures
//    never prevent the server from starting; operators retain manual unseal
//    via the admin UI / API as the source of truth.

export interface AutoUnsealResult {
  /** Path that was read (or empty if disabled). */
  source: string;
  /** Whether the feature was active for this run. */
  enabled: boolean;
  /** Project IDs successfully unsealed. */
  unsealed: number[];
  /** Project IDs whose key in the file did not match the stored hash. */
  hashMismatch: number[];
  /** Project IDs in the file that do not exist in the DB. */
  unknownProjects: number[];
  /** Non-fatal warnings (mode, parse, etc) for the operator. */
  warnings: string[];
}

/**
 * Dependencies injected into autoUnseal — making them explicit allows the
 * function to be tested without coupling to module-level singletons (the DB
 * connection and the config object).
 */
export interface AutoUnsealDeps {
  /** Path to the JSON keyfile. Empty/undefined disables. */
  filePath: string;
  /** Lookup helper: returns project metadata or null if missing. */
  lookupProject: (id: number) => { id: number; name: string } | null;
  /** Hash validator: true iff `key` matches the stored master_key_hash. */
  validate: (id: number, key: string) => boolean;
  /** Side effect: place an unsealed key into in-memory state. */
  unseal: (id: number, key: string) => void;
  /** Logger (defaults to console; tests inject a spy). */
  logger?: {
    info: (msg: string) => void;
    warn: (msg: string) => void;
    error: (msg: string) => void;
  };
}

/**
 * Read a keyfile and unseal each listed project.
 *
 * Pure with respect to filesystem state: side effects are limited to the
 * injected `unseal()` callback and the injected logger. Returns a structured
 * result that callers may log or surface in /api/v1/status.
 *
 * Idempotent: re-running with the same file on an already-unsealed map simply
 * re-stores the same key.
 */
export function autoUnsealWithDeps(deps: AutoUnsealDeps): AutoUnsealResult {
  const log = deps.logger ?? {
    info: (m: string) => console.log(m),
    warn: (m: string) => console.warn(m),
    error: (m: string) => console.error(m),
  };
  const result: AutoUnsealResult = {
    source: deps.filePath,
    enabled: false,
    unsealed: [],
    hashMismatch: [],
    unknownProjects: [],
    warnings: [],
  };

  if (!deps.filePath) {
    return result; // disabled — nothing to do
  }

  result.enabled = true;
  const path = deps.filePath;

  // 1. File must exist (non-fatal if not — operator may not have provisioned yet)
  if (!existsSync(path)) {
    const msg = `auto-unseal file not found: ${path}`;
    result.warnings.push(msg);
    log.warn(`[seklok][auto-unseal] file not found: ${path} — feature inactive this run`);
    return result;
  }

  // 2. File must be mode 0600 or 0400 (no group/other access). Refuse looser perms.
  let stat;
  try {
    stat = statSync(path);
  } catch (e) {
    const msg = `auto-unseal stat failed: ${(e as Error).message}`;
    result.warnings.push(msg);
    log.warn(`[seklok][auto-unseal] cannot stat ${path}: ${(e as Error).message}`);
    return result;
  }
  const mode = stat.mode & 0o777;
  if ((mode & 0o077) !== 0) {
    const msg =
      `auto-unseal file ${path} has mode ${mode.toString(8).padStart(4, "0")}; ` +
      `required: 0600 or 0400 (no group/other access)`;
    result.warnings.push(msg);
    log.error(`[seklok][auto-unseal] REFUSED: ${msg}`);
    return result;
  }

  // 3. Parse JSON
  let raw: string;
  try {
    raw = readFileSync(path, "utf-8");
  } catch (e) {
    const msg = `auto-unseal read failed: ${(e as Error).message}`;
    result.warnings.push(msg);
    log.error(`[seklok][auto-unseal] read failed for ${path}: ${(e as Error).message}`);
    return result;
  }
  let parsed: Record<string, unknown>;
  try {
    const candidate = JSON.parse(raw);
    if (typeof candidate !== "object" || candidate === null || Array.isArray(candidate)) {
      throw new Error("expected JSON object mapping projectId -> masterKey");
    }
    parsed = candidate as Record<string, unknown>;
  } catch (e) {
    const msg = `auto-unseal parse failed: ${(e as Error).message}`;
    result.warnings.push(msg);
    log.error(`[seklok][auto-unseal] JSON parse failed for ${path}: ${(e as Error).message}`);
    return result;
  }

  // 4. For each entry, validate against stored hash and unseal
  for (const [pidStr, keyVal] of Object.entries(parsed)) {
    const projectId = Number(pidStr);
    if (!Number.isInteger(projectId) || projectId <= 0 || !/^\d+$/.test(pidStr)) {
      result.warnings.push(`invalid projectId key in keyfile: ${pidStr}`);
      log.warn(`[seklok][auto-unseal] skipping invalid project key '${pidStr}'`);
      continue;
    }
    if (typeof keyVal !== "string" || keyVal.length === 0) {
      result.warnings.push(`projectId ${projectId}: master key must be a non-empty string`);
      log.warn(`[seklok][auto-unseal] skipping project ${projectId}: invalid key value`);
      continue;
    }

    const project = deps.lookupProject(projectId);
    if (!project) {
      result.unknownProjects.push(projectId);
      log.warn(`[seklok][auto-unseal] project id=${projectId} not found in DB — skipped`);
      continue;
    }

    const prepared = prepareMasterKey(keyVal);
    if (!deps.validate(projectId, prepared)) {
      result.hashMismatch.push(projectId);
      log.error(
        `[seklok][auto-unseal] HASH MISMATCH for project id=${projectId} (${project.name}) — ` +
          `keyfile contains a stale or wrong key. Skipped. Update keyfile after rotation.`
      );
      continue;
    }

    deps.unseal(projectId, prepared);
    result.unsealed.push(projectId);
    log.info(`[seklok][auto-unseal] unsealed project id=${projectId} (${project.name})`);
  }

  log.info(
    `[seklok][auto-unseal] summary: ${result.unsealed.length} unsealed, ` +
      `${result.hashMismatch.length} hash_mismatch, ` +
      `${result.unknownProjects.length} unknown_project, ` +
      `${result.warnings.length} warnings`
  );
  return result;
}

/**
 * Production entry point: wires autoUnsealWithDeps to live config + DB + the
 * module-level Map. Called once from src/index.tsx after initDb().
 */
export function autoUnseal(): AutoUnsealResult {
  return autoUnsealWithDeps({
    filePath: config.autoUnsealFile,
    lookupProject: (id) => {
      const db = getDb();
      const row = db
        .query<{ id: number; name: string }, [number]>(
          "SELECT id, name FROM projects WHERE id = ?"
        )
        .get(id);
      return row ?? null;
    },
    validate: validateMasterKey,
    unseal: setMasterKey,
  });
}
