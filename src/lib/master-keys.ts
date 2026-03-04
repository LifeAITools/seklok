import { config } from "../config";
import { getDb, type SecretValueHistory } from "../db";
import { generateKeyB64, encrypt, decrypt, isBase64 } from "./encryption";

const KEY_LENGTH = 32;
const KEY_PADDING = "=";

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

  const elapsed = Math.floor(Date.now() / 1000) - entry.setAt;
  if (elapsed > config.masterKeyExpiration) {
    encryptedMasterKeys.delete(String(projectId));
    return null;
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
  const row = db
    .query<SecretValueHistory, [number]>(
      `SELECT svh.* FROM secret_value_histories svh
       JOIN secrets s ON s.id = svh.secret_id
       WHERE s.project_id = ?
       ORDER BY svh.id ASC
       LIMIT 1`
    )
    .get(projectId);

  if (!row) return true;

  try {
    decrypt(masterKey, row.encrypted_value, row.iv_value);
    return true;
  } catch {
    return false;
  }
}

function checkExpiredKeys(): void {
  const now = Math.floor(Date.now() / 1000);
  for (const [projectId, entry] of encryptedMasterKeys) {
    if (now - entry.setAt > config.masterKeyExpiration) {
      encryptedMasterKeys.delete(projectId);
    }
  }
}

const _expirationTimer = setInterval(checkExpiredKeys, 30_000);
export { _expirationTimer };
