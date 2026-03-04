import {
  randomBytes,
  createCipheriv,
  createDecipheriv,
  createHash,
} from "node:crypto";

const KEY_LENGTH = 32;
const ALGORITHM = "aes-256-cbc";

export function generateKeyB64(): string {
  return randomBytes(KEY_LENGTH).toString("base64");
}

export function isBase64(s: string): boolean {
  try {
    if (!s) return false;
    return Buffer.from(s, "base64").toString("base64") === s;
  } catch {
    return false;
  }
}

export function hashStringSha256(input: string): string {
  return createHash("sha256").update(input).digest("hex");
}

export function encrypt(
  keyB64: string,
  plaintext: string
): { cipheredData: string; iv: string } {
  const key = Buffer.from(keyB64, "base64");
  const iv = randomBytes(16);
  const cipher = createCipheriv(ALGORITHM, key, iv);
  const encrypted = Buffer.concat([
    cipher.update(plaintext, "utf8"),
    cipher.final(),
  ]);
  return {
    cipheredData: encrypted.toString("base64"),
    iv: iv.toString("base64"),
  };
}

export function decrypt(
  keyB64: string,
  cipheredDataB64: string,
  ivB64: string
): string {
  const key = Buffer.from(keyB64, "base64");
  const iv = Buffer.from(ivB64, "base64");
  const decipher = createDecipheriv(ALGORITHM, key, iv);
  const decrypted = Buffer.concat([
    decipher.update(Buffer.from(cipheredDataB64, "base64")),
    decipher.final(),
  ]);
  return decrypted.toString("utf8");
}
