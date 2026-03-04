import { getDb, type ServiceToken } from "../db";
import { generateKeyB64, hashStringSha256 } from "./encryption";

const TOKEN_SEPARATOR = ":";

export type Right = "read" | "write" | "admin";

const RIGHTS_HIERARCHY: Record<Right, number> = {
  read: 0,
  write: 1,
  admin: 2,
};

export function generateToken(): string {
  return generateKeyB64();
}

export function hashToken(token: string): string {
  return hashStringSha256(token);
}

export function encodePublicToken(
  masterKey: string,
  generatedToken: string
): string {
  return Buffer.from(
    masterKey + TOKEN_SEPARATOR + generatedToken
  ).toString("base64");
}

export function decodePublicToken(
  publicToken: string
): { masterKey: string; generatedToken: string } {
  const decoded = Buffer.from(publicToken, "base64").toString("utf-8");
  const sepIdx = decoded.indexOf(TOKEN_SEPARATOR);
  if (sepIdx === -1) {
    throw new Error("Invalid public service token format");
  }
  return {
    masterKey: decoded.slice(0, sepIdx),
    generatedToken: decoded.slice(sepIdx + 1),
  };
}

export function createServiceToken(
  projectId: number,
  envId: number,
  friendlyName: string,
  rights: Right[]
): { record: ServiceToken; generatedToken: string } {
  const db = getDb();
  const generatedToken = generateToken();
  const tokenHash = hashToken(generatedToken);
  const rightsStr = rights.join(",");

  const stmt = db.prepare<void, [number, number, string, string, string]>(
    `INSERT INTO service_tokens (project_id, environment_id, friendly_name, token_hash, rights)
     VALUES (?, ?, ?, ?, ?)`
  );
  stmt.run(projectId, envId, friendlyName, tokenHash, rightsStr);

  const record = db
    .query<ServiceToken, [string]>(
      "SELECT * FROM service_tokens WHERE token_hash = ?"
    )
    .get(tokenHash)!;

  return { record, generatedToken };
}

export function verifyServiceToken(
  publicToken: string
): { masterKey: string; tokenRecord: ServiceToken } {
  const { masterKey, generatedToken } = decodePublicToken(publicToken);
  const tokenHash = hashToken(generatedToken);

  const db = getDb();
  const tokenRecord = db
    .query<ServiceToken, [string]>(
      "SELECT * FROM service_tokens WHERE token_hash = ?"
    )
    .get(tokenHash);

  if (!tokenRecord) {
    throw new Error("Service token not found");
  }

  return { masterKey, tokenRecord };
}

export function parseRights(rightsStr: string): Right[] {
  return rightsStr.split(",").map((r) => r.trim() as Right);
}

export function rightsInclude(tokenRights: Right[], required: Right): boolean {
  const requiredLevel = RIGHTS_HIERARCHY[required];
  return tokenRights.some((r) => RIGHTS_HIERARCHY[r] >= requiredLevel);
}
