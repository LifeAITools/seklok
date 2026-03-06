import type { MiddlewareHandler } from "hono";
import { getCookie, setCookie } from "hono/cookie";
import { getDb } from "../db";
import { config } from "../config";

export interface AuthUser {
  id: string;
  email: string;
  name: string;
  role: string;
  emailVerified: boolean;
}

function hashToken(token: string): string {
  const hasher = new Bun.CryptoHasher("sha256");
  hasher.update(token);
  return hasher.digest("hex");
}

function lookupSession(tokenHash: string): AuthUser | null {
  const db = getDb();
  const now = Math.floor(Date.now() / 1000);
  const row = db
    .query(
      `SELECT s.id, u.id as uid, u.email, u.name, u.role, u.email_verified
       FROM sessions s
       JOIN users u ON s.user_id = u.id
       WHERE s.token_hash = ? AND s.expires_at > ?`
    )
    .get(tokenHash, now) as {
    uid: string;
    email: string;
    name: string;
    role: string;
    email_verified: number;
  } | null;

  if (!row) return null;

  return {
    id: row.uid,
    email: row.email,
    name: row.name,
    role: row.role,
    emailVerified: row.email_verified === 1,
  };
}

export const requireAuth: MiddlewareHandler = async (c, next) => {
  // If user already set by upstream middleware (e.g. sessionOrBasicAuth), skip
  const existing = c.get("user") as AuthUser | undefined;
  if (existing) return next();

  const sessionCookie = getCookie(c, "seklok_session");
  if (!sessionCookie) {
    return c.redirect("/auth/login");
  }

  const tokenHash = hashToken(sessionCookie);
  const user = lookupSession(tokenHash);
  if (!user) {
    return c.redirect("/auth/login");
  }

  c.set("user", user);
  return next();
};

export const optionalAuth: MiddlewareHandler = async (c, next) => {
  const sessionCookie = getCookie(c, "seklok_session");
  if (sessionCookie) {
    const tokenHash = hashToken(sessionCookie);
    const user = lookupSession(tokenHash);
    if (user) {
      c.set("user", user);
    }
  }
  return next();
};

export function createSession(userId: string): string {
  const db = getDb();
  const rawToken = crypto.randomUUID();
  const tokenHash = hashToken(rawToken);
  const sessionId = crypto.randomUUID();
  const expiresAt = Math.floor(Date.now() / 1000) + config.sessionTtl;

  db.prepare(
    "INSERT INTO sessions (id, user_id, token_hash, expires_at) VALUES (?, ?, ?, ?)"
  ).run(sessionId, userId, tokenHash, expiresAt);

  return rawToken;
}

export function setSessionCookie(c: any, token: string): void {
  setCookie(c, "seklok_session", token, {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "Lax",
    maxAge: config.sessionTtl,
    path: "/",
  });
}
