import { Database } from "bun:sqlite";
import { config } from "./config";

export interface Project {
  id: number;
  parent_id: number | null;
  name: string;
  description: string;
  owner_id: string | null;
}

export interface Environment {
  id: number;
  name: string;
}

export interface Secret {
  id: number;
  project_id: number;
  environment_id: number;
  name: string;
  comment: string;
}

export interface SecretValueHistory {
  id: number;
  secret_id: number;
  encrypted_value: string;
  iv_value: string;
  comment: string;
  created_at: string;
  updated_at: string;
}

export interface ServiceToken {
  id: number;
  project_id: number;
  environment_id: number;
  friendly_name: string;
  token_hash: string;
  rights: string;
}

export interface User {
  id: string;
  email: string;
  password_hash: string | null;
  name: string;
  google_id: string | null;
  role: string;
  email_verified: number;
  created_at: string;
  updated_at: string;
}

export interface Session {
  id: string;
  user_id: string;
  token_hash: string;
  expires_at: number;
  created_at: string;
}

export interface VerificationToken {
  id: string;
  user_id: string;
  token_hash: string;
  expires_at: number;
  created_at: string;
}

let db: Database | null = null;

export function getDb(): Database {
  if (!db) {
    const dbPath = process.env.DB_PATH || "./data/seklok.db";
    db = new Database(dbPath, { create: true });
    db.exec("PRAGMA journal_mode = WAL");
    db.exec("PRAGMA foreign_keys = ON");
  }
  return db;
}

export function initDb(environments: string[]): void {
  const database = getDb();

  database.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY,
      email TEXT UNIQUE NOT NULL,
      password_hash TEXT,
      name TEXT NOT NULL,
      google_id TEXT UNIQUE,
      role TEXT NOT NULL DEFAULT 'user' CHECK(role IN ('user', 'admin')),
      email_verified INTEGER NOT NULL DEFAULT 0,
      created_at TEXT NOT NULL DEFAULT (datetime('now')),
      updated_at TEXT NOT NULL DEFAULT (datetime('now'))
    );

    CREATE TABLE IF NOT EXISTS sessions (
      id TEXT PRIMARY KEY,
      user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      token_hash TEXT NOT NULL,
      expires_at INTEGER NOT NULL,
      created_at TEXT NOT NULL DEFAULT (datetime('now'))
    );

    CREATE TABLE IF NOT EXISTS verification_tokens (
      id TEXT PRIMARY KEY,
      user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      token_hash TEXT NOT NULL,
      expires_at INTEGER NOT NULL,
      created_at TEXT NOT NULL DEFAULT (datetime('now'))
    );

    CREATE TABLE IF NOT EXISTS projects (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      parent_id INTEGER REFERENCES projects(id),
      name TEXT UNIQUE NOT NULL,
      description TEXT DEFAULT '',
      owner_id TEXT REFERENCES users(id),
      master_key_hash TEXT
    );

    CREATE TABLE IF NOT EXISTS environments (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT UNIQUE NOT NULL
    );

    CREATE TABLE IF NOT EXISTS secrets (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      project_id INTEGER NOT NULL REFERENCES projects(id),
      environment_id INTEGER NOT NULL REFERENCES environments(id),
      name TEXT NOT NULL,
      comment TEXT DEFAULT ''
    );
    CREATE INDEX IF NOT EXISTS idx_secrets_proj_env ON secrets(project_id, environment_id);

    CREATE TABLE IF NOT EXISTS secret_value_histories (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      secret_id INTEGER NOT NULL REFERENCES secrets(id) ON DELETE CASCADE,
      encrypted_value TEXT NOT NULL,
      iv_value TEXT NOT NULL,
      comment TEXT DEFAULT '',
      created_at TEXT NOT NULL DEFAULT (datetime('now')),
      updated_at TEXT NOT NULL DEFAULT (datetime('now'))
    );
    CREATE INDEX IF NOT EXISTS idx_svh_secret ON secret_value_histories(secret_id);

    CREATE TABLE IF NOT EXISTS service_tokens (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      project_id INTEGER NOT NULL REFERENCES projects(id),
      environment_id INTEGER NOT NULL REFERENCES environments(id),
      friendly_name TEXT DEFAULT '',
      token_hash TEXT NOT NULL,
      rights TEXT NOT NULL DEFAULT 'read'
    );
    CREATE INDEX IF NOT EXISTS idx_st_proj_env ON service_tokens(project_id, environment_id);
    CREATE INDEX IF NOT EXISTS idx_st_hash ON service_tokens(token_hash);

    CREATE INDEX IF NOT EXISTS idx_users_google_id ON users(google_id);
    CREATE INDEX IF NOT EXISTS idx_sessions_token_hash ON sessions(token_hash);
    CREATE INDEX IF NOT EXISTS idx_verification_tokens_token_hash ON verification_tokens(token_hash);
  `);

  // Add owner_id column to existing projects table if missing
  const cols = database.prepare("PRAGMA table_info(projects)").all() as { name: string }[];
  if (!cols.some((col) => col.name === "owner_id")) {
    database.exec("ALTER TABLE projects ADD COLUMN owner_id TEXT REFERENCES users(id)");
  }
  if (!cols.some((col) => col.name === "master_key_hash")) {
    database.exec("ALTER TABLE projects ADD COLUMN master_key_hash TEXT");
  }

  const insert = database.prepare(
    "INSERT OR IGNORE INTO environments (name) VALUES (?)"
  );
  for (const env of environments) {
    insert.run(env);
  }

  seedAdmin(database);
}

async function seedAdmin(database: Database): Promise<void> {
  const existing = database
    .query("SELECT id FROM users WHERE role = 'admin' LIMIT 1")
    .get() as { id: string } | null;

  if (existing) return;

  if (!config.adminUser || !config.adminPass) return;

  const adminId = crypto.randomUUID();
  const passwordHash = await Bun.password.hash(config.adminPass, {
    algorithm: "argon2id",
  });

  database
    .prepare(
      "INSERT INTO users (id, email, password_hash, name, role, email_verified) VALUES (?, ?, ?, ?, 'admin', 1)"
    )
    .run(adminId, config.adminUser, passwordHash, config.adminUser);

  database
    .prepare("UPDATE projects SET owner_id = ? WHERE owner_id IS NULL")
    .run(adminId);

  console.log(`[seklok] Seeded admin user: ${config.adminUser}`);
}

export { seedAdmin };
