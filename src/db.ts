import { Database } from "bun:sqlite";

export interface Project {
  id: number;
  parent_id: number | null;
  name: string;
  description: string;
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
    CREATE TABLE IF NOT EXISTS projects (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      parent_id INTEGER REFERENCES projects(id),
      name TEXT UNIQUE NOT NULL,
      description TEXT DEFAULT ''
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
  `);

  const insert = database.prepare(
    "INSERT OR IGNORE INTO environments (name) VALUES (?)"
  );
  for (const env of environments) {
    insert.run(env);
  }
}
