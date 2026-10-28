import { DatabaseSync } from 'node:sqlite';
import fs from 'node:fs';
import path from 'node:path';
import { DATA_DIR } from './config.js';

// Everything a company owns is end-to-end encrypted by the browser/app before
// it reaches this server: columns named enc_* / wrapped_* are opaque blobs.
// Plaintext is limited to what's needed to operate and to bill:
// ids, dates, counts, sizes, limits, operator usernames (for login) and the
// owner's own label for each account.

fs.mkdirSync(DATA_DIR, { recursive: true });
export const db = new DatabaseSync(path.join(DATA_DIR, 'laika.db'));

db.exec(`
  PRAGMA journal_mode = WAL;
  PRAGMA foreign_keys = ON;

  CREATE TABLE IF NOT EXISTS invite_codes (
    code TEXT PRIMARY KEY,
    label TEXT NOT NULL,
    max_teams INTEGER NOT NULL,
    max_operators INTEGER NOT NULL,
    created_at INTEGER NOT NULL,
    used_at INTEGER,
    company_id TEXT,
    revoked INTEGER NOT NULL DEFAULT 0
  );

  CREATE TABLE IF NOT EXISTS companies (
    id TEXT PRIMARY KEY,
    login_code TEXT NOT NULL UNIQUE,
    label TEXT NOT NULL,
    max_teams INTEGER NOT NULL,
    max_operators INTEGER NOT NULL,
    disabled INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL,
    last_activity_at INTEGER,
    boss_kdf_salt TEXT NOT NULL,
    boss_kdf_iter INTEGER NOT NULL,
    boss_auth_hash TEXT NOT NULL,
    boss_auth_salt TEXT NOT NULL,
    wrapped_cdk_boss TEXT NOT NULL,
    recovery_auth_hash TEXT NOT NULL,
    recovery_auth_salt TEXT NOT NULL,
    wrapped_cdk_recovery TEXT NOT NULL,
    enc_profile TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS teams (
    id TEXT PRIMARY KEY,
    company_id TEXT NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
    enc_name TEXT NOT NULL,
    wrapped_team_key TEXT NOT NULL,
    created_at INTEGER NOT NULL
  );

  CREATE TABLE IF NOT EXISTS operators (
    id TEXT PRIMARY KEY,
    company_id TEXT NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
    team_id TEXT NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
    username TEXT NOT NULL UNIQUE,
    kdf_salt TEXT NOT NULL,
    kdf_iter INTEGER NOT NULL,
    auth_hash TEXT NOT NULL,
    auth_salt TEXT NOT NULL,
    wrapped_team_key TEXT NOT NULL,
    enc_profile TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    last_login_at INTEGER
  );

  CREATE TABLE IF NOT EXISTS missions (
    id TEXT PRIMARY KEY,
    company_id TEXT NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
    team_id TEXT NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
    operator_id TEXT REFERENCES operators(id) ON DELETE SET NULL,
    enc_meta TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
  );

  CREATE TABLE IF NOT EXISTS mission_files (
    id TEXT PRIMARY KEY,
    mission_id TEXT NOT NULL REFERENCES missions(id) ON DELETE CASCADE,
    company_id TEXT NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
    size_bytes INTEGER NOT NULL,
    created_at INTEGER NOT NULL
  );

  CREATE TABLE IF NOT EXISTS sessions (
    token_hash TEXT PRIMARY KEY,
    role TEXT NOT NULL,
    company_id TEXT,
    operator_id TEXT,
    expires_at INTEGER NOT NULL
  );

  -- An operator asking the boss to see another team of the company. Once
  -- approved, wrapped_key holds that team's key wrapped for the operator's
  -- public key (ECDH with the ephemeral eph_pub).
  CREATE TABLE IF NOT EXISTS access_requests (
    id TEXT PRIMARY KEY,
    company_id TEXT NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
    operator_id TEXT NOT NULL REFERENCES operators(id) ON DELETE CASCADE,
    team_id TEXT NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
    status TEXT NOT NULL,
    wrapped_key TEXT,
    eph_pub TEXT,
    created_at INTEGER NOT NULL,
    decided_at INTEGER,
    UNIQUE (operator_id, team_id)
  );

  CREATE INDEX IF NOT EXISTS idx_teams_company ON teams(company_id);
  CREATE INDEX IF NOT EXISTS idx_requests_company ON access_requests(company_id, status);
  CREATE INDEX IF NOT EXISTS idx_operators_team ON operators(team_id);
  CREATE INDEX IF NOT EXISTS idx_missions_team ON missions(team_id, created_at);
  CREATE INDEX IF NOT EXISTS idx_files_mission ON mission_files(mission_id);
`);

// Columns added after the first release (CREATE TABLE IF NOT EXISTS won't add them).
function addColumn(table, column, type) {
  const exists = db.prepare(`PRAGMA table_info(${table})`).all().some((c) => c.name === column);
  if (!exists) db.exec(`ALTER TABLE ${table} ADD COLUMN ${column} ${type}`);
}
// Operator key pair: the private key is wrapped with the operator's password key.
addColumn('operators', 'public_key', 'TEXT');
addColumn('operators', 'wrapped_private_key', 'TEXT');
// Company name + list of team names, encrypted with this team's key, so the
// team's operators can see which teams they may ask access to.
addColumn('teams', 'enc_directory', 'TEXT');

/** Run fn inside a transaction (node:sqlite has no helper for it). */
export function tx(fn) {
  db.exec('BEGIN');
  try {
    const result = fn();
    db.exec('COMMIT');
    return result;
  } catch (error) {
    db.exec('ROLLBACK');
    throw error;
  }
}
