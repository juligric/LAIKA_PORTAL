import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { db } from './db.js';
import { DATA_DIR, SESSION_TTL_MS } from './config.js';

// Server-wide secret, generated on first run. Used only to answer login
// pre-checks for unknown accounts with stable fake salts (no user enumeration).
const SECRET_FILE = path.join(DATA_DIR, 'server.secret');
if (!fs.existsSync(SECRET_FILE)) fs.writeFileSync(SECRET_FILE, crypto.randomBytes(32).toString('base64'), { mode: 0o600 });
const SERVER_SECRET = Buffer.from(fs.readFileSync(SECRET_FILE, 'utf8'), 'base64');

export function fakeSalt(login) {
  return crypto.createHmac('sha256', SERVER_SECRET).update(`salt:${login}`).digest().subarray(0, 16).toString('base64');
}

// ── Verifier hashing ──
// Clients send an "auth key" derived from the password (not the password).
// It is hashed again here with scrypt so a stolen database can't be replayed.
const SCRYPT = { N: 1 << 15, r: 8, p: 1, maxmem: 64 * 1024 * 1024 };

export function hashSecret(secret, saltB64 = crypto.randomBytes(16).toString('base64')) {
  const hash = crypto.scryptSync(String(secret), Buffer.from(saltB64, 'base64'), 32, SCRYPT).toString('base64');
  return { hash, salt: saltB64 };
}

export function verifySecret(secret, hashB64, saltB64) {
  const actual = crypto.scryptSync(String(secret), Buffer.from(saltB64, 'base64'), 32, SCRYPT);
  const expected = Buffer.from(hashB64, 'base64');
  return expected.length === actual.length && crypto.timingSafeEqual(actual, expected);
}

// ── Sessions (opaque bearer tokens, stored hashed) ──
const sha256 = (s) => crypto.createHash('sha256').update(s).digest('base64');

export function createSession({ role, companyId = null, operatorId = null }) {
  const token = crypto.randomBytes(32).toString('base64url');
  db.prepare('INSERT INTO sessions (token_hash, role, company_id, operator_id, expires_at) VALUES (?, ?, ?, ?, ?)')
    .run(sha256(token), role, companyId, operatorId, Date.now() + SESSION_TTL_MS);
  return token;
}

export function readSession(token) {
  if (!token) return null;
  const row = db.prepare('SELECT * FROM sessions WHERE token_hash = ?').get(sha256(token));
  if (!row) return null;
  if (row.expires_at < Date.now()) {
    db.prepare('DELETE FROM sessions WHERE token_hash = ?').run(row.token_hash);
    return null;
  }
  return row;
}

export function deleteSession(token) {
  db.prepare('DELETE FROM sessions WHERE token_hash = ?').run(sha256(token));
}

export function deleteSessionsFor({ companyId, operatorId }) {
  if (operatorId) db.prepare('DELETE FROM sessions WHERE operator_id = ?').run(operatorId);
  else if (companyId) db.prepare('DELETE FROM sessions WHERE company_id = ?').run(companyId);
}

setInterval(() => db.prepare('DELETE FROM sessions WHERE expires_at < ?').run(Date.now()), 60 * 60 * 1000).unref();

// ── Brute-force protection: 10 failed attempts per ip+login per 15 min ──
const attempts = new Map();
const WINDOW_MS = 15 * 60 * 1000;
const MAX_FAILS = 10;

export function tooManyAttempts(key) {
  const entry = attempts.get(key);
  if (!entry || entry.resetAt < Date.now()) return false;
  return entry.fails >= MAX_FAILS;
}

export function recordFailure(key) {
  const entry = attempts.get(key);
  if (!entry || entry.resetAt < Date.now()) attempts.set(key, { fails: 1, resetAt: Date.now() + WINDOW_MS });
  else entry.fails += 1;
}

export function clearFailures(key) {
  attempts.delete(key);
}

// ── Invite codes: LAIKA-XXXX-XXXX (no ambiguous characters) ──
const ALPHABET = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
export function newInviteCode() {
  const bytes = crypto.randomBytes(8);
  const chars = [...bytes].map((b) => ALPHABET[b % ALPHABET.length]).join('');
  return `LAIKA-${chars.slice(0, 4)}-${chars.slice(4)}`;
}

export const newId = () => crypto.randomUUID();
