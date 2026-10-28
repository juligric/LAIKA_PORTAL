import express from 'express';
import cors from 'cors';
import fs from 'node:fs';
import path from 'node:path';
import { db, tx } from './db.js';
import { MAX_KDF_ITER, MAX_UPLOAD_BYTES, MIN_KDF_ITER, PORT, STORAGE_DIR, WEB_ORIGINS } from './config.js';
import {
  clearFailures, createSession, deleteSession, deleteSessionsFor, fakeSalt, hashSecret,
  newId, newInviteCode, readSession, recordFailure, tooManyAttempts, verifySecret,
} from './security.js';
import { readOwner } from './owner.js';

fs.mkdirSync(STORAGE_DIR, { recursive: true });

const app = express();
app.disable('x-powered-by');
app.use(cors({ origin: WEB_ORIGINS, allowedHeaders: ['Content-Type', 'Authorization'] }));
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('Cache-Control', 'no-store');
  next();
});
app.use(express.json({ limit: '5mb' }));

// ── Helpers ─────────────────────────────────────────────────────────────────

class HttpError extends Error {
  constructor(status, message) { super(message); this.status = status; }
}
const bad = (message) => new HttpError(400, message);

const B64 = /^[A-Za-z0-9+/_=-]+$/;
function str(value, name, { max = 200, min = 1, pattern } = {}) {
  if (typeof value !== 'string' || value.length < min || value.length > max) throw bad(`Campo inválido: ${name}`);
  if (pattern && !pattern.test(value)) throw bad(`Campo inválido: ${name}`);
  return value;
}
const blob = (value, name, max = 4 * 1024 * 1024) => str(value, name, { max, pattern: B64 });
function int(value, name, min, max) {
  const n = Number(value);
  if (!Number.isInteger(n) || n < min || n > max) throw bad(`Campo inválido: ${name}`);
  return n;
}
const normalizeCode = (code) => String(code || '').trim().toUpperCase();
const normalizeUser = (u) => String(u || '').trim().toLowerCase();
const USERNAME = /^[a-z0-9._-]{3,40}$/;

const route = (fn) => (req, res, next) => {
  try {
    const out = fn(req, res);
    if (out && typeof out.then === 'function') out.catch(next);
  } catch (error) {
    next(error);
  }
};

function auth(...roles) {
  return (req, _res, next) => {
    const token = (req.headers.authorization || '').replace(/^Bearer\s+/i, '');
    const session = readSession(token);
    if (!session || !roles.includes(session.role)) return next(new HttpError(401, 'Sesión inválida o vencida'));
    if (session.company_id) {
      const company = db.prepare('SELECT disabled FROM companies WHERE id = ?').get(session.company_id);
      if (!company || company.disabled) return next(new HttpError(403, 'Cuenta deshabilitada'));
      db.prepare('UPDATE companies SET last_activity_at = ? WHERE id = ?').run(Date.now(), session.company_id);
    }
    req.session = session;
    req.token = token;
    next();
  };
}

const bossTeam = (req, teamId) => {
  const team = db.prepare('SELECT * FROM teams WHERE id = ? AND company_id = ?').get(teamId, req.session.company_id);
  if (!team) throw new HttpError(404, 'Equipo no encontrado');
  return team;
};

// A team the session may read: any team of the company for the boss; for an
// operator, their own team or one the boss granted them access to.
const operatorCanSee = (operatorId, teamId) => !!db.prepare(`SELECT 1 FROM operators o WHERE o.id = ? AND (o.team_id = ?
    OR EXISTS (SELECT 1 FROM access_requests r WHERE r.operator_id = o.id AND r.team_id = ? AND r.status = 'approved'))`)
  .get(operatorId, teamId, teamId);

const sessionTeam = (req, teamId) => {
  if (req.session.role === 'boss') return bossTeam(req, teamId);
  if (!operatorCanSee(req.session.operator_id, teamId)) throw new HttpError(404, 'Equipo no encontrado');
  return db.prepare('SELECT * FROM teams WHERE id = ?').get(teamId);
};

// Optional operator key pair sent along with new credentials (both or neither).
function keyPair(body) {
  if (body.publicKey === undefined && body.wrappedPrivateKey === undefined) return null;
  return { publicKey: blob(body.publicKey, 'publicKey', 256), wrappedPrivateKey: blob(body.wrappedPrivateKey, 'wrappedPrivateKey', 1024) };
}

function companyUsage(companyId) {
  const teams = db.prepare('SELECT COUNT(*) n FROM teams WHERE company_id = ?').get(companyId).n;
  const operators = db.prepare('SELECT COUNT(*) n FROM operators WHERE company_id = ?').get(companyId).n;
  const missions = db.prepare('SELECT COUNT(*) n, COALESCE(SUM(LENGTH(enc_meta)), 0) bytes FROM missions WHERE company_id = ?').get(companyId);
  const files = db.prepare('SELECT COALESCE(SUM(size_bytes), 0) bytes FROM mission_files WHERE company_id = ?').get(companyId).bytes;
  return { teams, operators, missions: missions.n, storageBytes: Number(missions.bytes) + Number(files) };
}

const filePath = (companyId, fileId) => path.join(STORAGE_DIR, companyId, `${fileId}.bin`);
function deleteFiles(rows) {
  for (const { id, company_id } of rows) fs.rm(filePath(company_id, id), { force: true }, () => {});
}

const clientKey = (req, login) => `${req.ip}|${login}`;
function checkKdf(body) {
  return { salt: blob(body.kdfSalt, 'kdfSalt', 64), iter: int(body.kdfIter, 'kdfIter', MIN_KDF_ITER, MAX_KDF_ITER) };
}

// ── Public: registration, login, recovery ──────────────────────────────────

// Boss sign-up with an owner-issued invite code. Everything identifying the
// company arrives already encrypted (encProfile) together with the wrapped
// company key; the server just stores it.
app.post('/api/auth/register', route((req, res) => {
  const b = req.body || {};
  const code = normalizeCode(str(b.inviteCode, 'inviteCode', { max: 32 }));
  const { salt, iter } = checkKdf(b);
  const authKey = blob(b.authKey, 'authKey', 128);
  const recoveryAuthKey = blob(b.recoveryAuthKey, 'recoveryAuthKey', 128);
  const wrappedCdkBoss = blob(b.wrappedCdkBoss, 'wrappedCdkBoss', 512);
  const wrappedCdkRecovery = blob(b.wrappedCdkRecovery, 'wrappedCdkRecovery', 512);
  const encProfile = blob(b.encProfile, 'encProfile', 8192);

  if (tooManyAttempts(clientKey(req, 'register'))) throw new HttpError(429, 'Demasiados intentos, probá más tarde');
  const invite = db.prepare('SELECT * FROM invite_codes WHERE code = ?').get(code);
  if (!invite || invite.revoked || invite.used_at) {
    recordFailure(clientKey(req, 'register'));
    throw bad('Código inválido o ya utilizado');
  }

  const bossAuth = hashSecret(authKey);
  const recoveryAuth = hashSecret(recoveryAuthKey);
  const companyId = newId();
  const now = Date.now();
  tx(() => {
    db.prepare(`INSERT INTO companies (id, login_code, label, max_teams, max_operators, created_at, last_activity_at,
      boss_kdf_salt, boss_kdf_iter, boss_auth_hash, boss_auth_salt, wrapped_cdk_boss,
      recovery_auth_hash, recovery_auth_salt, wrapped_cdk_recovery, enc_profile)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
      .run(companyId, code, invite.label, invite.max_teams, invite.max_operators, now, now,
        salt, iter, bossAuth.hash, bossAuth.salt, wrappedCdkBoss,
        recoveryAuth.hash, recoveryAuth.salt, wrappedCdkRecovery, encProfile);
    db.prepare('UPDATE invite_codes SET used_at = ?, company_id = ? WHERE code = ?').run(now, companyId, code);
  });
  res.status(201).json({ ok: true });
}));

// Step 1 of login: KDF parameters for the account. Unknown accounts get a
// stable fake salt so the response doesn't reveal whether they exist.
app.post('/api/auth/prelogin', route((req, res) => {
  const b = req.body || {};
  const kind = b.kind === 'operator' ? 'operator' : 'boss';
  const login = kind === 'boss' ? normalizeCode(b.login) : normalizeUser(b.login);
  const row = kind === 'boss'
    ? db.prepare('SELECT boss_kdf_salt s, boss_kdf_iter i FROM companies WHERE login_code = ?').get(login)
    : db.prepare('SELECT kdf_salt s, kdf_iter i FROM operators WHERE username = ?').get(login);
  res.json(row ? { kdfSalt: row.s, kdfIter: row.i } : { kdfSalt: fakeSalt(`${kind}:${login}`), kdfIter: 600000 });
}));

app.post('/api/auth/login', route((req, res) => {
  const b = req.body || {};
  const kind = b.kind === 'operator' ? 'operator' : 'boss';
  const login = kind === 'boss' ? normalizeCode(b.login) : normalizeUser(b.login);
  const authKey = blob(b.authKey, 'authKey', 128);
  const key = clientKey(req, `${kind}:${login}`);
  if (tooManyAttempts(key)) throw new HttpError(429, 'Demasiados intentos, probá en 15 minutos');
  const fail = () => { recordFailure(key); return new HttpError(401, 'Datos de acceso incorrectos'); };

  if (kind === 'boss') {
    const c = db.prepare('SELECT * FROM companies WHERE login_code = ?').get(login);
    if (!c || !verifySecret(authKey, c.boss_auth_hash, c.boss_auth_salt)) throw fail();
    if (c.disabled) throw new HttpError(403, 'Cuenta deshabilitada. Contactá a LAIKA.');
    clearFailures(key);
    const token = createSession({ role: 'boss', companyId: c.id });
    return res.json({
      token,
      role: 'boss',
      company: { id: c.id, encProfile: c.enc_profile, wrappedCdkBoss: c.wrapped_cdk_boss },
    });
  }

  const op = db.prepare(`SELECT o.*, t.enc_name team_enc_name, c.disabled FROM operators o
    JOIN teams t ON t.id = o.team_id JOIN companies c ON c.id = o.company_id WHERE o.username = ?`).get(login);
  if (!op || !verifySecret(authKey, op.auth_hash, op.auth_salt)) throw fail();
  if (op.disabled) throw new HttpError(403, 'Cuenta deshabilitada');
  clearFailures(key);
  db.prepare('UPDATE operators SET last_login_at = ? WHERE id = ?').run(Date.now(), op.id);
  const token = createSession({ role: 'operator', companyId: op.company_id, operatorId: op.id });
  res.json({
    token,
    role: 'operator',
    operator: {
      id: op.id, username: op.username, teamId: op.team_id, wrappedTeamKey: op.wrapped_team_key, encProfile: op.enc_profile,
      publicKey: op.public_key, wrappedPrivateKey: op.wrapped_private_key,
    },
    team: { id: op.team_id, encName: op.team_enc_name },
  });
}));

app.post('/api/auth/logout', auth('boss', 'operator', 'owner'), route((req, res) => {
  deleteSession(req.token);
  res.json({ ok: true });
}));

// Boss password recovery with the recovery key shown at sign-up.
const resetTokens = new Map(); // token -> { companyId, expiresAt }
app.post('/api/auth/recovery/start', route((req, res) => {
  const b = req.body || {};
  const login = normalizeCode(b.login);
  const recoveryAuthKey = blob(b.recoveryAuthKey, 'recoveryAuthKey', 128);
  const key = clientKey(req, `recovery:${login}`);
  if (tooManyAttempts(key)) throw new HttpError(429, 'Demasiados intentos, probá en 15 minutos');
  const c = db.prepare('SELECT * FROM companies WHERE login_code = ?').get(login);
  if (!c || !verifySecret(recoveryAuthKey, c.recovery_auth_hash, c.recovery_auth_salt)) {
    recordFailure(key);
    throw new HttpError(401, 'Código o clave de recuperación incorrectos');
  }
  clearFailures(key);
  const resetToken = newId();
  resetTokens.set(resetToken, { companyId: c.id, expiresAt: Date.now() + 10 * 60 * 1000 });
  res.json({ resetToken, wrappedCdkRecovery: c.wrapped_cdk_recovery });
}));

app.post('/api/auth/recovery/finish', route((req, res) => {
  const b = req.body || {};
  const entry = resetTokens.get(String(b.resetToken || ''));
  if (!entry || entry.expiresAt < Date.now()) throw new HttpError(401, 'El proceso de recuperación venció, empezá de nuevo');
  const { salt, iter } = checkKdf(b);
  const authKey = blob(b.authKey, 'authKey', 128);
  const wrappedCdkBoss = blob(b.wrappedCdkBoss, 'wrappedCdkBoss', 512);
  const bossAuth = hashSecret(authKey);
  db.prepare(`UPDATE companies SET boss_kdf_salt = ?, boss_kdf_iter = ?, boss_auth_hash = ?, boss_auth_salt = ?, wrapped_cdk_boss = ?
    WHERE id = ?`).run(salt, iter, bossAuth.hash, bossAuth.salt, wrappedCdkBoss, entry.companyId);
  resetTokens.delete(String(b.resetToken));
  deleteSessionsFor({ companyId: entry.companyId });
  res.json({ ok: true });
}));

// ── Boss: company, teams, operators, missions ──────────────────────────────

app.get('/api/company', auth('boss'), route((req, res) => {
  const c = db.prepare('SELECT * FROM companies WHERE id = ?').get(req.session.company_id);
  res.json({
    encProfile: c.enc_profile,
    maxTeams: c.max_teams,
    maxOperators: c.max_operators,
    usage: companyUsage(c.id),
    pendingRequests: db.prepare("SELECT COUNT(*) n FROM access_requests WHERE company_id = ? AND status = 'pending'").get(c.id).n,
  });
}));

app.get('/api/teams', auth('boss'), route((req, res) => {
  const rows = db.prepare(`SELECT t.id, t.enc_name, t.wrapped_team_key, t.created_at, t.enc_directory,
      (SELECT COUNT(*) FROM operators o WHERE o.team_id = t.id) operators,
      (SELECT COUNT(*) FROM missions m WHERE m.team_id = t.id) missions,
      (SELECT MAX(created_at) FROM missions m WHERE m.team_id = t.id) last_mission_at
    FROM teams t WHERE t.company_id = ? ORDER BY t.created_at`).all(req.session.company_id);
  res.json(rows.map((t) => ({
    id: t.id, encName: t.enc_name, wrappedTeamKey: t.wrapped_team_key, createdAt: t.created_at,
    operators: t.operators, missions: t.missions, lastMissionAt: t.last_mission_at, encDirectory: t.enc_directory,
  })));
}));

// The boss's browser keeps each team's encrypted directory up to date.
app.put('/api/teams/directory', auth('boss'), route((req, res) => {
  const items = req.body?.items;
  if (!Array.isArray(items) || items.length > 10000) throw bad('Campo inválido: items');
  const update = db.prepare('UPDATE teams SET enc_directory = ? WHERE id = ? AND company_id = ?');
  tx(() => {
    for (const item of items) update.run(blob(item?.encDirectory, 'encDirectory', 1024 * 1024), str(item?.id, 'id', { max: 64 }), req.session.company_id);
  });
  res.json({ ok: true });
}));

app.post('/api/teams', auth('boss'), route((req, res) => {
  const b = req.body || {};
  const encName = blob(b.encName, 'encName', 4096);
  const wrappedTeamKey = blob(b.wrappedTeamKey, 'wrappedTeamKey', 512);
  const c = db.prepare('SELECT max_teams FROM companies WHERE id = ?').get(req.session.company_id);
  const { teams } = companyUsage(req.session.company_id);
  if (teams >= c.max_teams) throw new HttpError(403, `Tu plan permite hasta ${c.max_teams} equipo(s)`);
  const id = newId();
  db.prepare('INSERT INTO teams (id, company_id, enc_name, wrapped_team_key, created_at) VALUES (?, ?, ?, ?, ?)')
    .run(id, req.session.company_id, encName, wrappedTeamKey, Date.now());
  res.status(201).json({ id });
}));

app.patch('/api/teams/:id', auth('boss'), route((req, res) => {
  bossTeam(req, req.params.id);
  const encName = blob(req.body?.encName, 'encName', 4096);
  db.prepare('UPDATE teams SET enc_name = ? WHERE id = ?').run(encName, req.params.id);
  res.json({ ok: true });
}));

app.delete('/api/teams/:id', auth('boss'), route((req, res) => {
  bossTeam(req, req.params.id);
  const { n } = db.prepare('SELECT COUNT(*) n FROM operators WHERE team_id = ?').get(req.params.id);
  if (n) throw new HttpError(409, `El equipo tiene ${n} operador(es) asignado(s). Eliminalos antes de borrar el equipo.`);
  const files = db.prepare(`SELECT f.id, f.company_id FROM mission_files f JOIN missions m ON m.id = f.mission_id
    WHERE m.team_id = ?`).all(req.params.id);
  db.prepare('DELETE FROM teams WHERE id = ?').run(req.params.id); // cascades missions, file rows and access grants
  deleteFiles(files);
  res.json({ ok: true });
}));

app.get('/api/teams/:id/operators', auth('boss', 'operator'), route((req, res) => {
  sessionTeam(req, req.params.id);
  const rows = db.prepare(`SELECT o.id, o.username, o.enc_profile, o.created_at, o.last_login_at,
      (SELECT COUNT(*) FROM missions m WHERE m.operator_id = o.id) missions
    FROM operators o WHERE o.team_id = ? ORDER BY o.created_at`).all(req.params.id);
  const isBoss = req.session.role === 'boss';
  res.json(rows.map((o) => ({
    id: o.id, username: o.username, encProfile: o.enc_profile, createdAt: o.created_at,
    lastLoginAt: isBoss ? o.last_login_at : null, missions: o.missions,
  })));
}));

// The boss's browser derives the operator's keys from the password it sets,
// wraps the team key for them and sends only the verifier + wrapped key.
app.post('/api/teams/:id/operators', auth('boss'), route((req, res) => {
  const team = bossTeam(req, req.params.id);
  const b = req.body || {};
  const username = normalizeUser(b.username);
  if (!USERNAME.test(username)) throw bad('Usuario inválido: 3 a 40 caracteres, letras, números, punto, guion o guion bajo');
  const { salt, iter } = checkKdf(b);
  const authKey = blob(b.authKey, 'authKey', 128);
  const wrappedTeamKey = blob(b.wrappedTeamKey, 'wrappedTeamKey', 512);
  const encProfile = blob(b.encProfile, 'encProfile', 4096);
  const pair = keyPair(b);
  const c = db.prepare('SELECT max_operators FROM companies WHERE id = ?').get(req.session.company_id);
  const { operators } = companyUsage(req.session.company_id);
  if (operators >= c.max_operators) throw new HttpError(403, `Tu plan permite hasta ${c.max_operators} operador(es)`);
  if (db.prepare('SELECT 1 FROM operators WHERE username = ?').get(username)) throw new HttpError(409, 'Ese usuario ya existe, elegí otro');
  const verifier = hashSecret(authKey);
  const id = newId();
  db.prepare(`INSERT INTO operators (id, company_id, team_id, username, kdf_salt, kdf_iter, auth_hash, auth_salt,
    wrapped_team_key, enc_profile, created_at, public_key, wrapped_private_key) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
    .run(id, req.session.company_id, team.id, username, salt, iter, verifier.hash, verifier.salt, wrappedTeamKey, encProfile, Date.now(),
      pair?.publicKey ?? null, pair?.wrappedPrivateKey ?? null);
  res.status(201).json({ id });
}));

const bossOperator = (req) => {
  const op = db.prepare('SELECT * FROM operators WHERE id = ? AND company_id = ?').get(req.params.id, req.session.company_id);
  if (!op) throw new HttpError(404, 'Operador no encontrado');
  return op;
};

app.put('/api/operators/:id/credentials', auth('boss'), route((req, res) => {
  const op = bossOperator(req);
  const b = req.body || {};
  const { salt, iter } = checkKdf(b);
  const verifier = hashSecret(blob(b.authKey, 'authKey', 128));
  const wrappedTeamKey = blob(b.wrappedTeamKey, 'wrappedTeamKey', 512);
  // The old private key was wrapped with the old password, so it's replaced
  // (or cleared) and every granted team key is re-wrapped for the new public
  // key. Grants the boss didn't re-wrap go back to pending.
  const pair = keyPair(b);
  const rewrapped = new Map((pair && Array.isArray(b.grants) ? b.grants : []).map((g) => [
    str(g?.requestId, 'requestId', { max: 64 }), { wrappedKey: blob(g?.wrappedKey, 'wrappedKey', 512), ephPub: blob(g?.ephPub, 'ephPub', 256) },
  ]));
  tx(() => {
    db.prepare(`UPDATE operators SET kdf_salt = ?, kdf_iter = ?, auth_hash = ?, auth_salt = ?, wrapped_team_key = ?,
      public_key = ?, wrapped_private_key = ? WHERE id = ?`)
      .run(salt, iter, verifier.hash, verifier.salt, wrappedTeamKey, pair?.publicKey ?? null, pair?.wrappedPrivateKey ?? null, op.id);
    const grants = db.prepare("SELECT id FROM access_requests WHERE operator_id = ? AND status = 'approved'").all(op.id);
    for (const { id } of grants) {
      const g = rewrapped.get(id);
      if (g) db.prepare('UPDATE access_requests SET wrapped_key = ?, eph_pub = ? WHERE id = ?').run(g.wrappedKey, g.ephPub, id);
      else db.prepare("UPDATE access_requests SET status = 'pending', wrapped_key = NULL, eph_pub = NULL, decided_at = NULL WHERE id = ?").run(id);
    }
  });
  deleteSessionsFor({ operatorId: op.id });
  res.json({ ok: true });
}));

app.patch('/api/operators/:id', auth('boss'), route((req, res) => {
  const op = bossOperator(req);
  db.prepare('UPDATE operators SET enc_profile = ? WHERE id = ?').run(blob(req.body?.encProfile, 'encProfile', 4096), op.id);
  res.json({ ok: true });
}));

app.delete('/api/operators/:id', auth('boss'), route((req, res) => {
  const op = bossOperator(req);
  deleteSessionsFor({ operatorId: op.id });
  db.prepare('DELETE FROM operators WHERE id = ?').run(op.id); // their missions stay with the team
  res.json({ ok: true });
}));

app.get('/api/teams/:id/missions', auth('boss', 'operator'), route((req, res) => {
  sessionTeam(req, req.params.id);
  const rows = db.prepare(`SELECT m.id, m.operator_id, o.username, m.enc_meta, m.created_at,
      LENGTH(m.enc_meta) + COALESCE((SELECT SUM(size_bytes) FROM mission_files f WHERE f.mission_id = m.id), 0) size_bytes,
      (SELECT COUNT(*) FROM mission_files f WHERE f.mission_id = m.id) files
    FROM missions m LEFT JOIN operators o ON o.id = m.operator_id
    WHERE m.team_id = ? ORDER BY m.created_at DESC`).all(req.params.id);
  res.json(rows.map((m) => ({
    id: m.id, operatorId: m.operator_id, operatorUsername: m.username, encMeta: m.enc_meta,
    createdAt: m.created_at, sizeBytes: m.size_bytes, files: m.files,
  })));
}));

app.delete('/api/missions/:id', auth('boss'), route((req, res) => {
  const m = db.prepare('SELECT id FROM missions WHERE id = ? AND company_id = ?').get(req.params.id, req.session.company_id);
  if (!m) throw new HttpError(404, 'Misión no encontrada');
  const files = db.prepare('SELECT id, company_id FROM mission_files WHERE mission_id = ?').all(m.id);
  db.prepare('DELETE FROM missions WHERE id = ?').run(m.id);
  deleteFiles(files);
  res.json({ ok: true });
}));

// Encrypted file download: the boss of the company, or an operator of the
// team or with granted access to it.
app.get('/api/files/:id', auth('boss', 'operator'), route((req, res) => {
  const f = db.prepare(`SELECT f.id, f.company_id, m.team_id FROM mission_files f JOIN missions m ON m.id = f.mission_id
    WHERE f.id = ? AND f.company_id = ?`).get(req.params.id, req.session.company_id);
  if (!f) throw new HttpError(404, 'Archivo no encontrado');
  if (req.session.role === 'operator' && !operatorCanSee(req.session.operator_id, f.team_id)) throw new HttpError(404, 'Archivo no encontrado');
  res.setHeader('Content-Type', 'application/octet-stream');
  fs.createReadStream(filePath(f.company_id, f.id)).on('error', () => res.status(404).end()).pipe(res);
}));

// ── LAIKA app: upload missions to a team ───────────────────────────────────
// Operators upload to their own team; a boss using the app picks one of the
// company's teams (their missions have no operator_id).

const operatorRow = (req) => db.prepare('SELECT * FROM operators WHERE id = ?').get(req.session.operator_id);

app.post('/api/missions', auth('operator', 'boss'), route((req, res) => {
  const encMeta = blob(req.body?.encMeta, 'encMeta');
  let teamId, operatorId = null;
  if (req.session.role === 'operator') {
    const op = operatorRow(req);
    teamId = op.team_id;
    operatorId = op.id;
  } else {
    teamId = bossTeam(req, str(req.body?.teamId, 'teamId', { max: 64 })).id;
  }
  const id = newId();
  const now = Date.now();
  db.prepare('INSERT INTO missions (id, company_id, team_id, operator_id, enc_meta, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)')
    .run(id, req.session.company_id, teamId, operatorId, encMeta, now, now);
  res.status(201).json({ id });
}));

// A mission can be completed only by whoever created it.
const operatorMission = (req) => {
  const m = req.session.role === 'operator'
    ? db.prepare('SELECT * FROM missions WHERE id = ? AND operator_id = ?').get(req.params.id, req.session.operator_id)
    : db.prepare('SELECT * FROM missions WHERE id = ? AND company_id = ? AND operator_id IS NULL').get(req.params.id, req.session.company_id);
  if (!m) throw new HttpError(404, 'Misión no encontrada');
  return m;
};

app.put('/api/missions/:id/meta', auth('operator', 'boss'), route((req, res) => {
  const m = operatorMission(req);
  db.prepare('UPDATE missions SET enc_meta = ?, updated_at = ? WHERE id = ?').run(blob(req.body?.encMeta, 'encMeta'), Date.now(), m.id);
  res.json({ ok: true });
}));

app.post('/api/missions/:id/files', auth('operator', 'boss'),
  express.raw({ type: 'application/octet-stream', limit: MAX_UPLOAD_BYTES }),
  route((req, res) => {
    const m = operatorMission(req);
    if (!Buffer.isBuffer(req.body) || req.body.length < 28) throw bad('Archivo vacío o inválido');
    const id = newId();
    fs.mkdirSync(path.join(STORAGE_DIR, m.company_id), { recursive: true });
    fs.writeFileSync(filePath(m.company_id, id), req.body);
    db.prepare('INSERT INTO mission_files (id, mission_id, company_id, size_bytes, created_at) VALUES (?, ?, ?, ?, ?)')
      .run(id, m.id, m.company_id, req.body.length, Date.now());
    res.status(201).json({ id });
  }));

// ── Operator portal: own team, granted teams, access requests ─────────────

app.get('/api/me', auth('operator'), route((req, res) => {
  const op = operatorRow(req);
  const team = db.prepare('SELECT id, enc_name, enc_directory FROM teams WHERE id = ?').get(op.team_id);
  const grants = db.prepare(`SELECT r.id, r.team_id, r.wrapped_key, r.eph_pub, t.enc_name FROM access_requests r
    JOIN teams t ON t.id = r.team_id WHERE r.operator_id = ? AND r.status = 'approved' AND r.wrapped_key IS NOT NULL
    ORDER BY t.created_at`).all(op.id);
  const requests = db.prepare('SELECT id, team_id, status, created_at, decided_at FROM access_requests WHERE operator_id = ?').all(op.id);
  res.json({
    team: { id: team.id, encName: team.enc_name, encDirectory: team.enc_directory },
    grants: grants.map((g) => ({ requestId: g.id, teamId: g.team_id, encName: g.enc_name, wrappedKey: g.wrapped_key, ephPub: g.eph_pub })),
    requests: requests.map((r) => ({ id: r.id, teamId: r.team_id, status: r.status, createdAt: r.created_at, decidedAt: r.decided_at })),
  });
}));

// Operators created before key pairs existed make one on their first login.
app.put('/api/me/keypair', auth('operator'), route((req, res) => {
  const pair = keyPair(req.body || {});
  if (!pair) throw bad('Campo inválido: publicKey');
  const r = db.prepare('UPDATE operators SET public_key = ?, wrapped_private_key = ? WHERE id = ? AND public_key IS NULL')
    .run(pair.publicKey, pair.wrappedPrivateKey, req.session.operator_id);
  if (!r.changes) throw new HttpError(409, 'Ya tenés un par de claves');
  res.json({ ok: true });
}));

app.post('/api/access-requests', auth('operator'), route((req, res) => {
  const op = operatorRow(req);
  const teamId = str(req.body?.teamId, 'teamId', { max: 64 });
  if (!db.prepare('SELECT 1 FROM teams WHERE id = ? AND company_id = ?').get(teamId, op.company_id)) throw new HttpError(404, 'Equipo no encontrado');
  if (teamId === op.team_id) throw bad('Ya sos parte de ese equipo');
  if (!op.public_key) throw new HttpError(409, 'Cerrá sesión y volvé a ingresar antes de pedir acceso');
  const existing = db.prepare('SELECT * FROM access_requests WHERE operator_id = ? AND team_id = ?').get(op.id, teamId);
  if (existing?.status === 'pending') throw new HttpError(409, 'Ya hay una solicitud pendiente para ese equipo');
  if (existing?.status === 'approved') throw new HttpError(409, 'Ya tenés acceso a ese equipo');
  const now = Date.now();
  if (existing) {
    db.prepare("UPDATE access_requests SET status = 'pending', created_at = ?, decided_at = NULL WHERE id = ?").run(now, existing.id);
    return res.status(201).json({ id: existing.id });
  }
  const id = newId();
  db.prepare("INSERT INTO access_requests (id, company_id, operator_id, team_id, status, created_at) VALUES (?, ?, ?, ?, 'pending', ?)")
    .run(id, op.company_id, op.id, teamId, now);
  res.status(201).json({ id });
}));

app.get('/api/access-requests', auth('boss'), route((req, res) => {
  const rows = db.prepare(`SELECT r.id, r.team_id, r.status, r.created_at, r.decided_at,
      o.id operator_id, o.username, o.enc_profile, o.team_id operator_team_id, o.public_key
    FROM access_requests r JOIN operators o ON o.id = r.operator_id
    WHERE r.company_id = ? AND r.status IN ('pending', 'approved') ORDER BY r.created_at DESC`).all(req.session.company_id);
  res.json(rows.map((r) => ({
    id: r.id, teamId: r.team_id, status: r.status, createdAt: r.created_at, decidedAt: r.decided_at,
    operator: { id: r.operator_id, username: r.username, encProfile: r.enc_profile, teamId: r.operator_team_id, publicKey: r.public_key },
  })));
}));

const bossRequest = (req) => {
  const r = db.prepare('SELECT * FROM access_requests WHERE id = ? AND company_id = ?').get(req.params.id, req.session.company_id);
  if (!r) throw new HttpError(404, 'Solicitud no encontrada');
  return r;
};

// The boss's browser wraps the team key for the operator's public key.
app.post('/api/access-requests/:id/approve', auth('boss'), route((req, res) => {
  const r = bossRequest(req);
  if (r.status !== 'pending') throw new HttpError(409, 'La solicitud ya fue resuelta');
  const wrappedKey = blob(req.body?.wrappedKey, 'wrappedKey', 512);
  const ephPub = blob(req.body?.ephPub, 'ephPub', 256);
  db.prepare("UPDATE access_requests SET status = 'approved', wrapped_key = ?, eph_pub = ?, decided_at = ? WHERE id = ?")
    .run(wrappedKey, ephPub, Date.now(), r.id);
  res.json({ ok: true });
}));

app.post('/api/access-requests/:id/reject', auth('boss'), route((req, res) => {
  const r = bossRequest(req);
  if (r.status !== 'pending') throw new HttpError(409, 'La solicitud ya fue resuelta');
  db.prepare("UPDATE access_requests SET status = 'rejected', decided_at = ? WHERE id = ?").run(Date.now(), r.id);
  res.json({ ok: true });
}));

// Boss: revoke a granted access. Operator: cancel a request or leave a team.
app.delete('/api/access-requests/:id', auth('boss', 'operator'), route((req, res) => {
  const r = req.session.role === 'boss'
    ? bossRequest(req)
    : db.prepare('SELECT * FROM access_requests WHERE id = ? AND operator_id = ?').get(req.params.id, req.session.operator_id);
  if (!r) throw new HttpError(404, 'Solicitud no encontrada');
  db.prepare('DELETE FROM access_requests WHERE id = ?').run(r.id);
  res.json({ ok: true });
}));

// ── Owner: accounts overview (no content), limits, invite codes ────────────

app.post('/api/owner/login', route((req, res) => {
  const b = req.body || {};
  const key = clientKey(req, 'owner');
  if (tooManyAttempts(key)) throw new HttpError(429, 'Demasiados intentos, probá en 15 minutos');
  const owner = readOwner();
  if (!owner) throw new HttpError(503, 'Owner sin configurar: corré "npm run owner:setup" en el servidor');
  const ok = String(b.username || '') === owner.username && verifySecret(String(b.password || ''), owner.hash, owner.salt);
  if (!ok) { recordFailure(key); throw new HttpError(401, 'Usuario o contraseña incorrectos'); }
  clearFailures(key);
  res.json({ token: createSession({ role: 'owner' }) });
}));

app.get('/api/owner/overview', auth('owner'), route((_req, res) => {
  const companies = db.prepare('SELECT id, label, login_code, max_teams, max_operators, disabled, created_at, last_activity_at FROM companies ORDER BY created_at DESC').all();
  const rows = companies.map((c) => ({
    id: c.id,
    label: c.label,
    code: c.login_code,
    maxTeams: c.max_teams,
    maxOperators: c.max_operators,
    disabled: !!c.disabled,
    createdAt: c.created_at,
    lastActivityAt: c.last_activity_at,
    ...companyUsage(c.id),
  }));
  const totals = rows.reduce((acc, r) => ({
    companies: acc.companies + 1,
    teams: acc.teams + r.teams,
    operators: acc.operators + r.operators,
    missions: acc.missions + r.missions,
    storageBytes: acc.storageBytes + r.storageBytes,
  }), { companies: 0, teams: 0, operators: 0, missions: 0, storageBytes: 0 });
  res.json({ companies: rows, totals });
}));

app.patch('/api/owner/companies/:id', auth('owner'), route((req, res) => {
  const c = db.prepare('SELECT * FROM companies WHERE id = ?').get(req.params.id);
  if (!c) throw new HttpError(404, 'Empresa no encontrada');
  const b = req.body || {};
  const label = b.label !== undefined ? str(b.label, 'label', { max: 80 }) : c.label;
  const maxTeams = b.maxTeams !== undefined ? int(b.maxTeams, 'maxTeams', 0, 10000) : c.max_teams;
  const maxOperators = b.maxOperators !== undefined ? int(b.maxOperators, 'maxOperators', 0, 100000) : c.max_operators;
  const disabled = b.disabled !== undefined ? (b.disabled ? 1 : 0) : c.disabled;
  db.prepare('UPDATE companies SET label = ?, max_teams = ?, max_operators = ?, disabled = ? WHERE id = ?')
    .run(label, maxTeams, maxOperators, disabled, c.id);
  if (disabled) deleteSessionsFor({ companyId: c.id });
  res.json({ ok: true });
}));

app.get('/api/owner/codes', auth('owner'), route((_req, res) => {
  const rows = db.prepare('SELECT * FROM invite_codes ORDER BY created_at DESC').all();
  res.json(rows.map((r) => ({
    code: r.code, label: r.label, maxTeams: r.max_teams, maxOperators: r.max_operators,
    createdAt: r.created_at, usedAt: r.used_at, revoked: !!r.revoked,
  })));
}));

app.post('/api/owner/codes', auth('owner'), route((req, res) => {
  const b = req.body || {};
  const label = str(b.label, 'label', { max: 80 });
  const maxTeams = int(b.maxTeams, 'maxTeams', 1, 10000);
  const maxOperators = int(b.maxOperators, 'maxOperators', 1, 100000);
  let code = newInviteCode();
  while (db.prepare('SELECT 1 FROM invite_codes WHERE code = ?').get(code)) code = newInviteCode();
  db.prepare('INSERT INTO invite_codes (code, label, max_teams, max_operators, created_at) VALUES (?, ?, ?, ?, ?)')
    .run(code, label, maxTeams, maxOperators, Date.now());
  res.status(201).json({ code });
}));

app.delete('/api/owner/codes/:code', auth('owner'), route((req, res) => {
  const r = db.prepare('UPDATE invite_codes SET revoked = 1 WHERE code = ? AND used_at IS NULL').run(normalizeCode(req.params.code));
  if (!r.changes) throw new HttpError(404, 'Código inexistente o ya utilizado');
  res.json({ ok: true });
}));

// ── Errors ──────────────────────────────────────────────────────────────────

app.use((err, _req, res, _next) => {
  if (err?.type === 'entity.too.large') return res.status(413).json({ error: 'Archivo demasiado grande' });
  if (err?.type === 'entity.parse.failed') return res.status(400).json({ error: 'JSON inválido' });
  const status = err instanceof HttpError ? err.status : 500;
  if (status === 500) console.error(err);
  res.status(status).json({ error: status === 500 ? 'Error interno del servidor' : err.message });
});

app.listen(PORT, () => {
  console.log(`LAIKA Portal API en http://localhost:${PORT}`);
  if (!readOwner()) console.log('Aviso: owner sin configurar. Corré "npm run owner:setup -- <usuario> <contraseña>".');
});
