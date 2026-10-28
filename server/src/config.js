import path from 'node:path';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));

export const PORT = Number(process.env.PORT || 4000);
export const DATA_DIR = path.resolve(process.env.DATA_DIR || path.join(here, '..', 'data'));
export const STORAGE_DIR = path.join(DATA_DIR, 'storage');

// Browsers allowed to call the API (the portal web app). Comma-separated.
export const WEB_ORIGINS = (process.env.WEB_ORIGINS
  || 'http://localhost:8082,http://127.0.0.1:8082,http://localhost:8081,http://127.0.0.1:8081')
  .split(',').map((s) => s.trim()).filter(Boolean);

export const SESSION_TTL_MS = 12 * 60 * 60 * 1000;
export const MAX_UPLOAD_BYTES = 500 * 1024 * 1024;

// Client-side key derivation (PBKDF2-SHA256). The server only stores the
// parameters; it never sees passwords or derived encryption keys.
export const MIN_KDF_ITER = 310000;
export const MAX_KDF_ITER = 5000000;
