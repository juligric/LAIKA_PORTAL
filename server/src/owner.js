import fs from 'node:fs';
import path from 'node:path';
import { DATA_DIR } from './config.js';

// The owner account lives outside the database, in data/owner.json, and is
// created with `npm run owner:setup -- <usuario> <contraseña>`.
export const OWNER_FILE = path.join(DATA_DIR, 'owner.json');

export function readOwner() {
  try {
    return JSON.parse(fs.readFileSync(OWNER_FILE, 'utf8'));
  } catch {
    return null;
  }
}
