// Creates or replaces the owner login:
//   npm run owner:setup -- <usuario> <contraseña>
import fs from 'node:fs';
import { OWNER_FILE } from '../src/owner.js';
import { hashSecret } from '../src/security.js';

const [username, password] = process.argv.slice(2);
if (!username || !password || password.length < 10) {
  console.error('Uso: npm run owner:setup -- <usuario> <contraseña de al menos 10 caracteres>');
  process.exit(1);
}
const { hash, salt } = hashSecret(password);
fs.writeFileSync(OWNER_FILE, JSON.stringify({ username, hash, salt }, null, 2), { mode: 0o600 });
console.log(`Owner "${username}" configurado en ${OWNER_FILE}`);
process.exit(0);
