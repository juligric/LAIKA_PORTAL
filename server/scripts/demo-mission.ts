// Uploads a demo mission as an operator, exactly like the LAIKA app will:
//   npm run demo:mision -- <usuario> <contraseña> [http://localhost:4000]
// It logs in, unwraps the team key with the operator's password and uploads
// an encrypted mission with a timeline and an image.
import {
  decryptJson, deriveFromPassword, encryptBytes, encryptJson, unwrapKey,
} from '../../web/src/lib/crypto.ts';

const [username, password, apiArg] = process.argv.slice(2);
const API = (apiArg || 'http://localhost:4000').replace(/\/$/, '');
if (!username || !password) {
  console.error('Uso: npm run demo:mision -- <usuario> <contraseña> [url del servidor]');
  process.exit(1);
}

async function call(path: string, init: RequestInit & { token?: string } = {}) {
  const res = await fetch(API + path, {
    ...init,
    headers: { ...(init.headers || {}), ...(init.token ? { Authorization: `Bearer ${init.token}` } : {}) },
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(`${res.status} ${data.error || ''}`);
  return data;
}
const json = (body: unknown) => ({ method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });

const pre = await call('/api/auth/prelogin', json({ kind: 'operator', login: username }));
const { authKey, encKey } = await deriveFromPassword(password, pre.kdfSalt, pre.kdfIter);
const login = await call('/api/auth/login', json({ kind: 'operator', login: username, authKey }));
const teamKey = await unwrapKey(login.operator.wrappedTeamKey, encKey);
const profile = await decryptJson<{ fullName: string }>(login.operator.encProfile, teamKey);
const { name: teamName } = await decryptJson<{ name: string }>(login.team.encName, teamKey);
console.log(`Operador ${profile.fullName} (equipo "${teamName}")`);

const started = new Date(Date.now() - 23 * 60 * 1000);
const mission = await call('/api/missions', { ...json({ encMeta: await encryptJson({ nombre: 'Subiendo…', fecha: started.toISOString() }, teamKey) }), token: login.token });

const svg = `<svg xmlns="http://www.w3.org/2000/svg" width="960" height="540"><rect width="960" height="540" fill="#4a3d36"/>
<rect x="80" y="300" width="800" height="160" fill="#6b5a4a"/><circle cx="700" cy="160" r="70" fill="#E83D3D" opacity="0.6"/>
<text x="80" y="140" font-family="Helvetica" font-weight="700" font-size="54" fill="#F8E3E3">Foto de misión (demo)</text>
<text x="80" y="210" font-family="Helvetica" font-size="28" fill="#E8DADA">${started.toLocaleString('es-AR')}</text></svg>`;
const upload = async (bytes: Uint8Array) => call(`/api/missions/${mission.id}/files`, {
  method: 'POST', headers: { 'Content-Type': 'application/octet-stream' }, body: await encryptBytes(bytes, teamKey) as BodyInit, token: login.token,
});
const photo = await upload(new TextEncoder().encode(svg));

const meta = {
  nombre: `Misión demo ${new Date().toLocaleTimeString('es-AR', { hour: '2-digit', minute: '2-digit' })}`,
  operador: profile.fullName,
  ubicacion: 'Av. Libertador 3344, CABA',
  fecha: started.toISOString(),
  duracion_s: 23 * 60,
  eventos: [
    { t: 0, tipo: 'mision', texto: 'Misión iniciada' },
    { t: 45, tipo: 'camara', texto: 'Cámara: Térmica' },
    { t: 180, tipo: 'hablar', texto: 'Micrófono abierto' },
    { t: 240, tipo: 'foto', texto: 'Foto guardada' },
    { t: 610, tipo: 'postura', texto: 'Postura: Agachado' },
    { t: 1380, tipo: 'mision', texto: 'Misión finalizada' },
  ],
  galeria: [{ fileId: photo.id, tipo: 'captura', mime: 'image/svg+xml', creado_at: new Date(started.getTime() + 240000).toISOString() }],
};
await call(`/api/missions/${mission.id}/meta`, { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ encMeta: await encryptJson(meta, teamKey) }), token: login.token });
console.log(`Misión subida (${mission.id}) con 1 foto cifrada.`);
