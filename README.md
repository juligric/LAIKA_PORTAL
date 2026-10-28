# LAIKA Portal

Web para empresas que usan LAIKA (desktop) y panel del owner.

- **Empresas** (`/`): el jefe o encargado se registra con un código de acceso, crea equipos de trabajo,
  registra operadores (usuario + contraseña) y ve la carpeta de misiones de cada equipo. Puede borrar operadores
  y equipos (un equipo solo se borra si no tiene operadores asignados) y aprueba o rechaza las solicitudes de acceso.
- **Owner** (`/owner`): lista todas las empresas con su uso (equipos, operadores, misiones, MB),
  ajusta límites (lápiz en cada empresa), deshabilita cuentas y genera códigos de acceso. No puede ver el contenido de las empresas.
- **Operadores** (`/operador`): con su usuario y contraseña ven su equipo y sus misiones, y desde "Mi empresa"
  piden acceso a otros equipos. Si el jefe lo aprueba, ven también las misiones de ese equipo (solo lectura).
  Desde la app LAIKA suben misiones a su equipo (integración pendiente, ver abajo).

## Estructura

```
LAIKA_PORTAL/
  server/   API Node + Express, SQLite integrado (node:sqlite) y archivos cifrados en data/storage
  web/      Expo (React Native Web) con Expo Router; pantallas en web/src/app
```

## Cómo correrlo (Windows, Node 22)

```bash
# 1) Servidor (puerto 4000)
cd server
npm install
npm run owner:setup -- <usuario> <contraseña de 10+ caracteres>   # una sola vez
npm start

# 2) Web (puerto 8082), en otra terminal
cd web
npm install
npm start          # abre http://localhost:8082
```

Owner: http://localhost:8082/owner → generá un código → el jefe lo usa en "Registrar empresa".

Modo prueba: `npm run start:prueba` (en `server`) usa `server/data-prueba` en vez de `server/data`, con su propia
base, archivos y owner (`npm run owner:setup:prueba -- <usuario> <contraseña>`). Para empezar de cero, borrá esa carpeta.

Variables opcionales:
- Servidor: `PORT` (4000), `DATA_DIR` (server/data), `WEB_ORIGINS` (orígenes permitidos, separados por coma).
- Web: `EXPO_PUBLIC_API_URL` (http://localhost:4000).

**Importante:** el cifrado usa Web Crypto, que el navegador solo habilita en `localhost` o en `https://`.
Para usarlo desde otra PC hay que servirlo con HTTPS.

## Seguridad: cifrado de punta a punta

Todo se cifra en el navegador (o en la app) antes de llegar al servidor:

| Clave | Quién la abre | Cifra |
| --- | --- | --- |
| Clave de la empresa | la contraseña del jefe, o su clave de recuperación | claves de equipo, nombre de la empresa y del jefe |
| Clave de equipo | el jefe (vía clave de empresa), los operadores de ese equipo (vía su contraseña) y los operadores con acceso aprobado (vía su clave privada) | nombre del equipo, nombres de operadores, misiones, fotos y videos, y la lista de equipos de la empresa |
| Clave privada del operador (ECDH P-256) | la contraseña del operador | las claves de los equipos que el jefe le compartió |

- Para compartir un equipo, el navegador del jefe cifra la clave de ese equipo con la clave pública del operador;
  el servidor guarda solo el resultado. Si el jefe le cambia la contraseña a un operador, se genera un par de claves
  nuevo y los accesos aprobados se vuelven a cifrar. Los operadores creados antes de esta versión generan su par de
  claves al ingresar por primera vez a `/operador`.
- Cada equipo guarda el nombre de la empresa y la lista de equipos cifrados con su propia clave, para que sus
  operadores sepan a qué equipos pueden pedir acceso. El panel del jefe la mantiene al día cada vez que lo abre.

- Las contraseñas nunca se envían: con PBKDF2-SHA256 (600.000 iteraciones) se derivan una clave de
  login (que el servidor vuelve a hashear con scrypt) y una clave de cifrado que no sale del dispositivo.
- Datos en AES-256-GCM. Clave de recuperación de 160 bits (HKDF), mostrada una sola vez al registrarse.
- En claro el servidor solo tiene lo necesario para operar y facturar: fechas, cantidades, tamaños,
  límites, usuarios de operadores (para el login) y la etiqueta que el owner le pone a cada código.
- **Si el jefe pierde su contraseña y su clave de recuperación, los datos no se pueden recuperar.**
- Límite de 10 intentos fallidos de login cada 15 minutos por usuario e IP.

`data/` contiene la base, los archivos cifrados, `owner.json` y `server.secret`: respaldala y no la subas a git.

## Probar sin la app: misión de demo

Con un operador creado desde el panel:

```bash
cd server
npm run demo:mision -- <usuario-operador> <contraseña>
```

Inicia sesión como ese operador, cifra una misión con línea de tiempo y una foto, y la sube a su equipo.

## API para la app LAIKA (integración pendiente)

1. `POST /api/auth/prelogin` `{ kind: "operator", login }` → `{ kdfSalt, kdfIter }`
2. Derivar con PBKDF2 → `POST /api/auth/login` `{ kind: "operator", login, authKey }`
   → `{ token, operator: { wrappedTeamKey, encProfile, teamId }, team: { encName } }`
3. Abrir la clave de equipo con la clave de cifrado del operador.
4. `POST /api/missions` `{ encMeta }` → `{ id }`
5. Por cada foto/video: `POST /api/missions/:id/files` (cuerpo: bytes cifrados, `application/octet-stream`) → `{ id }`
6. `PUT /api/missions/:id/meta` `{ encMeta }` con la galería apuntando a los ids de archivo.

`web/src/lib/crypto.ts` tiene todas las funciones; `server/scripts/demo-mission.ts` es un ejemplo completo.
El formato de `encMeta` está en `web/src/lib/types.ts` (`MissionMeta`), con los mismos campos que guarda la app.
