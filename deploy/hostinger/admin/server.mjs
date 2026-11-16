#!/usr/bin/env node
/**
 * Admin panel + supervisor for the public God's Eye View deployment.
 *
 * The in-app POWER UP panel only answers the machine running the server, by
 * design (src/keySetupCore.mjs `admitKeySetupRequest`), so it can never work on
 * a public instance behind Traefik. This process is the public replacement:
 *
 *  - it runs the app (scripts/docker-start.mjs) as a child process and
 *    restarts it after a key change, so the new keys load from a clean
 *    environment (an in-process Vite restart keeps the old values);
 *  - it serves a password-protected admin page at /admin on its own port,
 *    which Traefik routes to (see deploy/hostinger/compose.yaml), with two
 *    tabs: every POWER UP key, and every other setting documented in the
 *    app's .env.example (parsed at runtime, so the list follows the app).
 *    Settings the deployment pins (compose environment) and the ones that
 *    decide who can reach the server are shown read-only.
 *
 * Keys are validated and written with the app's own registry and writers
 * (KEY_SETUP_KEYS, validateKeySetupUpdates, upsertDotenvValues), to the same
 * repo-root .env the app loads at boot. The page never shows a key's value,
 * only whether it is set.
 *
 * Security:
 *  - disabled unless GEV_ADMIN_PASSWORD is set (12+ characters); the password
 *    is removed from the app's environment;
 *  - login is rate-limited per client and globally, compared in constant time;
 *  - sessions are random 256-bit tokens in an HttpOnly, Secure,
 *    SameSite=Strict cookie scoped to /admin, expiring after an hour;
 *  - every state-changing request must carry the exact public Origin
 *    (GEV_ADMIN_ORIGIN) and writes additionally require a JSON body;
 *  - strict CSP with no inline script, no framing, no caching.
 */
import { spawn } from 'node:child_process';
import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';
import {
  chmodSync,
  existsSync,
  readFileSync,
  renameSync,
  writeFileSync,
} from 'node:fs';
import { createServer } from 'node:http';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseEnv } from 'node:util';
import {
  KEY_SETUP_KEYS,
  upsertDotenvValues,
  validateKeySetupUpdates,
} from '../../../src/keySetupCore.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const APP_ROOT = path.resolve(HERE, '../../..');
const ENV_FILE = path.join(APP_ROOT, '.env');
const APP_ENTRY = path.join(APP_ROOT, 'scripts/docker-start.mjs');

const PASSWORD = String(process.env.GEV_ADMIN_PASSWORD ?? '');
const PUBLIC_ORIGIN = String(process.env.GEV_ADMIN_ORIGIN ?? '')
  .trim()
  .replace(/\/+$/, '');
const ADMIN_PORT = Number.parseInt(process.env.GEV_ADMIN_PORT ?? '', 10) || 4174;
const ADMIN_ENABLED = PASSWORD.length >= 12 && PUBLIC_ORIGIN !== '';

const SESSION_TTL_MS = 60 * 60 * 1000;
const LOGIN_WINDOW_MS = 15 * 60 * 1000;
const LOGIN_MAX_PER_CLIENT = 5;
const LOGIN_MAX_GLOBAL = 30;
const BODY_LIMIT = 16 * 1024;

// ---------------------------------------------------------------------------
// Supervisor
// ---------------------------------------------------------------------------

/** The app never sees the admin's own settings. */
function appEnv() {
  const env = { ...process.env };
  for (const name of Object.keys(env)) {
    if (name.startsWith('GEV_ADMIN_')) delete env[name];
  }
  return env;
}

let child = null;
let stopping = false;
let restarting = null;

function startApp() {
  child = spawn(process.execPath, [APP_ENTRY], {
    cwd: APP_ROOT,
    env: appEnv(),
    stdio: 'inherit',
  });
  const current = child;
  current.on('exit', (code, signal) => {
    if (child !== current) return;
    child = null;
    if (stopping) process.exit(code ?? 0);
    if (restarting) return;
    console.warn(
      `[Admin] App exited (${signal || code}); starting it again in 2 s.`,
    );
    setTimeout(() => {
      if (!child && !stopping && !restarting) startApp();
    }, 2000);
  });
}

function stopApp() {
  return new Promise((resolve) => {
    const current = child;
    if (!current) return resolve();
    const timer = setTimeout(() => current.kill('SIGKILL'), 10_000);
    current.once('exit', () => {
      clearTimeout(timer);
      resolve();
    });
    current.kill('SIGTERM');
  });
}

/** Restart the app so it reloads .env from scratch. Calls coalesce. */
function restartApp() {
  if (restarting) return restarting;
  restarting = (async () => {
    // Let Vite's own .env watcher settle before the process goes away.
    await new Promise((resolve) => setTimeout(resolve, 500));
    await stopApp();
    child = null;
    restarting = null;
    if (!stopping) startApp();
  })();
  return restarting;
}

for (const signal of ['SIGTERM', 'SIGINT']) {
  process.on(signal, () => {
    stopping = true;
    if (!child) process.exit(0);
    child.kill(signal);
    setTimeout(() => process.exit(0), 10_000).unref();
  });
}

// ---------------------------------------------------------------------------
// Key store
// ---------------------------------------------------------------------------

function readStore() {
  return existsSync(ENV_FILE) ? readFileSync(ENV_FILE, 'utf8') : '';
}

function storeValues() {
  try {
    return parseEnv(readStore());
  } catch {
    return {};
  }
}

function keyStatus() {
  const values = storeValues();
  return KEY_SETUP_KEYS.map((entry) => ({
    id: entry.id,
    title: entry.title,
    unlocks: entry.unlocks,
    getUrl: entry.getUrl,
    tier: entry.tier,
    clientExposed: Boolean(entry.clientExposed),
    vars: entry.envVars.map((name) => ({
      name,
      set: String(values[name] ?? '').trim() !== '',
    })),
  }));
}

// ---------------------------------------------------------------------------
// Settings: every other variable documented in the app's .env.example
// ---------------------------------------------------------------------------

const EXAMPLE_FILE = path.join(APP_ROOT, '.env.example');
const KEY_VARS = new Set(KEY_SETUP_KEYS.flatMap((entry) => entry.envVars));
/** Never editable here: they decide who can reach the server. */
const SECURITY_VARS = new Set([
  'HOST',
  'PORT',
  'GEV_ALLOWED_HOSTS',
  'GEV_KEY_SETUP_TRUSTED_PEERS',
]);
const SECRET_PATTERN = /KEY|TOKEN|SECRET|PASSWORD|CERTIFICATE|CREDENTIAL/;
const SETTING_VALUE_LIMIT = 2048;
const SETTING_GROUPS = [
  ['Rate limits', /^GEV_RATELIMIT_/],
  ['OpenAI voice & chat', /^OPENAI_|^GEV_PREFER_CODEX_OAUTH$|^GEV_VOICE_/],
  ['Gemini', /^GEMINI_/],
  ['Flights', /^OPENSKY_/],
  ['Ships (AIS)', /AIS/],
  ['Traffic', /^TOMTOM_/],
  ['Cameras (CCTV)', /^CCTV_|^ONTARIO_|^OTTAWA_/],
  ['Map search & OpenStreetMap', /^OVERPASS_|^NOMINATIM_|^PHOTON_/],
  ['News', /NEWS|^LIVEUAMAP_/],
  ['Launches', /^LL2_/],
];

const groupOf = (name) =>
  SETTING_GROUPS.find(([, pattern]) => pattern.test(name))?.[0] || 'General';

/**
 * Parse .env.example into [{name, description, default}] in file order. A
 * comment block describes the first variable after it; variables that follow
 * in the same run share that block, so only the first one carries it.
 */
let schemaCache = null;
function settingsSchema() {
  if (schemaCache) return schemaCache;
  const assignment = /^\s*(#\s*)?(?:export\s+)?([A-Z][A-Z0-9_]*)=(.*)$/;
  const seen = new Set();
  const schema = [];
  let prose = [];
  let consumed = false;
  for (const line of readFileSync(EXAMPLE_FILE, 'utf8').split(/\r?\n/)) {
    const match = assignment.exec(line);
    if (match) {
      const [, , name, raw] = match;
      if (!seen.has(name)) {
        seen.add(name);
        const fallback = raw.replace(/\s+#.*$/, '').trim();
        schema.push({
          name,
          description: consumed ? '' : prose.join('\n'),
          default: SECRET_PATTERN.test(name) ? '' : fallback,
        });
      }
      consumed = true;
      continue;
    }
    if (/^\s*#/.test(line)) {
      if (consumed) {
        prose = [];
        consumed = false;
      }
      prose.push(line.replace(/^\s*#\s?/, ''));
    } else if (line.trim() === '') {
      if (consumed) {
        prose = [];
        consumed = false;
      }
    }
  }
  schemaCache = schema.filter(
    (entry) => !KEY_VARS.has(entry.name) && !entry.name.startsWith('GEV_ADMIN_'),
  );
  return schemaCache;
}

/** Set by the deployment (compose) or security-relevant: shown, not editable. */
const lockedSetting = (name) =>
  SECURITY_VARS.has(name) || Object.hasOwn(process.env, name);

function settingsStatus() {
  const values = storeValues();
  const groups = new Map();
  for (const entry of settingsSchema()) {
    const secret = SECRET_PATTERN.test(entry.name);
    const locked = lockedSetting(entry.name);
    const stored = String(values[entry.name] ?? '');
    const effective = locked ? String(process.env[entry.name] ?? '') : stored;
    const group = groupOf(entry.name);
    if (!groups.has(group)) groups.set(group, []);
    groups.get(group).push({
      name: entry.name,
      description: entry.description,
      default: entry.default,
      secret,
      locked,
      set: effective.trim() !== '',
      value: secret ? '' : effective,
    });
  }
  const order = [...SETTING_GROUPS.map(([label]) => label), 'General'];
  return order
    .filter((label) => groups.has(label))
    .map((label) => ({ group: label, vars: groups.get(label) }));
}

/** Validate {NAME: value|null}; null resets the setting to its default. */
function validateSettingUpdates(body) {
  if (!body || typeof body !== 'object' || Array.isArray(body))
    return { ok: false, error: 'Body must be a JSON object' };
  const entries = Object.entries(body);
  if (!entries.length) return { ok: false, error: 'Nothing to save' };
  if (entries.length > 64)
    return { ok: false, error: 'At most 64 settings per save' };
  const known = new Set(settingsSchema().map((entry) => entry.name));
  const updates = {};
  for (const [name, raw] of entries) {
    if (!known.has(name)) return { ok: false, error: `Unknown setting: ${name}` };
    if (lockedSetting(name))
      return { ok: false, error: `${name} is set by the deployment` };
    if (raw === null) {
      updates[name] = null;
      continue;
    }
    if (typeof raw !== 'string')
      return { ok: false, error: `${name} must be text` };
    const value = raw.trim();
    if (!value) {
      updates[name] = null;
      continue;
    }
    if (value.length > SETTING_VALUE_LIMIT)
      return { ok: false, error: `${name} is too long` };
    // Written unquoted to .env, so refuse what dotenv would read back
    // differently: line breaks, comments, expansion, escapes, outer quotes.
    if (/[\x00-\x1f\x7f#$\\`]/.test(value) || /^["']|["']$/.test(value)) {
      return {
        ok: false,
        error: `${name} cannot contain line breaks, #, $, \\, backticks or surrounding quotes`,
      };
    }
    updates[name] = value;
  }
  return { ok: true, updates };
}

function writeStore(updates) {
  const next = upsertDotenvValues(readStore(), updates);
  const temp = `${ENV_FILE}.admin-${process.pid}.tmp`;
  writeFileSync(temp, next, { mode: 0o600 });
  chmodSync(temp, 0o600);
  renameSync(temp, ENV_FILE);
}

// ---------------------------------------------------------------------------
// Sessions and login throttling
// ---------------------------------------------------------------------------

const sessions = new Map(); // token -> expiry (ms)
const attempts = new Map(); // client -> [timestamps]
let globalAttempts = [];

const digest = (value) => createHash('sha256').update(String(value)).digest();
const PASSWORD_DIGEST = digest(PASSWORD);

function passwordMatches(candidate) {
  return timingSafeEqual(digest(candidate), PASSWORD_DIGEST);
}

function parseCookies(header) {
  const cookies = {};
  for (const part of String(header || '').split(';')) {
    const index = part.indexOf('=');
    if (index > 0)
      cookies[part.slice(0, index).trim()] = part.slice(index + 1).trim();
  }
  return cookies;
}

function sessionToken(req) {
  const token = parseCookies(req.headers.cookie).gev_admin;
  if (!token || !/^[A-Za-z0-9_-]{43}$/.test(token)) return null;
  const expiry = sessions.get(token);
  if (!expiry) return null;
  if (expiry < Date.now()) {
    sessions.delete(token);
    return null;
  }
  return token;
}

function newSession() {
  const now = Date.now();
  for (const [token, expiry] of sessions) {
    if (expiry < now) sessions.delete(token);
  }
  const token = randomBytes(32).toString('base64url');
  sessions.set(token, now + SESSION_TTL_MS);
  return token;
}

const cookie = (value, maxAge) =>
  `gev_admin=${value}; Path=/admin; HttpOnly; Secure; SameSite=Strict; Max-Age=${maxAge}`;

/** Traefik appends the real client to X-Forwarded-For; only Traefik reaches this port. */
function clientOf(req) {
  const forwarded = String(req.headers['x-forwarded-for'] || '')
    .split(',')
    .map((entry) => entry.trim())
    .filter(Boolean);
  return forwarded.at(-1) || req.socket.remoteAddress || 'unknown';
}

function loginThrottled(client) {
  const cutoff = Date.now() - LOGIN_WINDOW_MS;
  globalAttempts = globalAttempts.filter((time) => time > cutoff);
  const mine = (attempts.get(client) || []).filter((time) => time > cutoff);
  attempts.set(client, mine);
  return (
    mine.length >= LOGIN_MAX_PER_CLIENT ||
    globalAttempts.length >= LOGIN_MAX_GLOBAL
  );
}

function recordFailedLogin(client) {
  const now = Date.now();
  globalAttempts.push(now);
  attempts.set(client, [...(attempts.get(client) || []), now]);
}

// ---------------------------------------------------------------------------
// HTTP
// ---------------------------------------------------------------------------

const SECURITY_HEADERS = {
  'Content-Security-Policy':
    "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'",
  'X-Frame-Options': 'DENY',
  'X-Content-Type-Options': 'nosniff',
  // Not no-referrer: that makes browsers send `Origin: null` on form posts.
  'Referrer-Policy': 'same-origin',
  'Cache-Control': 'no-store',
  'Strict-Transport-Security': 'max-age=31536000',
};

function send(res, status, type, body, headers = {}) {
  res.writeHead(status, {
    ...SECURITY_HEADERS,
    'Content-Type': type,
    ...headers,
  });
  res.end(body);
}

const sendJson = (res, status, payload, headers) =>
  send(
    res,
    status,
    'application/json; charset=utf-8',
    JSON.stringify(payload),
    headers,
  );

function readBody(req) {
  return new Promise((resolve, reject) => {
    let size = 0;
    const chunks = [];
    req.on('data', (chunk) => {
      size += chunk.length;
      if (size > BODY_LIMIT) {
        reject(Object.assign(new Error('too large'), { status: 413 }));
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    req.on('error', reject);
  });
}

const sameOrigin = (req) => req.headers.origin === PUBLIC_ORIGIN;

const STATIC = {
  '/admin/app.js': ['text/javascript; charset=utf-8', 'app.js'],
  '/admin/app.css': ['text/css; charset=utf-8', 'app.css'],
};

function page(title, body) {
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow">
<title>${title}</title>
<link rel="stylesheet" href="/admin/app.css">
</head>
<body>
${body}
</body>
</html>`;
}

const loginPage = (message = '') =>
  page(
    'GEV Admin',
    `<main class="card narrow">
  <h1>God's Eye View · Admin</h1>
  <p class="muted">Sign in to manage provider keys.</p>
  ${message ? `<p class="error">${message}</p>` : ''}
  <form method="post" action="/admin/login">
    <label for="password">Admin password</label>
    <input id="password" name="password" type="password" autocomplete="current-password" required autofocus>
    <button type="submit">Sign in</button>
  </form>
</main>`,
  );

const panelPage = () =>
  page(
    'GEV Admin',
    `<main class="card">
  <header class="bar">
    <div>
      <h1>God's Eye View · Admin</h1>
      <p class="muted">Saving restarts the globe (about 10 seconds). Every visitor uses these keys, so set quotas and billing alerts with each provider.</p>
    </div>
    <form method="post" action="/admin/logout"><button type="submit" class="ghost">Sign out</button></form>
  </header>
  <nav class="tabs" role="tablist">
    <button type="button" class="tab active" data-tab="keys" role="tab">POWER UP keys</button>
    <button type="button" class="tab" data-tab="settings" role="tab">Settings</button>
  </nav>
  <p id="notice" class="notice" hidden></p>
  <form id="keys" class="pane" data-pane="keys" autocomplete="off">
    <p class="muted">Every provider from the in-app POWER UP panel. Values are never shown; paste a new one to replace it.</p>
    <div id="key-list" class="list"><p class="muted">Loading…</p></div>
    <div class="actions">
      <a href="/" class="ghost button">Open the globe</a>
      <button type="submit">Save keys</button>
    </div>
  </form>
  <form id="settings" class="pane" data-pane="settings" autocomplete="off" hidden>
    <p class="muted">Every other option the app reads from its environment, with the help text from <code>.env.example</code>. Leave a field empty to use the default. Settings marked <em>deployment</em> are fixed in the Docker Manager compose file.</p>
    <input id="filter" type="search" placeholder="Filter settings, e.g. CCTV or rate">
    <div id="setting-list" class="list"><p class="muted">Loading…</p></div>
    <div class="actions">
      <a href="/" class="ghost button">Open the globe</a>
      <button type="submit">Save settings</button>
    </div>
  </form>
</main>
<script src="/admin/app.js"></script>`,
  );

async function handle(req, res) {
  const url = new URL(req.url, 'http://admin.invalid');
  const route = url.pathname.replace(/\/+$/, '') || '/';

  if (STATIC[route] && req.method === 'GET') {
    const [type, file] = STATIC[route];
    return send(res, 200, type, readFileSync(path.join(HERE, file)));
  }

  if (!ADMIN_ENABLED) {
    return send(
      res,
      503,
      'text/plain; charset=utf-8',
      'The admin panel is disabled: set GEV_ADMIN_PASSWORD (12+ characters) and GEV_ADMIN_ORIGIN.',
    );
  }

  if (route === '/admin' && req.method === 'GET') {
    return send(
      res,
      200,
      'text/html; charset=utf-8',
      sessionToken(req) ? panelPage() : loginPage(),
    );
  }

  if (route === '/admin/login' && req.method === 'POST') {
    if (!sameOrigin(req))
      return send(res, 403, 'text/plain; charset=utf-8', 'Bad origin');
    const client = clientOf(req);
    if (loginThrottled(client)) {
      return send(
        res,
        429,
        'text/html; charset=utf-8',
        loginPage('Too many attempts. Try again in 15 minutes.'),
      );
    }
    const body = await readBody(req);
    const password = new URLSearchParams(body).get('password') || '';
    if (!passwordMatches(password)) {
      recordFailedLogin(client);
      console.warn(`[Admin] Failed sign-in from ${client}.`);
      return send(
        res,
        401,
        'text/html; charset=utf-8',
        loginPage('Wrong password.'),
      );
    }
    attempts.delete(client);
    console.log(`[Admin] Signed in from ${client}.`);
    res.writeHead(303, {
      ...SECURITY_HEADERS,
      Location: '/admin',
      'Set-Cookie': cookie(newSession(), SESSION_TTL_MS / 1000),
    });
    return res.end();
  }

  if (route === '/admin/logout' && req.method === 'POST') {
    if (!sameOrigin(req))
      return send(res, 403, 'text/plain; charset=utf-8', 'Bad origin');
    const token = sessionToken(req);
    if (token) sessions.delete(token);
    res.writeHead(303, {
      ...SECURITY_HEADERS,
      Location: '/admin',
      'Set-Cookie': cookie('', 0),
    });
    return res.end();
  }

  if (route.startsWith('/admin/api/')) {
    if (!sessionToken(req))
      return sendJson(res, 401, { error: 'Sign in again.' });

    if (route === '/admin/api/status' && req.method === 'GET') {
      return sendJson(res, 200, {
        keys: keyStatus(),
        settings: settingsStatus(),
        restarting: Boolean(restarting),
      });
    }

    if (
      (route === '/admin/api/keys' || route === '/admin/api/settings') &&
      req.method === 'POST'
    ) {
      if (!sameOrigin(req)) return sendJson(res, 403, { error: 'Bad origin' });
      if (
        !String(req.headers['content-type'] || '').startsWith(
          'application/json',
        )
      ) {
        return sendJson(res, 415, { error: 'JSON required' });
      }
      let body;
      try {
        body = JSON.parse(await readBody(req));
      } catch (error) {
        return sendJson(res, error?.status || 400, { error: 'Invalid JSON' });
      }
      const verdict =
        route === '/admin/api/keys'
          ? validateKeySetupUpdates(body)
          : validateSettingUpdates(body);
      if (!verdict.ok) return sendJson(res, 400, { error: verdict.error });
      try {
        writeStore(verdict.updates);
      } catch (error) {
        console.error('[Admin] Could not write .env:', error?.message);
        return sendJson(res, 500, { error: 'Could not save the keys.' });
      }
      const names = Object.keys(verdict.updates);
      console.log(
        `[Admin] Updated ${names.join(', ')} from ${clientOf(req)}; restarting the app.`,
      );
      restartApp();
      return sendJson(res, 200, {
        ok: true,
        saved: names,
        keys: keyStatus(),
        settings: settingsStatus(),
      });
    }
  }

  return send(res, 404, 'text/plain; charset=utf-8', 'Not found');
}

// ---------------------------------------------------------------------------

startApp();

createServer((req, res) => {
  handle(req, res).catch((error) => {
    console.error('[Admin] Request failed:', error?.message || error);
    if (!res.headersSent)
      send(res, error?.status || 500, 'text/plain; charset=utf-8', 'Error');
    else res.end();
  });
}).listen(ADMIN_PORT, '0.0.0.0', () => {
  console.log(
    ADMIN_ENABLED
      ? `[Admin] Panel at ${PUBLIC_ORIGIN}/admin (port ${ADMIN_PORT}).`
      : '[Admin] Panel disabled: set GEV_ADMIN_PASSWORD (12+ characters) and GEV_ADMIN_ORIGIN.',
  );
});
