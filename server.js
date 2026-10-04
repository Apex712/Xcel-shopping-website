'use strict';

const crypto = require('node:crypto');
const fs = require('node:fs');
const http = require('node:http');
const path = require('node:path');
const { Pool } = require('pg');

const ROOT = __dirname;

function loadLocalEnv() {
  const envPath = path.join(ROOT, '.env');
  if (!fs.existsSync(envPath)) return;

  for (const line of fs.readFileSync(envPath, 'utf8').split(/\r?\n/)) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) continue;
    const separator = trimmed.indexOf('=');
    if (separator < 1) continue;
    const name = trimmed.slice(0, separator).trim().replace(/\s+/g, '_');
    const value = trimmed.slice(separator + 1).trim().replace(/^(['"])(.*)\1$/, '$2');
    if (name && process.env[name] === undefined) process.env[name] = value;
  }
}

loadLocalEnv();

const PORT = Number(process.env.PORT || 8000);
const HOST = process.env.HOST || '127.0.0.1';
const CLIENT_ID = process.env.GOOGLE_CLIENT_ID;
const CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET;
const REDIRECT_URI = process.env.GOOGLE_REDIRECT_URI || `http://localhost:${PORT}/auth/callback`;
const COOKIE_SECURE = REDIRECT_URI.startsWith('https://');
const SESSION_LIFETIME = 12 * 60 * 60 * 1000;
const pendingStates = new Map();
const sessions = new Map();
const databaseUrl = process.env.SUPABASE_CONNECTION_STRING;
const databaseCaPath = path.resolve(ROOT, process.env.SUPABASE_CA_CERT_PATH || 'supabase-ca.crt');
const databaseCa = databaseUrl ? fs.readFileSync(databaseCaPath, 'utf8') : null;
const dbPool = databaseUrl ? new Pool({
  connectionString: databaseUrl,
  ssl: { ca: databaseCa, rejectUnauthorized: true },
  max: 5,
  connectionTimeoutMillis: 10000,
  idleTimeoutMillis: 30000
}) : null;

if (dbPool) dbPool.on('error', () => console.error('Supabase database pool error.'));

function cookieValue(request, name) {
  const cookies = (request.headers.cookie || '').split(';');
  for (const cookie of cookies) {
    const separator = cookie.indexOf('=');
    if (separator < 0) continue;
    if (cookie.slice(0, separator).trim() === name) return decodeURIComponent(cookie.slice(separator + 1).trim());
  }
  return '';
}

function setCookie(response, name, value, maxAge) {
  const attributes = [`${name}=${encodeURIComponent(value)}`, 'Path=/', 'HttpOnly', 'SameSite=Lax', `Max-Age=${maxAge}`];
  if (COOKIE_SECURE) attributes.push('Secure');
  const existing = response.getHeader('Set-Cookie');
  const cookies = existing ? (Array.isArray(existing) ? existing : [existing]) : [];
  response.setHeader('Set-Cookie', [...cookies, attributes.join('; ')]);
}

function clearCookie(response, name) {
  setCookie(response, name, '', 0);
}

function sendJson(response, status, body) {
  response.writeHead(status, {
    'Cache-Control': 'no-store',
    'Content-Type': 'application/json; charset=utf-8',
    'X-Content-Type-Options': 'nosniff'
  });
  response.end(JSON.stringify(body));
}

function redirect(response, location) {
  response.writeHead(303, { Location: location, 'Cache-Control': 'no-store' });
  response.end();
}

function cleanExpiredEntries() {
  const now = Date.now();
  for (const [state, entry] of pendingStates) if (entry.expiresAt <= now) pendingStates.delete(state);
  for (const [sessionId, customer] of sessions) if (customer.expiresAt <= now) sessions.delete(sessionId);
}

function currentCustomer(request) {
  cleanExpiredEntries();
  const sessionId = cookieValue(request, 'xcel_session');
  const customer = sessions.get(sessionId);
  return customer ? { id: customer.id, name: customer.name, email: customer.email, picture: customer.picture } : null;
}

async function saveGoogleUser(profile) {
  if (!dbPool) throw new Error('Supabase is not configured.');

  const client = await dbPool.connect();
  try {
    await client.query('BEGIN');
    await client.query('SELECT pg_advisory_xact_lock(hashtext($1))', [profile.email.toLowerCase()]);
    const existing = await client.query(
      'SELECT id FROM public."USERS DATA" WHERE email = $1 ORDER BY id LIMIT 1',
      [profile.email]
    );

    let user;
    if (existing.rowCount) {
      const result = await client.query(
        'UPDATE public."USERS DATA" SET name = $1 WHERE id = $2 RETURNING id',
        [profile.name || profile.email, existing.rows[0].id]
      );
      user = result.rows[0];
    } else {
      const result = await client.query(
        'INSERT INTO public."USERS DATA" (name, email) VALUES ($1, $2) RETURNING id',
        [profile.name || profile.email, profile.email]
      );
      user = result.rows[0];
    }

    await client.query('COMMIT');
    return user;
  } catch (error) {
    await client.query('ROLLBACK').catch(() => {});
    throw error;
  } finally {
    client.release();
  }
}

async function beginGoogleSignIn(response) {
  if (!CLIENT_ID || !CLIENT_SECRET) return redirect(response, '/?auth_error=configuration');

  const state = crypto.randomBytes(32).toString('base64url');
  pendingStates.set(state, { expiresAt: Date.now() + 10 * 60 * 1000 });
  setCookie(response, 'xcel_oauth_state', state, 600);

  const authorizationUrl = new URL('https://accounts.google.com/o/oauth2/v2/auth');
  authorizationUrl.search = new URLSearchParams({
    client_id: CLIENT_ID,
    redirect_uri: REDIRECT_URI,
    response_type: 'code',
    scope: 'openid email profile',
    state,
    prompt: 'select_account'
  }).toString();
  redirect(response, authorizationUrl.toString());
}

async function finishGoogleSignIn(request, response, url) {
  const state = url.searchParams.get('state') || '';
  const stateCookie = cookieValue(request, 'xcel_oauth_state');
  const savedState = pendingStates.get(state);
  pendingStates.delete(state);
  clearCookie(response, 'xcel_oauth_state');

  if (!state || state !== stateCookie || !savedState || savedState.expiresAt <= Date.now()) {
    return redirect(response, '/?auth_error=google');
  }
  if (url.searchParams.has('error') || !url.searchParams.get('code')) return redirect(response, '/?auth_error=google');

  try {
    const tokenResponse = await fetch('https://oauth2.googleapis.com/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        code: url.searchParams.get('code'),
        client_id: CLIENT_ID,
        client_secret: CLIENT_SECRET,
        redirect_uri: REDIRECT_URI,
        grant_type: 'authorization_code'
      })
    });
    if (!tokenResponse.ok) throw new Error('Token exchange failed');
    const tokens = await tokenResponse.json();
    if (!tokens.access_token) throw new Error('Missing access token');

    const profileResponse = await fetch('https://openidconnect.googleapis.com/v1/userinfo', {
      headers: { Authorization: `Bearer ${tokens.access_token}` }
    });
    if (!profileResponse.ok) throw new Error('Profile request failed');
    const profile = await profileResponse.json();
    if (!profile.sub || !profile.email || profile.email_verified !== true) throw new Error('Google account email is not verified');

    const user = await saveGoogleUser(profile);
    const sessionId = crypto.randomBytes(32).toString('base64url');
    sessions.set(sessionId, {
      id: String(user.id),
      name: profile.name || profile.email,
      email: profile.email,
      picture: profile.picture || '',
      expiresAt: Date.now() + SESSION_LIFETIME
    });
    setCookie(response, 'xcel_session', sessionId, SESSION_LIFETIME / 1000);
    return redirect(response, '/?auth=success');
  } catch {
    return redirect(response, '/?auth_error=google');
  }
}

function serveStorefront(response) {
  fs.readFile(path.join(ROOT, 'index.html'), (error, contents) => {
    if (error) {
      response.writeHead(500, { 'Content-Type': 'text/plain; charset=utf-8' });
      response.end('Storefront could not be loaded.');
      return;
    }
    response.writeHead(200, {
      'Cache-Control': 'no-store',
      'Content-Type': 'text/html; charset=utf-8',
      'Referrer-Policy': 'no-referrer',
      'X-Content-Type-Options': 'nosniff',
      'X-Frame-Options': 'DENY'
    });
    response.end(contents);
  });
}

async function checkDatabase() {
  if (!dbPool) {
    console.error('SUPABASE_CONNECTION_STRING is not set.');
    process.exitCode = 1;
    return;
  }

  try {
    const result = await dbPool.query(
      `SELECT column_name
       FROM information_schema.columns
       WHERE table_schema = $1 AND table_name = $2
       ORDER BY ordinal_position`,
      ['public', 'USERS DATA']
    );
    const columns = result.rows.map(row => row.column_name);
    const missing = ['id', 'name', 'email'].filter(column => !columns.includes(column));
    if (!columns.length || missing.length) throw new Error('Table schema does not match.');

    await dbPool.query('SELECT 1');
    console.log(JSON.stringify({ connected: true, table: 'public."USERS DATA"', columns }, null, 2));
  } catch (error) {
    const reason = error && typeof error === 'object' ? (error.code || error.name || 'unknown') : 'unknown';
    console.error(`Supabase check failed (${reason}). Verify the connection string, table name, and required columns.`);
    process.exitCode = 1;
  } finally {
    await dbPool.end();
  }
}

const server = http.createServer(async (request, response) => {
  let url;
  try {
    url = new URL(request.url, 'http://localhost');
  } catch {
    response.writeHead(400);
    return response.end();
  }

  if (request.method === 'GET' && url.pathname === '/auth/google') return beginGoogleSignIn(response);
  if (request.method === 'GET' && url.pathname === '/auth/callback') return finishGoogleSignIn(request, response, url);
  if (request.method === 'GET' && url.pathname === '/api/session') return sendJson(response, 200, { customer: currentCustomer(request) });
  if (request.method === 'POST' && url.pathname === '/auth/logout') {
    const sessionId = cookieValue(request, 'xcel_session');
    sessions.delete(sessionId);
    clearCookie(response, 'xcel_session');
    response.writeHead(204, { 'Cache-Control': 'no-store' });
    return response.end();
  }
  if (request.method === 'GET' && (url.pathname === '/' || url.pathname === '/index.html')) return serveStorefront(response);

  response.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8', 'X-Content-Type-Options': 'nosniff' });
  response.end('Not found.');
});

server.on('clientError', (_error, socket) => socket.end('HTTP/1.1 400 Bad Request\r\n\r\n'));

if (process.argv.includes('--check-db')) {
  checkDatabase().catch(() => {
    console.error('Supabase check failed. Verify the connection string, table name, and required columns.');
    process.exitCode = 1;
  });
} else {
  server.listen(PORT, HOST, () => console.log(`Xcel storefront listening at http://localhost:${PORT}`));
}