/**
 * Gateway — Zero Trust Auth + Cerbos ABAC
 * Port: 3001
 */

'use strict';

const express  = require('express');
const fetch    = require('node-fetch');
const { randomUUID } = require('crypto');
const { createProxyMiddleware } = require('http-proxy-middleware');

const app = express();

// ─── Config ───────────────────────────────────────────────────────────────
const CERBOS_URL      = 'http://171.244.143.144:3592/api/check/resources';
const OAUTH2_AUTH_URL = 'http://127.0.0.1:4180/oauth2/auth';
const RESOURCE_APP    = 'http://127.0.0.1:3000/resources';
const PRIVATE_APP     = 'http://171.237.178.61:4000';

// Các group được phép vào /app/
const APP_ALLOWED_GROUPS = new Set([
  'private-access',
  'admin',
  'administrator',
  'adminitrator',
  'adminitrators',
  'manager',
  'contributor',
]);

// Static file extensions — bỏ qua Cerbos check
const STATIC_EXTS = new Set([
  '.js', '.css', '.png', '.ico', '.woff', '.woff2',
  '.ttf', '.map', '.svg', '.jpg', '.jpeg', '.gif', '.webp', '.html'
]);

// ─── Helper: chuẩn hoá path — bỏ prefix /app nếu có ─────────────────────
// x-original-uri có thể là /app/api/... hoặc /api/... tuỳ điểm gọi
function normalizePath(req) {
  const uri  = req.headers['x-original-uri'] || req.url;
  const path = uri.split('?')[0];
  // Bỏ prefix /app để getAction/getResource luôn nhận path chuẩn
  return path.replace(/^\/app/, '');
}

// ─── Action mapping ───────────────────────────────────────────────────────
function getAction(req) {
  const path   = normalizePath(req);
  const method = req.method.toUpperCase();

  // ── /resources/ ──────────────────────────────────────────────────────
  if (/^\/resources\/api\/documents\/\d+\/download$/.test(path)) return 'download';
  if (/^\/resources\/api\/documents(\/\d+)?$/.test(path)) {
    if (method === 'GET')    return 'read';
    if (method === 'POST')   return 'upload';
    if (method === 'DELETE') return 'delete';
  }
  if (path.startsWith('/resources/api/')) return 'read';

  // ── /app/ ─────────────────────────────────────────────────────────────
  if (/^\/api\/projects(\/\d+)?$/.test(path)) {
    if (method === 'GET')    return 'read';
    if (method === 'POST')   return 'create_project';
    if (method === 'DELETE') return 'delete';
  }
  if (/^\/api\/tasks(\/\d+)?$/.test(path)) {
    if (method === 'GET')    return 'read';
    if (method === 'POST')   return 'create_task';
    if (method === 'PATCH')  return 'update';
    if (method === 'DELETE') return 'delete';
  }
  if (path === '/api/logs') return 'read_logs';

  // FIX: admin trước, rồi mới prefix chung — cả 2 đều đã strip /app rồi
  if (path === '/api/private-data/admin')      return 'read_admin';
  if (path.startsWith('/api/private-data'))    return 'read_private';

  // Fallback
  const fallback = { GET: 'read', POST: 'write', PATCH: 'update', PUT: 'update', DELETE: 'delete' };
  return fallback[method] || 'read';
}

// ─── Resource mapping ─────────────────────────────────────────────────────
function getResource(req) {
  const path = normalizePath(req);

  // /resources/
  if (/^\/resources\/api\/documents(\/|$)/.test(path)) return { kind: 'document',      id: 'shared'  };
  if (path.startsWith('/resources/api/'))               return { kind: 'resource_api',  id: 'default' };
  if (path.startsWith('/resources'))                    return { kind: 'resource_page', id: 'default' };

  // /app/
  if (/^\/api\/projects(\/|$)/.test(path))             return { kind: 'project',      id: 'default' };
  if (/^\/api\/tasks(\/|$)/.test(path))                return { kind: 'task',         id: 'default' };
  if (path === '/api/logs')                             return { kind: 'logs',         id: 'audit'   };

  // FIX: admin trước
  if (path === '/api/private-data/admin')               return { kind: 'private_data', id: 'admin'   };
  if (path.includes('/api/private-data'))               return { kind: 'private_data', id: 'default' };

  return { kind: 'application', id: 'default' };
}

// ─── Context builder ──────────────────────────────────────────────────────
function buildContext(req, groups, email) {
  return {
    groups,
    ip:         req.headers['x-forwarded-for'] || req.socket.remoteAddress,
    hour:       new Date().getHours(),
    method:     req.method,
    path:       normalizePath(req),
    user_agent: req.headers['user-agent'] || '',
    email
  };
}

// ─── Audit log ────────────────────────────────────────────────────────────
function auditLog({ user, email, path, action, resource, decision, ip }) {
  console.log(JSON.stringify({
    ts: new Date().toISOString(),
    source: 'gateway',
    user, email, ip, path, action, resource, decision
  }));
}

// ─── Core check: OAuth2 + Cerbos ─────────────────────────────────────────
async function check(req) {
  const oauthRes = await fetch(OAUTH2_AUTH_URL, {
    headers: { Cookie: req.headers.cookie || '' }
  });

  if (oauthRes.status === 401) return { status: 401 };

  const user      = oauthRes.headers.get('x-auth-request-user')   || '';
  const email     = oauthRes.headers.get('x-auth-request-email')  || '';
  const groupsRaw = oauthRes.headers.get('x-auth-request-groups') || '';
  const groupList = groupsRaw.split(',').map(g => g.trim()).filter(Boolean);

  const action   = getAction(req);
  const resource = getResource(req);
  const context  = buildContext(req, groupList, email);

  const body = {
    requestId: randomUUID(),
    principal: {
      id:    user || 'anonymous',
      roles: groupList.length ? groupList : ['anonymous'],
      attr:  context
    },
    resources: [{ resource, actions: [action] }]
  };

  const cerbosRes = await fetch(CERBOS_URL, {
    method:  'POST',
    headers: { 'Content-Type': 'application/json' },
    body:    JSON.stringify(body)
  });

  const data = await cerbosRes.json();

  if (!data?.results?.[0]?.actions?.[action]) {
    console.error('[gateway] Cerbos unexpected response:', JSON.stringify(data));
    return { status: 403, user, email, groups: groupsRaw };
  }

  const decision = data.results[0].actions[action];
  const allowed  = decision === 'EFFECT_ALLOW';

  auditLog({
    user, email,
    ip:       req.headers['x-forwarded-for'] || req.socket.remoteAddress,
    path:     normalizePath(req),
    action, resource,
    decision: allowed ? 'ALLOW' : 'DENY'
  });
  console.log('[DEBUG] user:', user, 'email:', email, 'groups:', groupList);
  return { status: allowed ? 200 : 403, user, email, groups: groupsRaw };
}

// ─── Helper: static asset ────────────────────────────────────────────────
function isStaticAsset(url) {
  const clean = url.split('?')[0];
  const ext   = clean.match(/\.[a-z0-9]+$/i)?.[0]?.toLowerCase();
  return ext ? STATIC_EXTS.has(ext) : false;
}

// ─── Helper: group guard cho /app ────────────────────────────────────────
function hasAppAccess(groupList) {
  return groupList.some(g => APP_ALLOWED_GROUPS.has(g.toLowerCase()));
}

// =========================================================================
// ROUTE: /authz — nginx auth_request internal cho /app/
// =========================================================================
app.all('/authz', async (req, res) => {
  try {
    const oauthRes = await fetch(OAUTH2_AUTH_URL, {
      headers: {
                'Cookie':            req.headers['cookie'] || '',
                // Thêm các headers này để OAuth2 Proxy validate đúng
                'X-Forwarded-Proto': req.headers['x-forwarded-proto'] || 'https',
                'X-Forwarded-Host':  req.headers['x-forwarded-host']  || req.headers['host'] || '',
                'X-Forwarded-Uri':   req.headers['x-forwarded-uri']   || req.headers['x-original-uri'] || '/',
                'X-Real-IP':         req.headers['x-real-ip']         || '',
                'X-Forwarded-For':   req.headers['x-forwarded-for']   || '',
       }
    });

    if (oauthRes.status === 401) return res.status(401).end();

    const user      = oauthRes.headers.get('x-auth-request-user')   || '';
    const email     = oauthRes.headers.get('x-auth-request-email')  || '';
    const groupsRaw = oauthRes.headers.get('x-auth-request-groups') || '';
    const groupList = groupsRaw.split(',').map(g => g.trim()).filter(Boolean);

    // Guard: chặn ngay nếu không có group phù hợp, không cần gọi Cerbos
    if (!hasAppAccess(groupList)) {
      console.log(JSON.stringify({
        ts: new Date().toISOString(), source: 'gateway',
        user, email, groups: groupList,
        path: req.headers['x-original-uri'] || req.url,
        decision: 'DENY', reason: 'no_app_access_group'
      }));
      const uri  = encodeURIComponent(req.headers['x-original-uri'] || '');
      const u    = encodeURIComponent(user);
      const mail = encodeURIComponent(email);
      res.set('x-authz-redirect', `https://public.vocongkhanh.id.vn/403.html?uri=${uri}&user=${u}&mail=${mail}`);
      return res.status(403).end();
    }

    // Gọi Cerbos check chi tiết
    const result = await check(req);

    if (result.status === 403) {
      const uri  = encodeURIComponent(req.headers['x-original-uri'] || '');
      const u    = encodeURIComponent(result.user  || '');
      const mail = encodeURIComponent(result.email || '');
      res.set('x-authz-redirect', `https://public.vocongkhanh.id.vn/403.html?uri=${uri}&user=${u}&mail=${mail}`);
      return res.status(403).end();
    }

    res.set('x-auth-request-user',   result.user);
    res.set('x-auth-request-email',  result.email);
    res.set('x-auth-request-groups', result.groups);
    return res.status(200).end();

  } catch (err) {
    console.error('[authz] error:', err);
    return res.status(500).end();
  }
});

// =========================================================================
// MIDDLEWARE: check mọi request vào /resources/ và /app/
// =========================================================================
app.use(async (req, res, next) => {
  if (req.path === '/authz') return next();
  if (isStaticAsset(req.url)) return next();

  const needsCheck = req.url.startsWith('/resources') ||
                     req.url.startsWith('/app')        ||
                     req.url.startsWith('/api')        ||
                     req.url === '/whoami'              ||
                     req.url === '/projects'            ||
                     req.url === '/logs';

  if (!needsCheck) return next();

  try {
    const result = await check(req);

    if (result.status === 401) return res.redirect('/oauth2/start');
    if (result.status === 403) return res.redirect('/403.html');

    req.headers['x-remote-user']   = result.user;
    req.headers['x-remote-email']  = result.email;
    req.headers['x-remote-groups'] = result.groups;
    next();

  } catch (err) {
    console.error('[middleware] error:', err);
    return res.status(500).send('Gateway error');
  }
});

// =========================================================================
// PROXY
// =========================================================================
app.use('/resources', createProxyMiddleware({
  target: RESOURCE_APP, changeOrigin: true,
  on: { error: (err, req, res) => { console.error('[proxy:resources]', err.message); res.status(502).send('Resource backend unavailable'); } }
}));

app.use('/', createProxyMiddleware({
  target: PRIVATE_APP, changeOrigin: true,
  on: { error: (err, req, res) => { console.error('[proxy:app]', err.message); res.status(502).send('Application backend unavailable'); } }
}));

// =========================================================================
app.listen(3001, '127.0.0.1', () => console.log('Gateway running on 127.0.0.1:3001'));

process.on('uncaughtException',  err => console.error('[uncaughtException]',  err));
process.on('unhandledRejection', err => console.error('[unhandledRejection]', err));
