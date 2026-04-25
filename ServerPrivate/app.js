const express           = require('express');
const winston           = require('winston');
const DailyRotateFile   = require('winston-daily-rotate-file');
const morgan            = require('morgan');
const fs                = require('fs');
const path              = require('path');

const app     = express();
const PORT    = 4000;
const LOG_DIR = '/var/log/nodejs-app';

if (!fs.existsSync(LOG_DIR)) fs.mkdirSync(LOG_DIR, { recursive: true });

// ─── Logger ───────────────────────────────────────────────────────────────
const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp({ format: 'YYYY-MM-DDTHH:mm:ss' }),
    winston.format.json()
  ),
  transports: [
    new DailyRotateFile({
      filename:    path.join(LOG_DIR, 'app-%DATE%.log'),
      datePattern: 'YYYY-MM-DD',
      maxSize:     '20m',
      maxFiles:    '14d',
      level:       'info'
    })
  ]
});

// ─── Audit log (JSON Lines) ───────────────────────────────────────────────
const AUDIT_FILE = path.join(LOG_DIR, 'audit.json');

function writeAudit(entry) {
  const { user, ...rest } = entry;
  const record = { ...rest, user_id: user, timestamp: new Date().toISOString() };
  logger.info('[AUDIT]', record);
  fs.appendFileSync(AUDIT_FILE, JSON.stringify(record) + '\n', 'utf8');
}

function readAuditLogs(limit = 200) {
  if (!fs.existsSync(AUDIT_FILE)) return [];
  const lines = fs.readFileSync(AUDIT_FILE, 'utf8').split('\n').filter(Boolean);
  return lines
    .slice(-limit)
    .map(l => { try { return JSON.parse(l); } catch { return null; } })
    .filter(Boolean)
    .reverse()
    // ── Chỉ giữ lại log tạo / cập nhật / xóa / truy cập / từ chối ──
    .filter(l => {
      const a = (l.action || '').toUpperCase();
      return a.includes('CREATE') || a.includes('UPDATE') || a.includes('DELETE') ||
             a.includes('ACCESS') || a.includes('DENIED');
    });
}

// ─── Middleware ───────────────────────────────────────────────────────────
app.use(express.json());
app.use(morgan('combined', { stream: { write: msg => logger.info(msg.trim()) } }));

app.use((req, res, next) => {
  req.logger = logger.child({
    user_ip:   req.headers['x-remote-user']   || 'anonymous',
    email:  req.headers['x-remote-email']  || '',
    groups: req.headers['x-remote-groups'] || '',
    ip:     req.ip || req.connection.remoteAddress
  });
  next();
});

app.get('/projects', (req, res) => res.sendFile(path.join(__dirname, 'projects.html')));
app.get('/logs',     (req, res) => {
  const { groups } = getUser(req);
  if (!isAdmin(groups)) return res.status(403).send('Access Denied');
  res.sendFile(path.join(__dirname, 'logs.html'));
});
app.use(express.static(path.join(__dirname)));

// ─── In-memory store ──────────────────────────────────────────────────────
let projects = [
  { id: 1, name: 'Zero Trust Infrastructure',  status: 'active',   owner: 'admin',     createdAt: '2025-01-15', desc: 'Triển khai mô hình bảo mật Zero Trust cho toàn hệ thống' },
  { id: 2, name: 'SIEM Migration v2',           status: 'active',   owner: 'techteam',  createdAt: '2025-02-20', desc: 'Nâng cấp hệ thống SIEM lên phiên bản mới' },
  { id: 3, name: 'Onboarding Automation',       status: 'planning', owner: 'manager01', createdAt: '2025-03-01', desc: 'Tự động hóa quy trình onboarding nhân viên mới' },
];
let tasks = [
  { id: 1,  projectId: 1, title: 'Cấu hình Cerbos policy',            status: 'done',  assignee: 'admin',     priority: 'high',   createdAt: '2025-01-16' },
  { id: 2,  projectId: 1, title: 'Tích hợp OAuth2 với Keycloak',      status: 'done',  assignee: 'techteam',  priority: 'high',   createdAt: '2025-01-18' },
  { id: 3,  projectId: 1, title: 'Kiểm thử phân quyền RBAC',          status: 'doing', assignee: 'admin',     priority: 'high',   createdAt: '2025-01-22' },
  { id: 4,  projectId: 1, title: 'Viết tài liệu kiến trúc',           status: 'doing', assignee: 'manager01', priority: 'medium', createdAt: '2025-01-25' },
  { id: 5,  projectId: 1, title: 'Audit log tập trung với Wazuh',     status: 'todo',  assignee: 'techteam',  priority: 'medium', createdAt: '2025-02-01' },
  { id: 6,  projectId: 2, title: 'Cài đặt Wazuh agent trên node mới', status: 'done',  assignee: 'techteam',  priority: 'high',   createdAt: '2025-02-21' },
  { id: 7,  projectId: 2, title: 'Cấu hình rule detection',           status: 'doing', assignee: 'techteam',  priority: 'high',   createdAt: '2025-02-25' },
  { id: 8,  projectId: 2, title: 'Dashboard Kibana cho team',         status: 'todo',  assignee: 'manager01', priority: 'low',    createdAt: '2025-03-02' },
  { id: 9,  projectId: 3, title: 'Thiết kế workflow onboarding',      status: 'todo',  assignee: 'manager01', priority: 'medium', createdAt: '2025-03-05' },
  { id: 10, projectId: 3, title: 'Script tạo account tự động',        status: 'todo',  assignee: 'techteam',  priority: 'medium', createdAt: '2025-03-10' },
];
let nextProjId = 4, nextTaskId = 11;

// ─── Helpers ──────────────────────────────────────────────────────────────
function getUser(req) {
  return {
    user:   req.headers['x-remote-user']   || 'anonymous',
    email:  req.headers['x-remote-email']  || '',
    groups: req.headers['x-remote-groups'] || '',
    ip:     req.headers['x-real-ip']       || req.ip || ''
  };
}
function hasRole(groups, ...roles) {
  const list = groups.toLowerCase().split(/[\s,]+/).map(x => x.trim()).filter(Boolean);
  return roles.some(r => list.includes(r));
}
function canCreate(g) { return hasRole(g, 'contributor','manager','admin','adminitrator','adminitrators','private-access'); }
function canUpdate(g) { return hasRole(g, 'contributor','manager','admin','adminitrator','adminitrators','private-access'); }
function canDelete(g) { return hasRole(g, 'manager','admin','adminitrator','adminitrators', 'private-access'); }
function isAdmin(g)   { return hasRole(g, 'admin','adminitrator','adminitrators'); }

// ─── Pages ────────────────────────────────────────────────────────────────
app.get('/', (req, res) => {
  req.logger.info('Access root');
  res.sendFile(path.join(__dirname, 'index.html'));
});

// ─── Whoami ───────────────────────────────────────────────────────────────
app.get('/whoami', (req, res) => {
  req.logger.info('Access whoami');
  const { user, email, groups } = getUser(req);
  res.json({ user, email, groups });
});

// ─── Permissions ──────────────────────────────────────────────────────────
app.get('/api/permissions', (req, res) => {
  const { groups } = getUser(req);
  res.json({
    read:   true,
    create: canCreate(groups),
    update: canUpdate(groups),
    delete: canDelete(groups),
    admin:  isAdmin(groups)
  });
});

// ─── Audit Logs API ───────────────────────────────────────────────────────
app.get('/api/logs', (req, res) => {
  const { groups, user, ip } = getUser(req);
  if (!isAdmin(groups)) {
    writeAudit({ action: 'ACCESS_DENIED', resource: 'logs', user, ip, reason: 'Không phải admin' });
    return res.status(403).json({ error: 'Chỉ admin mới xem được log' });
  }
  const limit  = parseInt(req.query.limit) || 200;
  const filter = (req.query.filter || '').toLowerCase();
  let logs = readAuditLogs(limit);
  if (filter) {
    logs = logs.filter(l =>
      (l.user     || '').toLowerCase().includes(filter) ||
      (l.action   || '').toLowerCase().includes(filter) ||
      (l.resource || '').toLowerCase().includes(filter)
    );
  }
  res.json(logs);
});

// ─── Projects CRUD ────────────────────────────────────────────────────────
// GET — không ghi audit (đọc thuần túy)
app.get('/api/projects', (req, res) => {
  res.json(projects);
});

app.post('/api/projects', (req, res) => {
  const { groups, user, ip } = getUser(req);
  if (!canCreate(groups)) {
    writeAudit({ action: 'CREATE_PROJECT_DENIED', resource: 'projects', user, ip, reason: 'Không đủ quyền' });
    return res.status(403).json({ error: 'Bạn không có quyền tạo dự án' });
  }
  const { name, desc = '' } = req.body;
  if (!name) return res.status(400).json({ error: 'Thiếu tên dự án' });

  const proj = { id: nextProjId++, name, desc, status: 'planning', owner: user, createdAt: new Date().toISOString().split('T')[0] };
  projects.push(proj);
  writeAudit({ action: 'CREATE_PROJECT', resource: 'projects', resourceId: proj.id, user, ip, detail: { name, desc } });
  req.logger.info(`Tạo project mới: ${name}`);
  res.status(201).json(proj);
});

app.delete('/api/projects/:id', (req, res) => {
  const { groups, user, ip } = getUser(req);
  if (!canDelete(groups)) {
    writeAudit({ action: 'DELETE_PROJECT_DENIED', resource: 'projects', resourceId: req.params.id, user, ip, reason: 'Không đủ quyền' });
    return res.status(403).json({ error: 'Bạn không có quyền xóa dự án' });
  }
  const id  = parseInt(req.params.id);
  const idx = projects.findIndex(p => p.id === id);
  if (idx === -1) return res.status(404).json({ error: 'Không tìm thấy dự án' });

  const deleted     = projects.splice(idx, 1)[0];
  const removedTask = tasks.filter(t => t.projectId === id).length;
  tasks = tasks.filter(t => t.projectId !== id);
  writeAudit({ action: 'DELETE_PROJECT', resource: 'projects', resourceId: id, user, ip, detail: { name: deleted.name, removedTasks: removedTask } });
  req.logger.info(`Xóa project #${id}`);
  res.json({ success: true, deleted });
});

// ─── Tasks CRUD ───────────────────────────────────────────────────────────
// GET — không ghi audit (đọc thuần túy)
app.get('/api/tasks', (req, res) => {
  const projectId = req.query.projectId ? parseInt(req.query.projectId) : null;
  res.json(projectId ? tasks.filter(t => t.projectId === projectId) : tasks);
});

app.post('/api/tasks', (req, res) => {
  const { groups, user, ip } = getUser(req);
  if (!canCreate(groups)) {
    writeAudit({ action: 'CREATE_TASK_DENIED', resource: 'tasks', user, ip, reason: 'Không đủ quyền' });
    return res.status(403).json({ error: 'Bạn không có quyền tạo task' });
  }
  const { title, projectId, assignee = user, priority = 'medium' } = req.body;
  if (!title || !projectId) return res.status(400).json({ error: 'Thiếu tiêu đề hoặc dự án' });

  const proj = projects.find(p => p.id === parseInt(projectId));
  if (!proj) return res.status(404).json({ error: 'Dự án không tồn tại' });

  const task = { id: nextTaskId++, projectId: parseInt(projectId), title, status: 'todo', assignee, priority, createdAt: new Date().toISOString().split('T')[0] };
  tasks.push(task);
  writeAudit({ action: 'CREATE_TASK', resource: 'tasks', resourceId: task.id, user, ip, detail: { title, projectName: proj.name, assignee, priority } });
  req.logger.info(`Tạo task mới: ${title}`);
  res.status(201).json(task);
});

app.patch('/api/tasks/:id', (req, res) => {
  const { groups, user, ip } = getUser(req);
  if (!canUpdate(groups)) {
    writeAudit({ action: 'UPDATE_TASK_DENIED', resource: 'tasks', resourceId: req.params.id, user, ip, reason: 'Không đủ quyền' });
    return res.status(403).json({ error: 'Bạn không có quyền cập nhật task' });
  }
  const id   = parseInt(req.params.id);
  const task = tasks.find(t => t.id === id);
  if (!task) return res.status(404).json({ error: 'Không tìm thấy task' });

  const before = { status: task.status, title: task.title, assignee: task.assignee, priority: task.priority };
  const { status, title, assignee, priority } = req.body;
  if (status)   task.status   = status;
  if (title)    task.title    = title;
  if (assignee) task.assignee = assignee;
  if (priority) task.priority = priority;

  writeAudit({ action: 'UPDATE_TASK', resource: 'tasks', resourceId: id, user, ip, detail: { taskTitle: task.title, before, after: { status, title, assignee, priority } } });
  req.logger.info(`Cập nhật task #${id} bởi ${user}`);
  res.json(task);
});

app.delete('/api/tasks/:id', (req, res) => {
  const { groups, user, ip } = getUser(req);
  if (!canDelete(groups)) {
    writeAudit({ action: 'DELETE_TASK_DENIED', resource: 'tasks', resourceId: req.params.id, user, ip, reason: 'Không đủ quyền' });
    return res.status(403).json({ error: 'Bạn không có quyền xóa task' });
  }
  const id  = parseInt(req.params.id);
  const idx = tasks.findIndex(t => t.id === id);
  if (idx === -1) return res.status(404).json({ error: 'Không tìm thấy task' });

  const deleted = tasks.splice(idx, 1)[0];
  writeAudit({ action: 'DELETE_TASK', resource: 'tasks', resourceId: id, user, ip, detail: { title: deleted.title } });
  req.logger.info(`Xóa task #${id}`);
  res.json({ success: true, deleted });
});

// ─── Private data ─────────────────────────────────────────────────────────
app.get('/api/private-data', (req, res) => {
  const { user, groups, ip } = getUser(req);
  if (!groups.includes('private-access')) {
    writeAudit({ action: 'ACCESS_DENIED', resource: 'private-data', user, ip, reason: 'Không có group private-access' });
    req.logger.warn(`Access denied to private-data - User: ${user}`);
    return res.status(403).json({ error: 'Bạn không có quyền truy cập dữ liệu private' });
  }
  writeAudit({ action: 'ACCESS_PRIVATE_DATA', resource: 'private-data', user, ip });
  req.logger.info(`Access granted to private-data - User: ${user}`);
  res.json({ message: 'Đây là APPLICATIONS - Private Zone', user, email: req.headers['x-remote-email'], groups, zone: 'Private', timestamp: new Date().toISOString() });
});

app.get('/api/private-data/admin', (req, res) => {
  const { user, groups, ip } = getUser(req);
  if (!isAdmin(groups)) {
    writeAudit({ action: 'ACCESS_DENIED', resource: 'admin-zone', user, ip, reason: 'Không phải admin' });
    req.logger.warn(`[403] Access denied to ADMIN zone - User: ${user}`);
    return res.status(403).json({ error: 'Access Denied', message: "Bạn cần thuộc group 'admin' để truy cập khu vực này" });
  }
  writeAudit({ action: 'ACCESS_ADMIN_ZONE', resource: 'admin-zone', user, ip });
  req.logger.info(`[200] ADMIN access granted - User: ${user}`);
  res.json({ message: 'ADMIN ZONE - Private Application', user, email: req.headers['x-remote-email'], groups, zone: 'Admin Only', timestamp: new Date().toISOString() });
});

app.get('/health', (req, res) => { req.logger.info('Health check OK'); res.send('OK'); });

app.listen(PORT, () => logger.info(`Private Application chạy tại http://localhost:${PORT}`));
console.log('LOADED: Zero Trust App — Audit Logging enabled');
