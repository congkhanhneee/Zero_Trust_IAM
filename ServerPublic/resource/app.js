const express  = require('express');
const path     = require('path');
const fs       = require('fs');
const multer   = require('multer');

const app  = express();
const PORT = 3000;

// ─── Thư mục lưu trữ ─────────────────────────────────────────────────────
const UPLOAD_DIR = path.join(__dirname, 'uploads');
const DATA_FILE  = path.join(__dirname, 'data', 'documents.json');
const LOG_DIR    = path.join(__dirname, 'logs');
const LOG_FILE   = path.join(LOG_DIR, 'audit.log');

if (!fs.existsSync(UPLOAD_DIR))                    fs.mkdirSync(UPLOAD_DIR, { recursive: true });
if (!fs.existsSync(path.join(__dirname, 'data')))  fs.mkdirSync(path.join(__dirname, 'data'), { recursive: true });
if (!fs.existsSync(LOG_DIR))                       fs.mkdirSync(LOG_DIR, { recursive: true });

// ─── JSON store helpers ───────────────────────────────────────────────────
function loadDocs() {
  if (!fs.existsSync(DATA_FILE)) return [];
  try { return JSON.parse(fs.readFileSync(DATA_FILE, 'utf8')); } catch { return []; }
}
function saveDocs(docs) {
  fs.writeFileSync(DATA_FILE, JSON.stringify(docs, null, 2), 'utf8');
}

// Seed dữ liệu mẫu nếu chưa có
if (!fs.existsSync(DATA_FILE)) {
  saveDocs([
    { id: 1, name: 'Hợp đồng dịch vụ Q1-2025.pdf',       type: 'pdf',  size: '1.2 MB', owner: 'admin',  owner_email: 'admin@congkhanh.id.vn',  uploadedAt: '2025-01-10', category: 'Hợp đồng',  filename: null },
    { id: 2, name: 'Báo cáo tài chính tháng 3.xlsx',      type: 'xlsx', size: '845 KB', owner: 'admin',  owner_email: 'admin@congkhanh.id.vn',  uploadedAt: '2025-03-28', category: 'Tài chính', filename: null },
    { id: 3, name: 'Quy trình onboarding nhân viên.docx', type: 'docx', size: '320 KB', owner: 'user1',  owner_email: 'user1@congkhanh.id.vn',  uploadedAt: '2025-02-14', category: 'Nhân sự',   filename: null },
    { id: 4, name: 'Sơ đồ hạ tầng mạng v2.png',          type: 'img',  size: '2.1 MB', owner: 'user2',  owner_email: 'user2@congkhanh.id.vn',  uploadedAt: '2025-03-05', category: 'Kỹ thuật',  filename: null },
    { id: 5, name: 'Chính sách bảo mật nội bộ.pdf',       type: 'pdf',  size: '560 KB', owner: 'user3',  owner_email: 'user3@congkhanh.id.vn',  uploadedAt: '2025-01-20', category: 'Bảo mật',   filename: null },
    { id: 6, name: 'Kế hoạch triển khai Q2-2025.pptx',   type: 'pptx', size: '3.4 MB', owner: 'user1',  owner_email: 'user1@congkhanh.id.vn',  uploadedAt: '2025-03-30', category: 'Kế hoạch',  filename: null },
  ]);
}

let nextDocId = loadDocs().reduce((max, d) => Math.max(max, d.id), 0) + 1;

// ─── Multer config ────────────────────────────────────────────────────────
const ALLOWED_TYPES = {
  'application/pdf':                                                           'pdf',
  'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet':        'xlsx',
  'application/vnd.ms-excel':                                                 'xlsx',
  'application/vnd.openxmlformats-officedocument.wordprocessingml.document':  'docx',
  'application/msword':                                                        'docx',
  'application/vnd.openxmlformats-officedocument.presentationml.presentation':'pptx',
  'application/vnd.ms-powerpoint':                                            'pptx',
  'image/jpeg': 'img', 'image/png': 'img', 'image/gif': 'img', 'image/webp': 'img',
  'text/plain': 'other', 'application/zip': 'other',
};

const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, UPLOAD_DIR),
  filename:    (req, file, cb) => {
    const ts  = Date.now();
    const ext = path.extname(file.originalname);
    cb(null, `${ts}_${Math.random().toString(36).slice(2,8)}${ext}`);
  }
});

const upload = multer({
  storage,
  limits: { fileSize: 50 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    if (ALLOWED_TYPES[file.mimetype]) return cb(null, true);
    cb(new Error('Loại file không được phép'));
  }
});

// ─── Helpers ──────────────────────────────────────────────────────────────
function getUser(req) {
  return {
    user:   req.headers['x-remote-user']   || 'anonymous',
    email:  req.headers['x-remote-email']  || '',
    groups: req.headers['x-remote-groups'] || ''
  };
}

function hasPermission(groups, action) {
  const list = groups.toLowerCase().split(/[\s,]+/).map(x => x.trim()).filter(Boolean);
  switch (action) {
    case 'write':  return list.some(r => ['contributor','manager','admin','adminitrator','adminitrators','private-access'].includes(r));
    case 'delete': return list.some(r => ['manager','admin','adminitrator','adminitrators'].includes(r));
    default:       return true;
  }
}

function formatSize(bytes) {
  if (bytes < 1024)                 return bytes + ' B';
  if (bytes < 1024 * 1024)         return (bytes / 1024).toFixed(1) + ' KB';
  if (bytes < 1024 * 1024 * 1024)  return (bytes / (1024 * 1024)).toFixed(1) + ' MB';
  return (bytes / (1024 * 1024 * 1024)).toFixed(1) + ' GB';
}

// ═══════════════════════════════════════════════════════════════════════════
// AUDIT LOGGER
// ═══════════════════════════════════════════════════════════════════════════
function auditLog({ req, action, resource, result, details = {} }) {
  const { user, email, groups } = getUser(req);

  const entry = {
    timestamp: new Date().toISOString(),
    source:    'resources_app',
    action,
    resource,
    result,
    user: {
      name:   user,
      email:  email,
      groups: groups,
    },
    client: {
      ip:         req.headers['x-forwarded-for'] || req.socket.remoteAddress,
      user_agent: req.headers['user-agent'] || '',
    },
    details,
  };

  const line = JSON.stringify(entry) + '\n';
  fs.appendFileSync(LOG_FILE, line, 'utf8');
}

// ─── Middleware ───────────────────────────────────────────────────────────
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// ─── Pages ────────────────────────────────────────────────────────────────
app.get('/',                    (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));
app.get('/resources',           (req, res) => res.sendFile(path.join(__dirname, 'public', 'resources.html')));
app.get('/resources/documents', (req, res) => res.sendFile(path.join(__dirname, 'public', 'documents.html')));

// ─── API: whoami ──────────────────────────────────────────────────────────
app.get('/resources/api/whoami', (req, res) => {
  const { user, email, groups } = getUser(req);
  res.json({ user, email, groups });
});

// ─── API: permissions ─────────────────────────────────────────────────────
app.get('/resources/api/permissions', (req, res) => {
  const { groups } = getUser(req);
  res.json({
    read:     true,
    download: true,
    write:    hasPermission(groups, 'write'),
    delete:   hasPermission(groups, 'delete')
  });
});

// ─── API: Documents CRUD ──────────────────────────────────────────────────
app.get('/resources/api/documents', (req, res) => {
  res.json(loadDocs());
});

// Upload
app.post('/resources/api/documents', upload.single('file'), (req, res) => {
  const { groups, user, email } = getUser(req);

  if (!hasPermission(groups, 'write')) {
    auditLog({
      req,
      action:   'upload_document',
      resource: req.file?.originalname || 'unknown',
      result:   'denied',
      details:  { reason: 'insufficient_permission', groups },
    });
    return res.status(403).json({ error: 'Bạn không có quyền upload tài liệu' });
  }

  if (!req.file) {
    auditLog({
      req,
      action:   'upload_document',
      resource: 'unknown',
      result:   'failure',
      details:  { reason: 'no_file_provided' },
    });
    return res.status(400).json({ error: 'Vui lòng chọn file để upload' });
  }

  const { category = 'Khác' } = req.body;
  const fileType = ALLOWED_TYPES[req.file.mimetype] || 'other';

  const doc = {
    id:          nextDocId++,
    name:        req.file.originalname,
    type:        fileType,
    size:        formatSize(req.file.size),
    category,
    owner:       user,
    owner_email: email,
    uploadedAt:  new Date().toISOString().split('T')[0],
    filename:    req.file.filename,
    mimetype:    req.file.mimetype,
  };

  const docs = loadDocs();
  docs.unshift(doc);
  saveDocs(docs);

  auditLog({
    req,
    action:   'upload_document',
    resource: req.file.originalname,
    result:   'success',
    details:  {
      doc_id:    doc.id,
      file_type: fileType,
      file_size: req.file.size,
      mimetype:  req.file.mimetype,
      category,
      saved_as:  req.file.filename,
    },
  });

  res.status(201).json(doc);
});

// Download
app.get('/resources/api/documents/:id/download', (req, res) => {
  const { groups } = getUser(req);
  const id  = parseInt(req.params.id);
  const doc = loadDocs().find(d => d.id === id);

  if (!hasPermission(groups, 'download') && !hasPermission(groups, 'read')) {
    auditLog({
      req,
      action:   'download_document',
      resource: doc?.name || `doc_id:${id}`,
      result:   'denied',
      details:  { doc_id: id, reason: 'insufficient_permission' },
    });
    return res.status(403).json({ error: 'Bạn không có quyền tải xuống' });
  }

  if (!doc) {
    auditLog({
      req,
      action:   'download_document',
      resource: `doc_id:${id}`,
      result:   'failure',
      details:  { doc_id: id, reason: 'not_found' },
    });
    return res.status(404).json({ error: 'Không tìm thấy tài liệu' });
  }

  if (!doc.filename) {
    auditLog({
      req,
      action:   'download_document',
      resource: doc.name,
      result:   'failure',
      details:  { doc_id: id, reason: 'sample_data_no_file' },
    });
    return res.status(404).json({ error: 'File thực chưa được upload, đây là dữ liệu mẫu' });
  }

  const filePath = path.join(UPLOAD_DIR, doc.filename);
  if (!fs.existsSync(filePath)) {
    auditLog({
      req,
      action:   'download_document',
      resource: doc.name,
      result:   'failure',
      details:  { doc_id: id, reason: 'file_missing_on_disk' },
    });
    return res.status(404).json({ error: 'File không còn tồn tại trên server' });
  }

  auditLog({
    req,
    action:   'download_document',
    resource: doc.name,
    result:   'success',
    details:  {
      doc_id:    id,
      file_type: doc.type,
      file_size: doc.size,
      category:  doc.category,
      owner:     doc.owner,
    },
  });

  res.download(filePath, doc.name);
});

// Xóa
app.delete('/resources/api/documents/:id', (req, res) => {
  const { groups } = getUser(req);
  const id   = parseInt(req.params.id);
  let   docs = loadDocs();
  const doc  = docs.find(d => d.id === id);

  if (!hasPermission(groups, 'delete')) {
    auditLog({
      req,
      action:   'delete_document',
      resource: doc?.name || `doc_id:${id}`,
      result:   'denied',
      details:  { doc_id: id, reason: 'insufficient_permission', groups },
    });
    return res.status(403).json({ error: 'Bạn không có quyền xóa tài liệu' });
  }

  const idx = docs.findIndex(d => d.id === id);
  if (idx === -1) {
    auditLog({
      req,
      action:   'delete_document',
      resource: `doc_id:${id}`,
      result:   'failure',
      details:  { doc_id: id, reason: 'not_found' },
    });
    return res.status(404).json({ error: 'Không tìm thấy tài liệu' });
  }

  const [deleted] = docs.splice(idx, 1);

  if (deleted.filename) {
    const fp = path.join(UPLOAD_DIR, deleted.filename);
    if (fs.existsSync(fp)) fs.unlinkSync(fp);
  }

  saveDocs(docs);

  auditLog({
    req,
    action:   'delete_document',
    resource: deleted.name,
    result:   'success',
    details:  {
      doc_id:    id,
      file_type: deleted.type,
      category:  deleted.category,
      owner:     deleted.owner,
      had_file:  !!deleted.filename,
    },
  });

  res.json({ success: true, deleted });
});

// ─── Misc ─────────────────────────────────────────────────────────────────
app.get('/app/api/public-data', (req, res) => {
  res.json({ message: 'Đây là Resources - Public Zone', user: getUser(req).user, zone: 'Public', timestamp: new Date().toISOString() });
});

app.get('/health', (req, res) => res.send('OK'));

app.listen(PORT, () => console.log(`Resources Public Zone chạy tại http://localhost:${PORT}`));
