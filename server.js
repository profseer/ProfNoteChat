const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const cors = require('cors');
const path = require('path');
const fs = require('fs');
const { v4: uuidv4 } = require('uuid');
const low = require('lowdb');
const FileSync = require('lowdb/adapters/FileSync');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'notechat_secret_2024';

// ── DATABASE ──────────────────────────────────────────────
const DB_DIR = './db';
if (!fs.existsSync(DB_DIR)) fs.mkdirSync(DB_DIR, { recursive: true });
if (!fs.existsSync(DB_DIR + '/data.json')) fs.writeFileSync(DB_DIR + '/data.json', '{}');
const adapter = new FileSync('./db/data.json');
const db = low(adapter);
db.defaults({ users: [], messages: [], files: [], shares: [] }).write();

// ── UPLOADS ───────────────────────────────────────────────
const UPLOADS_DIR = './uploads';
if (!fs.existsSync(UPLOADS_DIR)) fs.mkdirSync(UPLOADS_DIR, { recursive: true });
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, UPLOADS_DIR),
  filename: (req, file, cb) => cb(null, uuidv4() + path.extname(file.originalname))
});
const upload = multer({ storage, limits: { fileSize: 10 * 1024 * 1024 } });

// ── CORS ──────────────────────────────────────────────────
app.use(cors());
app.use(express.json());
app.use('/uploads', express.static('uploads'));

// ── AUTH MIDDLEWARE ───────────────────────────────────────
function auth(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'No token' });
  try { req.user = jwt.verify(token, JWT_SECRET); next(); }
  catch { res.status(401).json({ error: 'Invalid token' }); }
}
function adminAuth(req, res, next) {
  auth(req, res, () => {
    if (!req.user.isAdmin) return res.status(403).json({ error: 'Admin only' });
    next();
  });
}

// ══════════════════════════════════════════════════════════
// AUTH ROUTES
// ══════════════════════════════════════════════════════════
app.get('/', (req, res) => res.json({ status: 'NoteChat API running ✓' }));

app.post('/api/register', async (req, res) => {
  const { username, email, password } = req.body;
  if (!username || !email || !password)
    return res.status(400).json({ error: 'All fields required' });
  if (db.get('users').find({ email }).value())
    return res.status(409).json({ error: 'Email already registered' });
  const isFirst = db.get('users').size().value() === 0;
  const hash = await bcrypt.hash(password, 10);
  const user = { id: uuidv4(), username, email, password: hash, isAdmin: isFirst, createdAt: new Date().toISOString(), active: true };
  db.get('users').push(user).write();
  const token = jwt.sign({ id: user.id, username, email, isAdmin: user.isAdmin }, JWT_SECRET, { expiresIn: '7d' });
  res.json({ token, user: { id: user.id, username, email, isAdmin: user.isAdmin } });
});

app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  const user = db.get('users').find({ email }).value();
  if (!user) return res.status(401).json({ error: 'Invalid credentials' });
  if (!user.active) return res.status(403).json({ error: 'Account disabled' });
  if (!await bcrypt.compare(password, user.password))
    return res.status(401).json({ error: 'Invalid credentials' });
  const token = jwt.sign({ id: user.id, username: user.username, email, isAdmin: user.isAdmin }, JWT_SECRET, { expiresIn: '7d' });
  res.json({ token, user: { id: user.id, username: user.username, email, isAdmin: user.isAdmin } });
});

app.get('/api/me', auth, (req, res) => {
  const user = db.get('users').find({ id: req.user.id }).value();
  if (!user) return res.status(404).json({ error: 'Not found' });
  res.json({ id: user.id, username: user.username, email: user.email, isAdmin: user.isAdmin });
});

// ══════════════════════════════════════════════════════════
// MESSAGE ROUTES
// ══════════════════════════════════════════════════════════
app.get('/api/messages', auth, (req, res) => {
  const { q } = req.query;
  let msgs = db.get('messages').filter({ userId: req.user.id }).value();
  if (q) {
    const ql = q.toLowerCase();
    msgs = msgs.filter(m => m.text?.toLowerCase().includes(ql) || m.fileName?.toLowerCase().includes(ql));
  }
  res.json(msgs);
});

app.post('/api/messages', auth, (req, res) => {
  const { text } = req.body;
  if (!text?.trim()) return res.status(400).json({ error: 'Text required' });
  const msg = {
    id: uuidv4(), userId: req.user.id, username: req.user.username,
    text: text.trim(), type: 'text', createdAt: new Date().toISOString()
  };
  db.get('messages').push(msg).write();
  res.json(msg);
});

app.patch('/api/messages/:id', auth, (req, res) => {
  const { text } = req.body;
  if (!text?.trim()) return res.status(400).json({ error: 'Text required' });
  const msg = db.get('messages').find({ id: req.params.id, userId: req.user.id }).value();
  if (!msg) return res.status(404).json({ error: 'Not found' });
  db.get('messages').find({ id: req.params.id })
    .assign({ text: text.trim(), edited: true, editedAt: new Date().toISOString() })
    .write();
  res.json({ ok: true });
});

app.delete('/api/messages/:id', auth, (req, res) => {
  const msg = db.get('messages').find({ id: req.params.id, userId: req.user.id }).value();
  if (!msg) return res.status(404).json({ error: 'Not found' });
  if (msg.fileId) {
    const file = db.get('files').find({ id: msg.fileId }).value();
    if (file) {
      try { fs.unlinkSync(path.join(UPLOADS_DIR, file.storedName)); } catch {}
      db.get('files').remove({ id: file.id }).write();
    }
  }
  db.get('messages').remove({ id: req.params.id }).write();
  res.json({ ok: true });
});

// ══════════════════════════════════════════════════════════
// FILE ROUTES
// ══════════════════════════════════════════════════════════
app.post('/api/upload', auth, upload.single('file'), (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'No file' });
  const host = req.headers['x-forwarded-host'] || req.headers.host;
  const proto = req.headers['x-forwarded-proto'] || req.protocol;
  const fileUrl = `${proto}://${host}/uploads/${req.file.filename}`;
  const fileRecord = {
    id: uuidv4(), userId: req.user.id,
    originalName: req.file.originalname, storedName: req.file.filename,
    mimeType: req.file.mimetype, size: req.file.size,
    url: fileUrl, createdAt: new Date().toISOString()
  };
  db.get('files').push(fileRecord).write();
  const msg = {
    id: uuidv4(), userId: req.user.id, username: req.user.username,
    text: null, type: 'file', fileId: fileRecord.id,
    fileName: fileRecord.originalName, fileMime: fileRecord.mimeType,
    fileSize: fileRecord.size, fileUrl, createdAt: new Date().toISOString()
  };
  db.get('messages').push(msg).write();
  res.json({ file: fileRecord, message: msg });
});

app.get('/api/files', auth, (req, res) => {
  const { q } = req.query;
  let files = db.get('files').filter({ userId: req.user.id }).value();
  if (q) files = files.filter(f => f.originalName.toLowerCase().includes(q.toLowerCase()));
  res.json(files);
});

// ══════════════════════════════════════════════════════════
// SHARING ROUTES
// ══════════════════════════════════════════════════════════
app.post('/api/share', auth, (req, res) => {
  const { messageId } = req.body;
  if (!messageId) return res.status(400).json({ error: 'messageId required' });
  const msg = db.get('messages').find({ id: messageId, userId: req.user.id }).value();
  if (!msg) return res.status(404).json({ error: 'Message not found' });
  const existing = db.get('shares').find({ messageId }).value();
  if (existing) return res.json({ shareId: existing.shareId });
  const shareId = uuidv4().replace(/-/g, '').slice(0, 12);
  db.get('shares').push({ shareId, messageId, userId: req.user.id, createdAt: new Date().toISOString() }).write();
  res.json({ shareId });
});

app.delete('/api/share/:shareId', auth, (req, res) => {
  db.get('shares').remove({ shareId: req.params.shareId, userId: req.user.id }).write();
  res.json({ ok: true });
});

// Public share page — no auth
app.get('/share/:shareId', (req, res) => {
  const share = db.get('shares').find({ shareId: req.params.shareId }).value();
  if (!share) return res.status(404).send(`<!DOCTYPE html><html lang="ar" dir="rtl"><head><meta charset="UTF-8"/><link href="https://fonts.googleapis.com/css2?family=Cairo:wght@700&display=swap" rel="stylesheet"/><style>body{font-family:'Cairo',sans-serif;display:flex;align-items:center;justify-content:center;min-height:100vh;background:#f0f4ff;margin:0}.card{text-align:center;padding:48px;background:#fff;border-radius:24px;box-shadow:0 8px 40px rgba(79,124,255,.14)}.icon{font-size:3rem;margin-bottom:16px}.title{font-size:1.1rem;font-weight:800;color:#1a2040}</style></head><body><div class="card"><div class="icon">🔗</div><div class="title">هذا الرابط غير موجود أو انتهت صلاحيته</div></div></body></html>`);
  const msg = db.get('messages').find({ id: share.messageId }).value();
  if (!msg) return res.status(404).send('<p>الملاحظة غير موجودة</p>');
  const user = db.get('users').find({ id: msg.userId }).value();
  const name = user ? user.username : 'مستخدم';
  const date = new Date(msg.createdAt).toLocaleDateString('ar', { year: 'numeric', month: 'long', day: 'numeric' });
  let content = '';
  if (msg.type === 'text') content = `<p class="nt">${(msg.text||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/\n/g,'<br>')}</p>`;
  else if (msg.fileMime?.startsWith('image/') || msg.type === 'drawing') content = `<img src="${msg.fileUrl}" style="max-width:100%;border-radius:16px;box-shadow:0 8px 32px rgba(0,0,0,.12)"/>`;
  else if (msg.type === 'audio') content = `<audio controls src="${msg.fileUrl}" style="width:100%"></audio>`;
  else if (msg.fileUrl) content = `<a href="${msg.fileUrl}" download="${msg.fileName||'file'}" style="display:inline-flex;align-items:center;gap:12px;padding:16px 24px;background:#f0f4ff;border-radius:14px;text-decoration:none;color:#1a2040;font-weight:700">📎 ${msg.fileName||'ملف'}</a>`;
  res.send(`<!DOCTYPE html><html lang="ar" dir="rtl"><head><meta charset="UTF-8"/><meta name="viewport" content="width=device-width,initial-scale=1"/><title>ملاحظة - NoteChat</title><link href="https://fonts.googleapis.com/css2?family=Cairo:wght@400;600;700;800&display=swap" rel="stylesheet"/><style>*{margin:0;padding:0;box-sizing:border-box}body{font-family:'Cairo',sans-serif;background:#f0f4ff;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:20px}.card{background:#fff;border-radius:24px;padding:36px;max-width:600px;width:100%;box-shadow:0 8px 40px rgba(79,124,255,.14)}.brand{display:flex;align-items:center;gap:10px;margin-bottom:24px;padding-bottom:20px;border-bottom:1px solid #e8edf8}.bic{width:36px;height:36px;border-radius:10px;background:linear-gradient(135deg,#3a5fd4,#7c9fff);display:flex;align-items:center;justify-content:center;flex-shrink:0}.bnm{font-size:1.1rem;font-weight:900;background:linear-gradient(135deg,#1a2040,#4f7cff);-webkit-background-clip:text;-webkit-text-fill-color:transparent}.meta{font-size:.82rem;color:#8a95b4;margin-bottom:20px}.cnt{margin-bottom:24px}.nt{font-size:1.05rem;line-height:1.75;color:#1a2040;font-weight:500;white-space:pre-wrap}.ft{font-size:.78rem;color:#9aa3be;text-align:center;padding-top:16px;border-top:1px solid #e8edf8}.cta{display:inline-block;margin-top:14px;padding:10px 22px;background:linear-gradient(135deg,#3a5fd4,#4f7cff);color:#fff;border-radius:10px;text-decoration:none;font-weight:700;font-size:.88rem}</style></head><body><div class="card"><div class="brand"><div class="bic"><svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#fff" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 20h9"/><path d="M16.5 3.5a2.121 2.121 0 013 3L7 19l-4 1 1-4L16.5 3.5z"/></svg></div><span class="bnm">NoteChat</span></div><div class="meta">✍️ ${name} &nbsp;·&nbsp; 📅 ${date}</div><div class="cnt">${content}</div><div class="ft">تمت المشاركة عبر NoteChat<br><a href="/" class="cta">انشئ ملاحظاتك →</a></div></div></body></html>`);
});

// ══════════════════════════════════════════════════════════
// ADMIN ROUTES
// ══════════════════════════════════════════════════════════
app.get('/api/admin/stats', adminAuth, (req, res) => {
  res.json({
    users: db.get('users').size().value(),
    messages: db.get('messages').size().value(),
    files: db.get('files').size().value(),
    totalSize: db.get('files').sumBy('size').value()
  });
});

app.get('/api/admin/users', adminAuth, (req, res) => {
  res.json(db.get('users').map(u => ({
    id: u.id, username: u.username, email: u.email,
    isAdmin: u.isAdmin, active: u.active, createdAt: u.createdAt
  })).value());
});

app.patch('/api/admin/users/:id', adminAuth, (req, res) => {
  const { active, isAdmin } = req.body;
  if (!db.get('users').find({ id: req.params.id }).value())
    return res.status(404).json({ error: 'Not found' });
  if (req.params.id === req.user.id)
    return res.status(400).json({ error: 'Cannot modify yourself' });
  if (active !== undefined) db.get('users').find({ id: req.params.id }).assign({ active }).write();
  if (isAdmin !== undefined) db.get('users').find({ id: req.params.id }).assign({ isAdmin }).write();
  res.json({ ok: true });
});

app.delete('/api/admin/users/:id', adminAuth, (req, res) => {
  if (req.params.id === req.user.id)
    return res.status(400).json({ error: 'Cannot delete yourself' });
  db.get('files').filter({ userId: req.params.id }).value()
    .forEach(f => { try { fs.unlinkSync(path.join(UPLOADS_DIR, f.storedName)); } catch {} });
  db.get('files').remove({ userId: req.params.id }).write();
  db.get('messages').remove({ userId: req.params.id }).write();
  db.get('users').remove({ id: req.params.id }).write();
  res.json({ ok: true });
});

app.delete('/api/admin/users/:id/messages', adminAuth, (req, res) => {
  db.get('messages').remove({ userId: req.params.id }).write();
  res.json({ ok: true });
});

app.delete('/api/admin/users/:id/files', adminAuth, (req, res) => {
  db.get('files').filter({ userId: req.params.id }).value()
    .forEach(f => { try { fs.unlinkSync(path.join(UPLOADS_DIR, f.storedName)); } catch {} });
  db.get('files').remove({ userId: req.params.id }).write();
  db.get('messages').remove({ userId: req.params.id, type: 'file' }).write();
  res.json({ ok: true });
});

app.post('/api/admin/broadcast', adminAuth, (req, res) => {
  const { text } = req.body;
  if (!text?.trim()) return res.status(400).json({ error: 'Text required' });
  const users = db.get('users').value();
  users.forEach(u => {
    db.get('messages').push({
      id: uuidv4(), userId: u.id, username: '📢 النظام',
      text: text.trim(), type: 'text', system: true,
      createdAt: new Date().toISOString()
    }).write();
  });
  res.json({ ok: true, count: users.length });
});

// ══════════════════════════════════════════════════════════
// START
// ══════════════════════════════════════════════════════════
app.listen(PORT, () => console.log(`NoteChat API running on port ${PORT}`));
