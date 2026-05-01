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
const JWT_SECRET = process.env.JWT_SECRET || 'notechat_secret_2024_changeme';

// ── DATABASE ──────────────────────────────────────────────────────
const DB_DIR = './db';
if (!fs.existsSync(DB_DIR)) fs.mkdirSync(DB_DIR, { recursive: true });
if (!fs.existsSync(DB_DIR + '/data.json')) fs.writeFileSync(DB_DIR + '/data.json', '{}');
const adapter = new FileSync('./db/data.json');
const db = low(adapter);
db.defaults({ users: [], messages: [], files: [] }).write();

// ── UPLOADS ───────────────────────────────────────────────────────
const UPLOADS_DIR = './uploads';
if (!fs.existsSync(UPLOADS_DIR)) fs.mkdirSync(UPLOADS_DIR, { recursive: true });

const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, UPLOADS_DIR),
  filename: (req, file, cb) => cb(null, uuidv4() + path.extname(file.originalname))
});
const upload = multer({ storage, limits: { fileSize: 10 * 1024 * 1024 } });

// ── CORS — allow mohamadysons.com to call this API ────────────────
app.use(cors({
  origin: function(origin, callback) {
    const allowed = [
      'https://mohamadysons.com',
      'http://mohamadysons.com',
      'http://localhost:3000',
      'http://localhost:5500',
    ];
    // allow Railway preview URLs and no-origin requests (same-origin / curl)
    if (!origin || allowed.includes(origin) || origin.endsWith('.railway.app')) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS: ' + origin));
    }
  },
  credentials: true
}));

app.use(express.json());
app.use('/uploads', express.static('uploads'));

// Health check
app.get('/', (req, res) => res.json({ status: 'NoteChat API is running ✓' }));

// ── AUTH MIDDLEWARE ───────────────────────────────────────────────
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

// ── REGISTER ─────────────────────────────────────────────────────
app.post('/api/register', async (req, res) => {
  const { username, email, password } = req.body;
  if (!username || !email || !password)
    return res.status(400).json({ error: 'All fields required' });
  if (db.get('users').find({ email }).value())
    return res.status(409).json({ error: 'Email already registered' });
  const isFirstUser = db.get('users').size().value() === 0;
  const hash = await bcrypt.hash(password, 10);
  const user = {
    id: uuidv4(), username, email, password: hash,
    isAdmin: isFirstUser, createdAt: new Date().toISOString(), active: true
  };
  db.get('users').push(user).write();
  const token = jwt.sign({ id: user.id, username, email, isAdmin: user.isAdmin }, JWT_SECRET, { expiresIn: '7d' });
  res.json({ token, user: { id: user.id, username, email, isAdmin: user.isAdmin } });
});

// ── LOGIN ─────────────────────────────────────────────────────────
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

// ── ME ────────────────────────────────────────────────────────────
app.get('/api/me', auth, (req, res) => {
  const user = db.get('users').find({ id: req.user.id }).value();
  if (!user) return res.status(404).json({ error: 'Not found' });
  res.json({ id: user.id, username: user.username, email: user.email, isAdmin: user.isAdmin });
});

// ── MESSAGES ──────────────────────────────────────────────────────
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

// ── FILE UPLOAD ───────────────────────────────────────────────────
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
    fileSize: fileRecord.size, fileUrl: fileUrl,
    createdAt: new Date().toISOString()
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

// ── ADMIN ─────────────────────────────────────────────────────────
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

app.get('/api/admin/stats', adminAuth, (req, res) => {
  res.json({
    users: db.get('users').size().value(),
    messages: db.get('messages').size().value(),
    files: db.get('files').size().value(),
    totalSize: db.get('files').sumBy('size').value()
  });
});

app.listen(PORT, () => console.log(`NoteChat API running on port ${PORT}`));
