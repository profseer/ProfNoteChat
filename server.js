/***
 * ProfNoteChat — Production Server
 * Stack: Express + NeDB (fast embedded DB) + Socket.io (realtime) + Multer
 * NeDB = MongoDB-like API, 10-100x faster than lowdb, no compilation needed
 */

const express    = require('express');
const http       = require('http');
const { Server } = require('socket.io');
const bcrypt     = require('bcryptjs');
const jwt        = require('jsonwebtoken');
const multer     = require('multer');
const cors       = require('cors');
const path       = require('path');
const fs         = require('fs');
const { v4: uuidv4 } = require('uuid');
const Datastore  = require('nedb');

const app    = express();
const server = http.createServer(app);
const io     = new Server(server, { cors: { origin: '*' } });

const PORT       = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'profnotechat_secret_2024';

// ══ DATABASE SETUP (NeDB — embedded, fast, persistent) ══════════
const DB_DIR = './db';
if (!fs.existsSync(DB_DIR)) fs.mkdirSync(DB_DIR, { recursive: true });

const db = {
  users:     new Datastore({ filename: `${DB_DIR}/users.db`,     autoload: true }),
  messages:  new Datastore({ filename: `${DB_DIR}/messages.db`,  autoload: true }),
  files:     new Datastore({ filename: `${DB_DIR}/files.db`,     autoload: true }),
  shares:    new Datastore({ filename: `${DB_DIR}/shares.db`,    autoload: true }),
  tags:      new Datastore({ filename: `${DB_DIR}/tags.db`,      autoload: true }),
  reactions: new Datastore({ filename: `${DB_DIR}/reactions.db`, autoload: true }),
  folders:   new Datastore({ filename: `${DB_DIR}/folders.db`,   autoload: true }),
};

// Indexes for performance
db.users.ensureIndex({ fieldName: 'username', unique: true });
db.users.ensureIndex({ fieldName: 'email',    unique: true });
db.messages.ensureIndex({ fieldName: 'userId' });
db.files.ensureIndex({ fieldName: 'userId' });
db.shares.ensureIndex({ fieldName: 'shareId', unique: true });
db.tags.ensureIndex({ fieldName: 'userId' });
db.reactions.ensureIndex({ fieldName: 'messageId' });
db.folders.ensureIndex({ fieldName: 'userId' });

// NeDB promise wrappers
const dbFind    = (col, q={}, sort={}, lim=0)   => new Promise((res,rej) => { let c=col.find(q); if(Object.keys(sort).length)c=c.sort(sort); if(lim)c=c.limit(lim); c.exec((e,d)=>e?rej(e):res(d)); });
const dbFindOne = (col, q={})                   => new Promise((res,rej) => col.findOne(q,(e,d)=>e?rej(e):res(d)));
const dbInsert  = (col, doc)                    => new Promise((res,rej) => col.insert(doc,(e,d)=>e?rej(e):res(d)));
const dbUpdate  = (col, q, upd, opts={})        => new Promise((res,rej) => col.update(q,upd,opts,(e,n)=>e?rej(e):res(n)));
const dbRemove  = (col, q, opts={multi:true})   => new Promise((res,rej) => col.remove(q,opts,(e,n)=>e?rej(e):res(n)));
const dbCount   = (col, q={})                   => new Promise((res,rej) => col.count(q,(e,n)=>e?rej(e):res(n)));

// Compact DB periodically (keeps file size lean)
setInterval(() => { Object.values(db).forEach(d => d.persistence.compactDatafile()); }, 3600000);

// App-wide config (persisted in DB as key-value)
const appConfig = {
  maxFileMB: 50, maxFileCount: 10,
  imgCompress: false, imgQuality: 75,
  showUploadToUsers: false, adminExempt: true, applyTo: 'all',
};
// Load from DB
dbFindOne(db.users, { __config: true }).then(cfg => { if (cfg) Object.assign(appConfig, cfg); }).catch(() => {});

// ══ FILE UPLOADS ════════════════════════════════════════════════
const UPLOADS_DIR = './uploads';
if (!fs.existsSync(UPLOADS_DIR)) fs.mkdirSync(UPLOADS_DIR, { recursive: true });

const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, UPLOADS_DIR),
  filename:    (req, file, cb) => cb(null, uuidv4() + path.extname(
    Buffer.from(file.originalname, 'latin1').toString('utf8')
  ))
});
// Load saved config from DB on startup
db.users.findOne({ __config: true }, (err, doc) => {
  if (!err && doc) {
    ['maxFileMB','maxFileCount','imgCompress','imgQuality',
     'showUploadToUsers','adminExempt','applyTo'].forEach(k => {
      if (doc[k] != null) appConfig[k] = doc[k];
    });
    console.log('Config loaded from DB:', appConfig);
  }
});

// Dynamic upload with current maxFileMB
function getUpload(){
  return multer({
    storage,
    limits: { fileSize: (appConfig.maxFileMB || 50) * 1024 * 1024 },
    fileFilter: (req, file, cb) => cb(null, true)
  });
}
const upload = { single: (field) => (req,res,next) => getUpload().single(field)(req,res,next) };

// ══ MIDDLEWARE ══════════════════════════════════════════════════
app.use(cors({
  origin: [
    'https://mohamadysons.com',
    'https://www.mohamadysons.com',
    'http://localhost:3000',
    /\.mohamadysons\.com$/,
    // Allow extension
    /^chrome-extension:/,
    /^moz-extension:/
  ],
  credentials: true
}));
app.use(express.json({ limit: '10mb' }));
app.use('/uploads', express.static(UPLOADS_DIR));

// ══ HELPERS ═════════════════════════════════════════════════════
const decodeFilename = name => {
  try { return decodeURIComponent(Buffer.from(name, 'latin1').toString('utf8')); }
  catch { try { return Buffer.from(name, 'latin1').toString('utf8'); } catch { return name; } }
};

const buildFileUrl = (req, filename) => {
  const host  = req.headers['x-forwarded-host'] || req.headers.host;
  const proto = req.headers['x-forwarded-proto'] || req.protocol;
  return `${proto}://${host}/uploads/${filename}`;
};

// ══ AUTH MIDDLEWARE ══════════════════════════════════════════════
const auth = async (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'No token' });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    // Track lastSeen (non-blocking)
    dbUpdate(db.users, { _id: req.user.id }, { $set: { lastSeen: new Date() } }).catch(() => {});
    next();
  } catch { res.status(401).json({ error: 'Invalid token' }); }
};

const adminAuth = async (req, res, next) => {
  await auth(req, res, async () => {
    const user = await dbFindOne(db.users, { _id: req.user.id });
    if (!user?.isAdmin) return res.status(403).json({ error: 'Admin only' });
    next();
  });
};

// ══ SOCKET.IO — REALTIME ════════════════════════════════════════
const userSockets = new Map(); // userId → Set of socket ids

io.use((socket, next) => {
  const token = socket.handshake.auth.token;
  if (!token) return next(new Error('No token'));
  try {
    socket.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch { next(new Error('Invalid token')); }
});

io.on('connection', socket => {
  const uid = socket.user.id;
  if (!userSockets.has(uid)) userSockets.set(uid, new Set());
  userSockets.get(uid).add(socket.id);
  socket.join(`user:${uid}`);
  socket.join('global'); // admin room

  socket.on('disconnect', () => {
    userSockets.get(uid)?.delete(socket.id);
    dbUpdate(db.users, { _id: uid }, { $set: { lastSeen: new Date() } }).catch(() => {});
  });
});

// Emit to specific user
const emitToUser = (userId, event, data) => io.to(`user:${userId}`).emit(event, data);
// Emit to all
const emitAll    = (event, data)         => io.to('global').emit(event, data);

// ══════════════════════════════════════════════════════════════
// ROUTES
// ══════════════════════════════════════════════════════════════

app.get('/', (req, res) => res.json({ status: 'ProfNoteChat API ✓', realtime: true, db: 'NeDB' }));

// ── Has-admin (public) ────────────────────────────────────────
app.get('/api/has-admin', async (req, res) => {
  const admin = await dbFindOne(db.users, { isAdmin: true });
  res.json({ hasAdmin: !!admin });
});

// ── Register ──────────────────────────────────────────────────
app.post('/api/register', async (req, res) => {
  try {
    const { username, email, password } = req.body;
    if (!username || !email || !password)
      return res.status(400).json({ error: 'جميع الحقول مطلوبة' });

    const existing = await dbFindOne(db.users, { $or: [{ email }, { username }] });
    if (existing) return res.status(409).json({ error: 'اسم المستخدم أو البريد مستخدم بالفعل' });

    const adminCount = await dbCount(db.users, { isAdmin: true });
    const hash = await bcrypt.hash(password, 10);
    const user = {
      _id: uuidv4(), username, email,
      password: hash, isAdmin: adminCount === 0,
      active: true, createdAt: new Date(),
      lastSeen: new Date()
    };
    await dbInsert(db.users, user);
    const token = jwt.sign({ id: user._id, username, email, isAdmin: user.isAdmin }, JWT_SECRET, { expiresIn: '30d' });
    res.json({ token, user: { id: user._id, username, email, isAdmin: user.isAdmin } });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── Login (by username OR email) ─────────────────────────────
app.post('/api/login', async (req, res) => {
  try {
    const { username, email, password } = req.body;
    const loginId = username || email;
    if (!loginId) return res.status(400).json({ error: 'اسم المستخدم مطلوب' });
    const user = await dbFindOne(db.users, { $or: [{ username: loginId }, { email: loginId }] });
    if (!user)         return res.status(401).json({ error: 'اسم المستخدم أو كلمة المرور غير صحيحة' });
    if (!user.active)  return res.status(403).json({ error: 'الحساب معطّل' });
    if (!await bcrypt.compare(password, user.password))
      return res.status(401).json({ error: 'اسم المستخدم أو كلمة المرور غير صحيحة' });
    await dbUpdate(db.users, { _id: user._id }, { $set: { lastSeen: new Date() } });
    const token = jwt.sign({ id: user._id, username: user.username, email: user.email, isAdmin: user.isAdmin }, JWT_SECRET, { expiresIn: '30d' });
    res.json({ token, user: { id: user._id, username: user.username, email: user.email, isAdmin: user.isAdmin } });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── Me ────────────────────────────────────────────────────────
app.get('/api/me', auth, async (req, res) => {
  const u = await dbFindOne(db.users, { _id: req.user.id });
  if (!u) return res.status(404).json({ error: 'Not found' });
  res.json({ id: u._id, username: u.username, email: u.email, isAdmin: u.isAdmin });
});

// ── Messages ──────────────────────────────────────────────────
app.get('/api/messages', auth, async (req, res) => {
  const { q, type } = req.query;
  let query = { userId: req.user.id };
  if (type && type !== 'all') query.type = type;
  let msgs = await dbFind(db.messages, query, { createdAt: 1 });
  if (q) {
    const ql = q.toLowerCase();
    msgs = msgs.filter(m => m.text?.toLowerCase().includes(ql) || m.fileName?.toLowerCase().includes(ql));
  }
  res.json(msgs);
});

app.post('/api/messages', auth, async (req, res) => {
  try {
    const { text } = req.body;
    if (!text?.trim()) return res.status(400).json({ error: 'النص مطلوب' });
    const msg = {
      _id: uuidv4(), userId: req.user.id, username: req.user.username,
      text: text.trim(), type: 'text', createdAt: new Date()
    };
    await dbInsert(db.messages, msg);
    // Realtime: emit to user
    emitToUser(req.user.id, 'message:new', msg);
    res.json(msg);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.patch('/api/messages/:id', auth, async (req, res) => {
  try {
    const { text } = req.body;
    if (!text?.trim()) return res.status(400).json({ error: 'النص مطلوب' });
    const msg = await dbFindOne(db.messages, { $or: [
      { _id: req.params.id, userId: req.user.id },
      { id:  req.params.id, userId: req.user.id }
    ]});
    if (!msg) return res.status(404).json({ error: 'غير موجود' });
    await dbUpdate(db.messages, { _id: msg._id }, { $set: { text: text.trim(), edited: true, editedAt: new Date() } });
    emitToUser(req.user.id, 'message:edit', { id: req.params.id, text: text.trim() });
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/messages/:id', auth, async (req, res) => {
  try {
    const msg = await dbFindOne(db.messages, { $or: [
      { _id: req.params.id, userId: req.user.id },
      { id:  req.params.id, userId: req.user.id }
    ]});
    if (!msg) return res.status(404).json({ error: 'غير موجود' });
    if (msg.fileId) {
      const file = await dbFindOne(db.files, { _id: msg.fileId });
      if (file) {
        try { fs.unlinkSync(path.join(UPLOADS_DIR, file.storedName)); } catch {}
        await dbRemove(db.files, { _id: file._id }, { multi: false });
      }
    }
    await dbRemove(db.messages, { _id: msg._id }, { multi: false });
    emitToUser(req.user.id, 'message:delete', { id: req.params.id });
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── File Upload ───────────────────────────────────────────────
app.post('/api/upload', auth, upload.single('file'), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ error: 'لا يوجد ملف' });
    const originalName = decodeFilename(req.file.originalname);
    const fileUrl      = buildFileUrl(req, req.file.filename);
    const fileRecord   = {
      _id: uuidv4(), userId: req.user.id,
      originalName, storedName: req.file.filename,
      mimeType: req.file.mimetype, size: req.file.size,
      url: fileUrl, createdAt: new Date()
    };
    await dbInsert(db.files, fileRecord);
    const msg = {
      _id: uuidv4(), userId: req.user.id, username: req.user.username,
      text: null, type: 'file', fileId: fileRecord._id,
      fileName: originalName, fileMime: req.file.mimetype,
      fileSize: req.file.size, fileUrl, createdAt: new Date()
    };
    await dbInsert(db.messages, msg);
    emitToUser(req.user.id, 'message:new', msg);
    emitToUser(req.user.id, 'file:new', fileRecord);
    res.json({ file: fileRecord, message: msg });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/files', auth, async (req, res) => {
  const { q, type } = req.query;
  let files = await dbFind(db.files, { userId: req.user.id }, { createdAt: -1 });
  if (q) files = files.filter(f => f.originalName?.toLowerCase().includes(q.toLowerCase()));
  if (type && type !== 'all') {
    files = files.filter(f => {
      if (type === 'image') return f.mimeType?.startsWith('image/');
      if (type === 'video') return f.mimeType?.startsWith('video/');
      if (type === 'audio') return f.mimeType?.startsWith('audio/');
      if (type === 'pdf')   return f.mimeType?.includes('pdf');
      return !f.mimeType?.match(/^(image|video|audio)\//) && !f.mimeType?.includes('pdf');
    });
  }
  res.json(files);
});

// ── Share ─────────────────────────────────────────────────────
app.post('/api/share', auth, async (req, res) => {
  try {
    const { messageId } = req.body;
    // Support both _id and id fields for compatibility
    const msg = await dbFindOne(db.messages, { $or: [{ _id: messageId }, { id: messageId }] });
    if (!msg) return res.status(404).json({ error: 'الملاحظة غير موجودة' });
    if (msg.userId !== req.user.id) return res.status(403).json({ error: 'غير مصرح' });
    const existing = await dbFindOne(db.shares, { messageId });
    if (existing) return res.json({ shareId: existing.shareId });
    const shareId = uuidv4().replace(/-/g,'').slice(0,14);
    await dbInsert(db.shares, { shareId, messageId, userId: req.user.id, createdAt: new Date() });
    res.json({ shareId });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/share/:shareId', auth, async (req, res) => {
  await dbRemove(db.shares, { shareId: req.params.shareId, userId: req.user.id }, { multi: false });
  res.json({ ok: true });
});

// Public share page
app.get('/share/:shareId', async (req, res) => {
  const share = await dbFindOne(db.shares, { shareId: req.params.shareId });
  if (!share) return res.status(404).send(shareNotFound());
  const msg  = await dbFindOne(db.messages, { _id: share.messageId });
  if (!msg)  return res.status(404).send(shareNotFound());
  const user = await dbFindOne(db.users,    { _id: msg.userId });
  const name = user?.username || 'مستخدم';
  const date = new Date(msg.createdAt).toLocaleDateString('ar', { year:'numeric', month:'long', day:'numeric' });
  let content = '';
  if (msg.type==='text') {
    const isTodo = msg.text?.startsWith('📋TODO:');
    if (isTodo) {
      try {
        const td = JSON.parse(msg.text.slice('📋TODO:'.length));
        const done = td.items.filter(i=>i.done).length;
        const items = td.items.map(it => `<div style="display:flex;gap:10px;align-items:flex-start;padding:6px 0;"><div style="width:18px;height:18px;border-radius:5px;border:1.5px solid ${it.done?'#00a878':'#ccc'};background:${it.done?'#00a878':'transparent'};flex-shrink:0;display:flex;align-items:center;justify-content:center;margin-top:1px;">${it.done?'<svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="#fff" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"/></svg>':''}</div><span style="${it.done?'text-decoration:line-through;opacity:.5;':''}">${it.text.replace(/&/g,'&amp;').replace(/</g,'&lt;')}</span></div>`).join('');
        content = `<div style="background:#f5f8ff;border-radius:14px;padding:16px 18px;"><div style="font-size:.82rem;font-weight:800;color:#4472ee;margin-bottom:12px;">☑️ ${td.title||'قائمة مهام'} <span style="background:#e8eefb;border-radius:99px;padding:2px 8px;">${done}/${td.items.length}</span></div>${items}</div>`;
      } catch { content = `<p class="nt">${(msg.text||'').replace(/&/g,'&amp;').replace(/</g,'&lt;')}</p>`; }
    } else {
      content = `<p class="nt">${(msg.text||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/\n/g,'<br>')}</p>`;
    }
  }
  else if (msg.fileMime?.startsWith('image/')||msg.type==='drawing') content=`<img src="${msg.fileUrl}" style="max-width:100%;border-radius:16px;box-shadow:0 8px 32px rgba(0,0,0,.12)"/>`;
  else if (msg.type==='audio') content=`<audio controls src="${msg.fileUrl}" style="width:100%"></audio>`;
  else if (msg.fileMime?.startsWith('video/')) content=`<video controls src="${msg.fileUrl}" style="max-width:100%;border-radius:12px"></video>`;
  else if (msg.fileUrl) content=`<a href="${msg.fileUrl}" download style="display:inline-flex;align-items:center;gap:12px;padding:16px 24px;background:#f0f4ff;border-radius:14px;text-decoration:none;color:#1a2040;font-weight:700">📎 ${msg.fileName||'ملف'}</a>`;
  res.send(sharePageHTML(name, date, content));
});

// ══ ADMIN ROUTES ══════════════════════════════════════════════
app.get('/api/admin/stats', adminAuth, async (req, res) => {
  const [users, messages, files] = await Promise.all([
    dbCount(db.users),
    dbCount(db.messages),
    dbCount(db.files)
  ]);
  const allFiles = await dbFind(db.files, {});
  const totalSize = allFiles.reduce((s,f) => s + (f.size||0), 0);
  const activeToday = await dbCount(db.users, {
    lastSeen: { $gt: new Date(Date.now() - 86400000) }
  });
  res.json({ users, messages, files, totalSize, activeToday });
});

app.get('/api/admin/users', adminAuth, async (req, res) => {
  const users = await dbFind(db.users, {}, { createdAt: 1 });
  const result = await Promise.all(users.map(async u => ({
    id: u._id, username: u.username, email: u.email,
    isAdmin: u.isAdmin, active: u.active,
    createdAt: u.createdAt, lastSeen: u.lastSeen,
    msgCount:  await dbCount(db.messages, { userId: u._id }),
    fileCount: await dbCount(db.files,    { userId: u._id })
  })));
  res.json(result);
});

app.patch('/api/admin/users/:id', adminAuth, async (req, res) => {
  const { active, isAdmin } = req.body;
  if (req.params.id === req.user.id) return res.status(400).json({ error: 'لا يمكن تعديل نفسك' });
  const upd = {};
  if (active   !== undefined) upd.active  = active;
  if (isAdmin  !== undefined) upd.isAdmin = isAdmin;
  await dbUpdate(db.users, { _id: req.params.id }, { $set: upd });
  res.json({ ok: true });
});

app.delete('/api/admin/users/:id', adminAuth, async (req, res) => {
  if (req.params.id === req.user.id) return res.status(400).json({ error: 'لا يمكن حذف نفسك' });
  const files = await dbFind(db.files, { userId: req.params.id });
  files.forEach(f => { try { fs.unlinkSync(path.join(UPLOADS_DIR, f.storedName)); } catch {} });
  await Promise.all([
    dbRemove(db.files,    { userId: req.params.id }),
    dbRemove(db.messages, { userId: req.params.id }),
    dbRemove(db.users,    { _id:    req.params.id }, { multi: false })
  ]);
  res.json({ ok: true });
});

app.delete('/api/admin/users/:id/messages', adminAuth, async (req, res) => {
  await dbRemove(db.messages, { userId: req.params.id });
  res.json({ ok: true });
});

app.delete('/api/admin/users/:id/files', adminAuth, async (req, res) => {
  const files = await dbFind(db.files, { userId: req.params.id });
  files.forEach(f => { try { fs.unlinkSync(path.join(UPLOADS_DIR, f.storedName)); } catch {} });
  await Promise.all([
    dbRemove(db.files,    { userId: req.params.id }),
    dbRemove(db.messages, { userId: req.params.id, type: 'file' })
  ]);
  res.json({ ok: true });
});

app.get('/api/admin/users/:id/messages', adminAuth, async (req, res) => {
  const msgs = await dbFind(db.messages, { userId: req.params.id }, { createdAt: 1 });
  res.json(msgs);
});

app.get('/api/admin/users/:id/files', adminAuth, async (req, res) => {
  const files = await dbFind(db.files, { userId: req.params.id }, { createdAt: -1 });
  res.json(files);
});

app.get('/api/admin/settings', adminAuth, async (req, res) => {
  res.json({
    maxFileMB: appConfig.maxFileMB || 50,
    maxFileCount: appConfig.maxFileCount || 10,
    imgCompress: !!appConfig.imgCompress,
    imgQuality: appConfig.imgQuality || 75,
    showUploadToUsers: !!appConfig.showUploadToUsers,
    adminExempt: appConfig.adminExempt !== false,
    applyTo: appConfig.applyTo || 'all',
  });
});

app.patch('/api/admin/settings', adminAuth, async (req, res) => {
  const b = req.body;
  if (b.maxFileMB    != null && b.maxFileMB >= 1 && b.maxFileMB <= 200)   appConfig.maxFileMB    = b.maxFileMB;
  if (b.maxFileCount != null && b.maxFileCount >= 1 && b.maxFileCount <= 50) appConfig.maxFileCount = b.maxFileCount;
  if (b.imgCompress  != null) appConfig.imgCompress       = !!b.imgCompress;
  if (b.imgQuality   != null && b.imgQuality >= 20 && b.imgQuality <= 95)  appConfig.imgQuality   = b.imgQuality;
  if (b.showUploadToUsers != null) appConfig.showUploadToUsers = !!b.showUploadToUsers;
  if (b.adminExempt  != null) appConfig.adminExempt        = !!b.adminExempt;
  if (b.applyTo      != null && ['all','users'].includes(b.applyTo)) appConfig.applyTo = b.applyTo;
  // Persist to DB
  dbRemove(db.users, { __config: true })
    .then(() => dbInsert(db.users, { __config: true, ...appConfig }))
    .catch(() => {});
  res.json({ ok: true, ...appConfig });
});

// Delete own account
app.delete('/api/me', auth, async (req, res) => {
  try {
    const uid = req.user.id;
    const u = await dbFindOne(db.users, { _id: uid });
    if (!u) return res.status(404).json({ error: 'المستخدم غير موجود' });
    // Delete all user data
    const files = await dbFind(db.files, { userId: uid });
    files.forEach(f => { try { require('fs').unlinkSync(require('path').join(UPLOADS_DIR, f.storedName)); } catch {} });
    await Promise.all([
      dbRemove(db.files, { userId: uid }),
      dbRemove(db.messages, { userId: uid }),
      dbRemove(db.shares, { userId: uid }),
      dbRemove(db.users, { _id: uid }, { multi: false })
    ]);
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// Clear own messages
app.delete('/api/me/messages', auth, async (req, res) => {
  await dbRemove(db.messages, { userId: req.user.id });
  res.json({ ok: true });
});

// Clear own files  
app.delete('/api/me/files', auth, async (req, res) => {
  const files = await dbFind(db.files, { userId: req.user.id });
  files.forEach(f => { try { require('fs').unlinkSync(require('path').join(UPLOADS_DIR, f.storedName)); } catch {} });
  await Promise.all([
    dbRemove(db.files, { userId: req.user.id }),
    dbRemove(db.messages, { userId: req.user.id, type: 'file' })
  ]);
  res.json({ ok: true });
});

// ══ PIN / UNPIN ══════════════════════════════════════════════
app.patch('/api/messages/:id/pin', auth, async (req, res) => {
  try {
    const msg = await dbFindOne(db.messages, { _id: req.params.id, userId: req.user.id });
    if (!msg) return res.status(404).json({ error: 'غير موجود' });
    const pinned = !msg.pinned;
    await dbUpdate(db.messages, { _id: msg._id }, { $set: { pinned } });
    emitToUser(req.user.id, 'message:pin', { id: req.params.id, pinned });
    res.json({ ok: true, pinned });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ══ TAGS ══════════════════════════════════════════════════════
app.get('/api/tags', auth, async (req, res) => {
  const tags = await dbFind(db.tags, { userId: req.user.id }, { createdAt: 1 });
  res.json(tags);
});
app.post('/api/tags', auth, async (req, res) => {
  try {
    const { name, color } = req.body;
    if (!name?.trim()) return res.status(400).json({ error: 'الاسم مطلوب' });
    const existing = await dbFindOne(db.tags, { userId: req.user.id, name: name.trim() });
    if (existing) return res.status(409).json({ error: 'الوسم موجود بالفعل' });
    const tag = { _id: uuidv4(), userId: req.user.id, name: name.trim(), color: color || '#4f7cff', createdAt: new Date() };
    await dbInsert(db.tags, tag);
    res.json(tag);
  } catch(e) { res.status(500).json({ error: e.message }); }
});
app.delete('/api/tags/:id', auth, async (req, res) => {
  await dbRemove(db.tags, { _id: req.params.id, userId: req.user.id }, { multi: false });
  // Remove tag from all messages
  await dbUpdate(db.messages, { userId: req.user.id, tags: { $elemMatch: req.params.id } }, { $pull: { tags: req.params.id } }, { multi: true });
  res.json({ ok: true });
});
app.patch('/api/messages/:id/tags', auth, async (req, res) => {
  try {
    const { tags } = req.body; // array of tag ids
    const msg = await dbFindOne(db.messages, { _id: req.params.id, userId: req.user.id });
    if (!msg) return res.status(404).json({ error: 'غير موجود' });
    await dbUpdate(db.messages, { _id: msg._id }, { $set: { tags: tags || [] } });
    emitToUser(req.user.id, 'message:tags', { id: req.params.id, tags });
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ══ REACTIONS ═════════════════════════════════════════════════
app.get('/api/messages/:id/reactions', auth, async (req, res) => {
  const reactions = await dbFind(db.reactions, { messageId: req.params.id, userId: req.user.id });
  res.json(reactions);
});
app.post('/api/messages/:id/reactions', auth, async (req, res) => {
  try {
    const { emoji } = req.body;
    if (!emoji) return res.status(400).json({ error: 'emoji مطلوب' });
    const existing = await dbFindOne(db.reactions, { messageId: req.params.id, userId: req.user.id, emoji });
    if (existing) {
      await dbRemove(db.reactions, { _id: existing._id }, { multi: false });
      emitToUser(req.user.id, 'reaction:remove', { messageId: req.params.id, emoji });
      return res.json({ ok: true, action: 'removed' });
    }
    const r = { _id: uuidv4(), messageId: req.params.id, userId: req.user.id, emoji, createdAt: new Date() };
    await dbInsert(db.reactions, r);
    emitToUser(req.user.id, 'reaction:add', { messageId: req.params.id, emoji });
    res.json({ ok: true, action: 'added' });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ══ FOLDERS ═══════════════════════════════════════════════════
app.get('/api/folders', auth, async (req, res) => {
  const folders = await dbFind(db.folders, { userId: req.user.id }, { createdAt: 1 });
  res.json(folders);
});
app.post('/api/folders', auth, async (req, res) => {
  try {
    const { name, icon, color } = req.body;
    if (!name?.trim()) return res.status(400).json({ error: 'الاسم مطلوب' });
    const folder = { _id: uuidv4(), userId: req.user.id, name: name.trim(), icon: icon || '📁', color: color || '#4f7cff', createdAt: new Date() };
    await dbInsert(db.folders, folder);
    res.json(folder);
  } catch(e) { res.status(500).json({ error: e.message }); }
});
app.patch('/api/folders/:id', auth, async (req, res) => {
  const { name, icon, color } = req.body;
  await dbUpdate(db.folders, { _id: req.params.id, userId: req.user.id }, { $set: { name, icon, color } });
  res.json({ ok: true });
});
app.delete('/api/folders/:id', auth, async (req, res) => {
  await dbRemove(db.folders, { _id: req.params.id, userId: req.user.id }, { multi: false });
  await dbUpdate(db.messages, { userId: req.user.id, folderId: req.params.id }, { $unset: { folderId: true } }, { multi: true });
  res.json({ ok: true });
});
app.patch('/api/messages/:id/folder', auth, async (req, res) => {
  try {
    const { folderId } = req.body;
    const msg = await dbFindOne(db.messages, { _id: req.params.id, userId: req.user.id });
    if (!msg) return res.status(404).json({ error: 'غير موجود' });
    const update = folderId ? { $set: { folderId } } : { $unset: { folderId: true } };
    await dbUpdate(db.messages, { _id: msg._id }, update);
    emitToUser(req.user.id, 'message:folder', { id: req.params.id, folderId });
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ══ REACTIONS BULK (load all reactions for user messages) ══════
app.get('/api/reactions', auth, async (req, res) => {
  const reactions = await dbFind(db.reactions, { userId: req.user.id });
  // Group by messageId
  const grouped = {};
  reactions.forEach(r => {
    if (!grouped[r.messageId]) grouped[r.messageId] = [];
    grouped[r.messageId].push(r.emoji);
  });
  res.json(grouped);
});

app.post('/api/admin/broadcast', adminAuth, async (req, res) => {
  try {
    const { text } = req.body;
    if (!text?.trim()) return res.status(400).json({ error: 'النص مطلوب' });
    const users = await dbFind(db.users, {});
    const msgs  = users.map(u => ({
      _id: uuidv4(), userId: u._id, username: '📢 النظام',
      text: text.trim(), type: 'text', system: true, createdAt: new Date()
    }));
    await Promise.all(msgs.map(m => dbInsert(db.messages, m)));
    // Realtime broadcast
    msgs.forEach(m => emitToUser(m.userId, 'message:new', m));
    res.json({ ok: true, count: users.length });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/admin/storage', adminAuth, async (req, res) => {
  const files = await dbFind(db.files, {}, { size: -1 });
  const result = await Promise.all(files.map(async f => {
    const user = await dbFindOne(db.users, { _id: f.userId });
    return { ...f, ownerName: user?.username||'محذوف', ownerEmail: user?.email||'' };
  }));
  res.json(result);
});

// ══ SHARE PAGE HTML ══════════════════════════════════════════
function shareNotFound() {
  return `<!DOCTYPE html><html lang="ar" dir="rtl"><head><meta charset="UTF-8"/><title>رابط منتهي</title><link href="https://fonts.googleapis.com/css2?family=Cairo:wght@700&display=swap" rel="stylesheet"/><style>body{font-family:'Cairo',sans-serif;display:flex;align-items:center;justify-content:center;min-height:100vh;background:#f0f4ff;margin:0}.c{text-align:center;padding:48px;background:#fff;border-radius:24px;box-shadow:0 8px 40px rgba(79,124,255,.14)}</style></head><body><div class="c"><div style="font-size:3rem">🔗</div><h2 style="margin-top:12px;color:#1a2040">هذا الرابط غير موجود</h2></div></body></html>`;
}

function sharePageHTML(name, date, content) {
  return `<!DOCTYPE html><html lang="ar" dir="rtl"><head><meta charset="UTF-8"/><meta name="viewport" content="width=device-width,initial-scale=1"/><title>ملاحظة - ProfNoteChat</title><link href="https://fonts.googleapis.com/css2?family=Cairo:wght@400;600;700;800&display=swap" rel="stylesheet"/><style>*{margin:0;padding:0;box-sizing:border-box}body{font-family:'Cairo',sans-serif;background:#f0f4ff;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:20px}.card{background:#fff;border-radius:24px;padding:36px;max-width:620px;width:100%;box-shadow:0 8px 40px rgba(79,124,255,.14)}.brand{display:flex;align-items:center;gap:10px;margin-bottom:24px;padding-bottom:20px;border-bottom:1px solid #e8edf8}.bic{width:36px;height:36px;border-radius:10px;background:linear-gradient(135deg,#3a5fd4,#7c9fff);display:flex;align-items:center;justify-content:center;flex-shrink:0}.bnm{font-size:1.1rem;font-weight:900;background:linear-gradient(135deg,#1a2040,#4f7cff);-webkit-background-clip:text;-webkit-text-fill-color:transparent}.meta{font-size:.82rem;color:#8a95b4;margin-bottom:20px}.nt{font-size:1.05rem;line-height:1.75;color:#1a2040;font-weight:500;white-space:pre-wrap}.ft{font-size:.78rem;color:#9aa3be;text-align:center;padding-top:16px;border-top:1px solid #e8edf8;margin-top:24px}.cta{display:inline-block;margin-top:14px;padding:10px 22px;background:linear-gradient(135deg,#3a5fd4,#4f7cff);color:#fff;border-radius:10px;text-decoration:none;font-weight:700;font-size:.88rem}</style></head><body><div class="card"><div class="brand"><div class="bic"><svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#fff" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 20h9"/><path d="M16.5 3.5a2.121 2.121 0 013 3L7 19l-4 1 1-4L16.5 3.5z"/></svg></div><span class="bnm">ProfNoteChat</span></div><div class="meta">✍️ ${name} &nbsp;·&nbsp; 📅 ${date}</div><div>${content}</div><div class="ft">تمت المشاركة عبر ProfNoteChat<br><a href="https://mohamadysons.com/prof/notes/" class="cta">انشئ ملاحظاتك →</a></div></div></body></html>`;
}

// ══ START ═════════════════════════════════════════════════════
server.listen(PORT, () => {
  console.log(`✅ ProfNoteChat running on port ${PORT}`);
  console.log(`📦 Database: NeDB (embedded, fast)`);
  console.log(`⚡ Realtime: Socket.io`);
});
