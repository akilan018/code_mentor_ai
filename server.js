require('dotenv').config();

const express     = require('express');
const session     = require('express-session');
const bcrypt      = require('bcryptjs');
const { v4: uuidv4 } = require('uuid');
const path        = require('path');
const https       = require('https');
const mongoose    = require('mongoose');
const helmet      = require('helmet');
const rateLimit   = require('express-rate-limit');

const app = express();
app.set('trust proxy', 1);
const PORT = process.env.PORT || 3000;

/* ── GEMINI KEY ROTATION ── */
const GEMINI_KEYS = [
  process.env.GEMINI_API_KEY_1,
  process.env.GEMINI_API_KEY_2,
  process.env.GEMINI_API_KEY_3,
  process.env.GEMINI_API_KEY_4,
  process.env.GEMINI_API_KEY_5,
  process.env.GEMINI_API_KEY,
].filter(Boolean);

let geminiKeyIndex = 0;
function getGeminiKey() {
  if (!GEMINI_KEYS.length) return null;
  const key = GEMINI_KEYS[geminiKeyIndex];
  geminiKeyIndex = (geminiKeyIndex + 1) % GEMINI_KEYS.length;
  return key;
}

const BREVO_KEY    = process.env.BREVO_API_KEY || '';
const SENDER_EMAIL = process.env.SENDER_EMAIL  || '';
const SENDER_NAME  = process.env.SENDER_NAME   || 'CodeMentor AI';
const FAST2SMS_KEY = process.env.FAST2SMS_KEY  || '';

/* ── MONGODB ── */
mongoose.connect(process.env.MONGODB_URI)
  .then(() => console.log('✅  MongoDB connected'))
  .catch(err => { console.error('❌  MongoDB error:', err.message); process.exit(1); });

/* ── SCHEMAS ── */
const userSchema = new mongoose.Schema({
  id:             { type: String, default: () => uuidv4() },
  userId:         { type: String, required: true, unique: true, lowercase: true },
  name:           { type: String, required: true },
  email:          { type: String, default: '' },
  phone:          { type: String, default: '' },
  password:       { type: String, required: true },
  passwordHistory:{ type: [String], default: [] },
  role:           { type: String, enum: ['admin','user'], default: 'user' },
  verified:       { type: Boolean, default: false },
  method:         { type: String, default: 'email' },
  securityAnswer: { type: String, default: '' },
  joined:         { type: Number, default: Date.now },
  lastSeen:       { type: Number, default: Date.now }
});
const User = mongoose.model('User', userSchema);

const chatSchema = new mongoose.Schema({
  chatId:   { type: String, default: () => uuidv4() },
  ownerId:  { type: String, required: true },
  title:    { type: String, default: 'New Chat' },
  ts:       { type: Number, default: Date.now },
  history:  { type: mongoose.Schema.Types.Mixed, default: [] },
  rendered: { type: mongoose.Schema.Types.Mixed, default: [] }
});
const Chat = mongoose.model('Chat', chatSchema);

const otpStore = new Map();

/* ── SEED ADMIN ── */
async function seedAdmin() {
  try {
    const adminPwd = process.env.ADMIN_PASSWORD;
    const exists   = await User.findOne({ userId: 'admin' });
    if (!exists) {
      const password = adminPwd || 'Admin@123!';
      const hashed   = await bcrypt.hash(password, 10);
      await User.create({
        userId: 'admin', name: 'Admin',
        email: 'admin@codementor.ai', phone: '',
        password: hashed, passwordHistory: [hashed],
        role: 'admin', verified: true, method: 'email',
        securityAnswer: await bcrypt.hash('codementor', 10)
      });
      console.log(`✅  Admin created  |  admin / ${password}`);
    } else if (adminPwd) {
      const match = await bcrypt.compare(adminPwd, exists.password);
      if (!match) {
        exists.password = await bcrypt.hash(adminPwd, 10);
        exists.passwordHistory = [exists.password];
        await exists.save();
        console.log('✅  Admin password synced');
      }
    }
  } catch(e) { console.error('Seed error:', e.message); }
}

/* ── HELPERS ── */
const safe = u => {
  const o = u.toObject ? u.toObject() : { ...u };
  delete o.password; delete o.passwordHistory; delete o.securityAnswer;
  return o;
};

function validatePassword(p) {
  if (p.length < 8)                   return 'Password must be at least 8 characters.';
  if (!/[A-Z]/.test(p))              return 'Need at least one uppercase letter.';
  if (!/[a-z]/.test(p))              return 'Need at least one lowercase letter.';
  if (!/[0-9]/.test(p))              return 'Need at least one number.';
  if (!/[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?`~]/.test(p))
    return 'Need at least one special character.';
  return null;
}

async function isPasswordReused(password, history = []) {
  for (const h of history) if (await bcrypt.compare(password, h)) return true;
  return false;
}

const isMain = (u) => u?.userId === 'admin';

/* ── OTP ── */
const genOTP = () => String(Math.floor(100000 + Math.random() * 900000));

async function sendEmailOTP(to, otp, purpose) {
  if (!BREVO_KEY) { console.log(`📧  [DEV] OTP for ${to} → ${otp}`); return; }
  const body = JSON.stringify({
    sender: { name: SENDER_NAME, email: SENDER_EMAIL },
    to: [{ email: to }],
    subject: purpose === 'register' ? 'CodeMentor AI — Verify Account' : 'CodeMentor AI — Reset Password',
    htmlContent: `<div style="font-family:monospace;background:#0d0d0d;color:#f0ece4;padding:32px;max-width:420px;border-radius:10px">
      <p style="font-size:20px;font-weight:800">&#x26A1; Code<span style="color:#f59e0b">Mentor</span> AI</p>
      <p style="font-size:13px;margin:16px 0">${purpose === 'register' ? 'Verification OTP' : 'Password Reset OTP'}:</p>
      <div style="background:#1a1a1a;border:1px solid #f59e0b44;border-radius:8px;padding:18px;text-align:center">
        <span style="font-size:38px;font-weight:800;letter-spacing:.2em;color:#f59e0b">${otp}</span>
      </div>
      <p style="color:#555;font-size:11px;margin-top:16px">Valid for 10 minutes.</p>
    </div>`
  });
  await new Promise((resolve, reject) => {
    const req = https.request({
      hostname: 'api.brevo.com', path: '/v3/smtp/email', method: 'POST',
      headers: { 'api-key': BREVO_KEY, 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) }
    }, res => {
      let d = ''; res.on('data', c => d += c);
      res.on('end', () => res.statusCode < 300 ? resolve(d) : reject(new Error(`Brevo ${res.statusCode}: ${d}`)));
    });
    req.on('error', reject); req.write(body); req.end();
  });
}

async function sendPhoneOTP(phone, otp) {
  if (!FAST2SMS_KEY) { console.log(`📱  [DEV] OTP for ${phone} → ${otp}`); return; }
  const msg = `Your CodeMentor AI OTP is ${otp}. Valid for 10 minutes.`;
  const url = `https://www.fast2sms.com/dev/bulkV2?authorization=${FAST2SMS_KEY}&route=q&message=${encodeURIComponent(msg)}&language=english&flash=0&numbers=${phone}`;
  await new Promise((res, rej) => {
    https.get(url, { headers: { 'cache-control': 'no-cache' } }, r => {
      let d = ''; r.on('data', c => d += c); r.on('end', () => res(d));
    }).on('error', rej);
  });
}

function storeOTP(key, otp, extra = {}) {
  otpStore.set(key, { otp, expires: Date.now() + 10 * 60 * 1000, ...extra });
}

function checkOTP(key, otp) {
  const r = otpStore.get(key);
  if (!r) return 'No OTP found. Please request again.';
  if (Date.now() > r.expires) { otpStore.delete(key); return 'OTP expired.'; }
  if (r.otp !== String(otp).trim()) return 'Incorrect OTP.';
  const data = { ...r }; otpStore.delete(key); return { ok: true, data };
}

/* ── MIDDLEWARE ── */
app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: '4mb' }));
app.use(express.urlencoded({ extended: true }));

app.use((req, res, next) => {
  const ext = path.extname(req.path).toLowerCase();
  if ((ext === '.js' || ext === '.css') && req.headers['sec-fetch-dest'] === 'document')
    return res.status(403).send('<html><body style="background:#0d0d0d;color:#ef4444;font-family:monospace;padding:40px;text-align:center"><h2>403 Forbidden</h2></body></html>');
  next();
});

app.use(express.static(path.join(__dirname, 'public')));
app.use(session({
  secret: process.env.SESSION_SECRET || 'cm-secret',
  resave: false, saveUninitialized: false,
  cookie: { maxAge: 7 * 24 * 60 * 60 * 1000, httpOnly: true, sameSite: 'strict' }
}));

const authLimiter   = rateLimit({ windowMs: 15*60*1000, max: 30, message: { error: 'Too many requests. Try again in 15 mins.' }, standardHeaders: true, legacyHeaders: false });
const forgotLimiter = rateLimit({ windowMs: 15*60*1000, max: 5,  message: { error: 'Too many reset attempts. Wait 15 mins.' }, standardHeaders: true, legacyHeaders: false });

const auth  = (q, s, n) => q.session.user ? n() : s.status(401).json({ error: 'Not authenticated' });
const admin = (q, s, n) => q.session.user?.role === 'admin' ? n() : s.status(403).json({ error: 'Forbidden' });

/* ── REGISTER ── */
app.post('/api/auth/register/send-otp', authLimiter, async (req, res) => {
  const { userId, name, password, method, contact, securityAnswer } = req.body;
  if (!userId || !name || !password || !method || !contact || !securityAnswer)
    return res.status(400).json({ error: 'All fields are required.' });
  if (!/^[a-zA-Z0-9_]{3,20}$/.test(userId))
    return res.status(400).json({ error: 'User ID: 3-20 chars, letters/numbers/underscore only.' });
  const pwErr = validatePassword(password);
  if (pwErr) return res.status(400).json({ error: pwErr });
  if (method === 'email' && !/\S+@\S+\.\S+/.test(contact))
    return res.status(400).json({ error: 'Enter a valid email address.' });
  if (method === 'phone' && !/^\d{10}$/.test(contact))
    return res.status(400).json({ error: 'Enter a valid 10-digit mobile number.' });

  const key = userId.toLowerCase();
  if (await User.findOne({ userId: key })) return res.status(400).json({ error: 'This User ID is already taken.' });
  const dup = await User.findOne(method === 'email' ? { email: contact } : { phone: contact });
  if (dup) return res.status(400).json({ error: `This ${method} is already registered.` });

  const otp = genOTP();
  storeOTP(`reg_${key}`, otp, { pending: { userId: key, name: name.trim(), password, method, contact, securityAnswer } });
  res.json({ success: true, message: `OTP sent to your ${method}.` });
  if (method === 'email') sendEmailOTP(contact, otp, 'register').catch(e => console.error('OTP err:', e.message));
  else sendPhoneOTP(contact, otp).catch(e => console.error('OTP err:', e.message));
});

app.post('/api/auth/register/verify-otp', authLimiter, async (req, res) => {
  const { userId, otp } = req.body;
  if (!userId || !otp) return res.status(400).json({ error: 'Missing fields.' });
  const key    = userId.toLowerCase();
  const result = checkOTP(`reg_${key}`, otp);
  if (typeof result === 'string') return res.status(400).json({ error: result });
  const { pending } = result.data;
  if (!pending) return res.status(400).json({ error: 'Session expired.' });
  if (await User.findOne({ userId: key })) return res.status(400).json({ error: 'User ID just taken.' });
  const hashed  = await bcrypt.hash(pending.password, 10);
  const secHash = await bcrypt.hash((pending.securityAnswer || '').toLowerCase().trim(), 10);
  const user = await User.create({
    userId: key, name: pending.name,
    email: pending.method === 'email' ? pending.contact : '',
    phone: pending.method === 'phone' ? pending.contact : '',
    password: hashed, passwordHistory: [hashed],
    role: 'user', verified: true, method: pending.method, securityAnswer: secHash
  });
  req.session.user = safe(user);
  res.json({ success: true, user: safe(user) });
});

/* ── LOGIN ── */
app.post('/api/auth/login', authLimiter, async (req, res) => {
  const { userId, password } = req.body;
  if (!userId || !password) return res.status(400).json({ error: 'All fields required.' });
  const user = await User.findOne({ userId: userId.toLowerCase().trim() });
  if (!user || !(await bcrypt.compare(password, user.password)))
    return res.status(401).json({ error: 'Incorrect User ID or password.' });
  user.lastSeen = Date.now(); await user.save();
  req.session.user = safe(user);
  res.json({ success: true, user: safe(user) });
});

app.post('/api/auth/logout', (req, res) => req.session.destroy(() => res.json({ success: true })));
app.get('/api/auth/me', auth, (req, res) => res.json({ user: req.session.user }));

/* ── CHANGE DISPLAY NAME ── */
app.post('/api/auth/change-username', auth, async (req, res) => {
  const { newName } = req.body;
  if (!newName || newName.trim().length < 2) return res.status(400).json({ error: 'Name must be at least 2 characters.' });
  if (newName.trim().length > 40) return res.status(400).json({ error: 'Name must be under 40 characters.' });
  const user = await User.findOne({ userId: req.session.user.userId });
  if (!user) return res.status(404).json({ error: 'User not found.' });
  user.name = newName.trim(); await user.save();
  req.session.user = safe(user);
  res.json({ success: true, name: user.name, message: 'Name updated successfully.' });
});

/* ── CHANGE USER ID ── */
app.post('/api/auth/change-userid', auth, async (req, res) => {
  const { newUserId, password } = req.body;

  // Admin userId cannot be changed
  if (req.session.user.userId === 'admin')
    return res.status(403).json({ error: 'Admin User ID cannot be changed.' });

  if (!newUserId || !password)
    return res.status(400).json({ error: 'New User ID and current password are required.' });
  if (!/^[a-zA-Z0-9_]{3,20}$/.test(newUserId))
    return res.status(400).json({ error: 'User ID: 3-20 chars, letters/numbers/underscore only.' });

  const newKey = newUserId.toLowerCase();
  if (newKey === req.session.user.userId)
    return res.status(400).json({ error: 'This is already your current User ID.' });

  // Check if taken
  const existing = await User.findOne({ userId: newKey });
  if (existing) return res.status(400).json({ error: 'This User ID is already taken.' });

  const user = await User.findOne({ userId: req.session.user.userId });
  if (!user) return res.status(404).json({ error: 'User not found.' });

  // Verify password
  const match = await bcrypt.compare(password, user.password);
  if (!match) return res.status(400).json({ error: 'Incorrect password.' });

  user.userId = newKey; await user.save();
  req.session.user = safe(user);
  res.json({ success: true, userId: user.userId, message: 'User ID updated successfully.' });
});

/* ── FORGOT PASSWORD ── */
app.post('/api/auth/forgot/send-otp', forgotLimiter, async (req, res) => {
  const { userId } = req.body;
  if (!userId) return res.status(400).json({ error: 'User ID is required.' });
  if (userId.toLowerCase().trim() === 'admin')
    return res.status(403).json({ error: 'Admin password cannot be reset here.' });
  const user = await User.findOne({ userId: userId.toLowerCase().trim() });
  if (!user) return res.status(404).json({ error: 'No account found with this User ID.' });
  const otp = genOTP();
  otpStore.set(`fpw_${userId.toLowerCase()}`, { otp, expires: Date.now() + 10 * 60 * 1000 });
  res.json({ success: true, message: 'OTP sent to your registered email.' });
  const contact = user.email || user.phone;
  if (user.method === 'email' || user.email) sendEmailOTP(contact, otp, 'reset').catch(e => console.error('OTP err:', e.message));
  else sendPhoneOTP(contact, otp).catch(e => console.error('OTP err:', e.message));
});

app.post('/api/auth/forgot/verify-otp', forgotLimiter, async (req, res) => {
  const { userId, otp } = req.body;
  if (!userId || !otp) return res.status(400).json({ error: 'User ID and OTP required.' });
  const key = `fpw_${userId.toLowerCase().trim()}`;
  const stored = otpStore.get(key);
  if (!stored) return res.status(400).json({ error: 'No OTP found.' });
  if (Date.now() > stored.expires) { otpStore.delete(key); return res.status(400).json({ error: 'OTP expired.' }); }
  if (stored.otp !== String(otp).trim()) return res.status(400).json({ error: 'Incorrect OTP.' });
  otpStore.delete(key);
  const token = uuidv4();
  otpStore.set(`reset_${userId.toLowerCase()}`, { token, expires: Date.now() + 5 * 60 * 1000 });
  res.json({ success: true, token, message: 'OTP verified.' });
});

app.post('/api/auth/forgot/reset', forgotLimiter, async (req, res) => {
  const { userId, token, newPassword, confirmPassword } = req.body;
  if (!userId || !token || !newPassword || !confirmPassword) return res.status(400).json({ error: 'All fields required.' });
  if (newPassword !== confirmPassword) return res.status(400).json({ error: 'Passwords do not match.' });
  const pwErr = validatePassword(newPassword);
  if (pwErr) return res.status(400).json({ error: pwErr });
  const key = `reset_${userId.toLowerCase()}`;
  const stored = otpStore.get(key);
  if (!stored || stored.token !== token || Date.now() > stored.expires)
    return res.status(400).json({ error: 'Reset session expired.' });
  otpStore.delete(key);
  const user = await User.findOne({ userId: userId.toLowerCase() });
  if (!user) return res.status(404).json({ error: 'No account found.' });
  if (await isPasswordReused(newPassword, user.passwordHistory))
    return res.status(400).json({ error: 'Cannot reuse a recent password.' });
  const hashed = await bcrypt.hash(newPassword, 10);
  user.password = hashed;
  user.passwordHistory = [hashed, ...(user.passwordHistory || [])].slice(0, 5);
  await user.save();
  res.json({ success: true, message: 'Password reset successfully.' });
});

/* ── CHANGE PASSWORD ── */
app.post('/api/auth/change-password', auth, async (req, res) => {
  const { currentPassword, securityAnswer, newPassword, confirmPassword } = req.body;
  if (req.session.user?.userId === 'admin')
    return res.status(403).json({ error: 'Admin password can only be changed via ADMIN_PASSWORD in .env.' });
  if (!currentPassword || !securityAnswer || !newPassword || !confirmPassword)
    return res.status(400).json({ error: 'All fields required.' });
  if (newPassword !== confirmPassword) return res.status(400).json({ error: 'Passwords do not match.' });
  const pwErr = validatePassword(newPassword);
  if (pwErr) return res.status(400).json({ error: pwErr });
  const user = await User.findOne({ userId: req.session.user.userId });
  if (!user) return res.status(404).json({ error: 'User not found.' });
  if (!(await bcrypt.compare(currentPassword, user.password)))
    return res.status(400).json({ error: 'Current password is incorrect.' });
  if (!user.securityAnswer) return res.status(400).json({ error: 'No security question set.' });
  if (!(await bcrypt.compare(securityAnswer.toLowerCase().trim(), user.securityAnswer)))
    return res.status(400).json({ error: 'Incorrect security answer.' });
  if (await isPasswordReused(newPassword, user.passwordHistory))
    return res.status(400).json({ error: 'Cannot reuse a recent password.' });
  const hashed = await bcrypt.hash(newPassword, 10);
  user.password = hashed;
  user.passwordHistory = [hashed, ...(user.passwordHistory || [])].slice(0, 5);
  await user.save();
  res.json({ success: true, message: 'Password updated successfully.' });
});

/* ── CHATS ── */
app.get('/api/chats', auth, async (req, res) => {
  const chats = await Chat.find({ ownerId: req.session.user.id }, { history: 0, rendered: 0 }).sort({ ts: -1 });
  res.json({ chats: chats.map(c => ({ id: c.chatId, title: c.title, ts: c.ts })) });
});
app.post('/api/chats', auth, async (req, res) => {
  const c = await Chat.create({ ownerId: req.session.user.id, title: (req.body.title || 'New Chat').slice(0, 80) });
  res.json({ chat: { id: c.chatId, title: c.title, ts: c.ts } });
});
app.get('/api/chats/:id', auth, async (req, res) => {
  const c = await Chat.findOne({ chatId: req.params.id, ownerId: req.session.user.id });
  if (!c) return res.status(404).json({ error: 'Not found.' });
  res.json({ chat: { id: c.chatId, title: c.title, ts: c.ts, history: c.history, rendered: c.rendered } });
});
app.put('/api/chats/:id', auth, async (req, res) => {
  const c = await Chat.findOne({ chatId: req.params.id, ownerId: req.session.user.id });
  if (!c) return res.status(404).json({ error: 'Not found.' });
  if (req.body.title    !== undefined) c.title    = req.body.title.slice(0, 80);
  if (req.body.history  !== undefined) c.history  = req.body.history;
  if (req.body.rendered !== undefined) c.rendered = req.body.rendered;
  c.ts = Date.now(); await c.save();
  res.json({ success: true, chat: { id: c.chatId, title: c.title, ts: c.ts } });
});
app.delete('/api/chats/:id', auth, async (req, res) => {
  const c = await Chat.findOneAndDelete({ chatId: req.params.id, ownerId: req.session.user.id });
  if (!c) return res.status(404).json({ error: 'Not found.' });
  res.json({ success: true });
});

/* ── ADMIN ── */
app.get('/api/admin/users', auth, admin, async (req, res) => {
  const users = await User.find({}, { password: 0, passwordHistory: 0, securityAnswer: 0 });
  const enriched = await Promise.all(users.map(async u => {
    const chats = await Chat.find({ ownerId: u.id });
    const msgCount = chats.reduce((n, c) => n + Math.floor((c.history?.length || 0) / 2), 0);
    return { ...u.toObject(), chatCount: chats.length, msgCount };
  }));
  res.json({ users: enriched });
});
app.get('/api/admin/users/:uid/messages', auth, admin, async (req, res) => {
  const user = await User.findOne({ userId: req.params.uid.toLowerCase() });
  if (!user) return res.status(404).json({ error: 'User not found.' });
  const chats = await Chat.find({ ownerId: user.id });
  res.json({ user: { userId: user.userId, name: user.name, email: user.email }, chats: chats.map(c => ({
    chatId: c.chatId, title: c.title, ts: c.ts,
    messages: (c.history || []).map(m => ({ role: m.role, content: m.content ? m.content.replace(/^\[MODE:[^\]]+\]\[LANG:[^\]]+\]\n\n/, '') : '' }))
  }))});
});
app.get('/api/admin/users/:uid/messages/download', auth, admin, async (req, res) => {
  const user = await User.findOne({ userId: req.params.uid.toLowerCase() });
  if (!user) return res.status(404).json({ error: 'User not found.' });
  const chats = await Chat.find({ ownerId: user.id });
  const data = { exportedAt: new Date().toISOString(), user: { userId: user.userId, name: user.name, email: user.email },
    chats: chats.map(c => ({ chatId: c.chatId, title: c.title, date: new Date(c.ts).toISOString(),
      messages: (c.history || []).map(m => ({ role: m.role, content: m.content ? m.content.replace(/^\[MODE:[^\]]+\]\[LANG:[^\]]+\]\n\n/, '') : '' }))
    }))
  };
  res.setHeader('Content-Disposition', `attachment; filename="${user.userId}_chats.json"`);
  res.setHeader('Content-Type', 'application/json');
  res.send(JSON.stringify(data, null, 2));
});
app.put('/api/admin/users/:uid/role', auth, admin, async (req, res) => {
  const { role } = req.body;
  if (!['admin', 'user'].includes(role)) return res.status(400).json({ error: 'Invalid role.' });
  const u = await User.findOne({ userId: req.params.uid.toLowerCase() });
  if (!u) return res.status(404).json({ error: 'User not found.' });
  if (u.userId === req.session.user.userId) return res.status(400).json({ error: 'Cannot change your own role.' });
  if (u.userId === 'admin') return res.status(403).json({ error: 'Main admin role cannot be changed.' });
  if (u.role === 'admin' && !isMain(req.session.user)) return res.status(403).json({ error: 'Only main admin can demote admins.' });
  u.role = role; await u.save();
  res.json({ success: true });
});
app.delete('/api/admin/users/:uid', auth, admin, async (req, res) => {
  const u = await User.findOne({ userId: req.params.uid.toLowerCase() });
  if (!u) return res.status(404).json({ error: 'User not found.' });
  if (u.userId === req.session.user.userId) return res.status(400).json({ error: 'Cannot delete yourself.' });
  if (u.userId === 'admin') return res.status(403).json({ error: 'Main admin cannot be deleted.' });
  if (u.role === 'admin' && !isMain(req.session.user)) return res.status(403).json({ error: 'Only main admin can delete admins.' });
  await Chat.deleteMany({ ownerId: u.id });
  await User.deleteOne({ userId: u.userId });
  res.json({ success: true });
});

/* ── CHAT — Gemini Key Rotation ── */
app.post('/api/chat', auth, async (req, res) => {
  if (!GEMINI_KEYS.length)
    return res.status(500).json({ error: 'No GEMINI_API_KEY set in environment.' });

  const { system, messages } = req.body;
  if (!messages?.length) return res.status(400).json({ error: 'messages required' });

  const contents = messages.map(m => {
    const parts = [];
    if (m.file?.data && m.file?.mimeType) parts.push({ inlineData: { mimeType: m.file.mimeType, data: m.file.data } });
    parts.push({ text: m.content });
    return { role: m.role === 'assistant' ? 'model' : 'user', parts };
  });

  const payload = JSON.stringify({
    system_instruction: { parts: [{ text: system || '' }] },
    contents,
    generationConfig: { maxOutputTokens: 8192, temperature: 0.7 }
  });

  const hasImage = messages.some(m => m.file?.data);

  // ✅ VERIFIED working model names
  const modelsToTry = ['gemini-2.5-flash', 'gemini-2.0','gemini-1.5-flash','gemini-1.5-pro'];

  const callGemini = (model, apiKey) => new Promise((resolve, reject) => {
    const opts = {
      hostname: 'generativelanguage.googleapis.com',
      path: `/v1beta/models/${model}:generateContent?key=${apiKey}`,
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(payload) },
      timeout: hasImage ? 90000 : 60000  // 60s for text (big projects need time)
    };
    const apiReq = https.request(opts, apiRes => {
      let data = '';
      apiRes.on('data', c => data += c);
      apiRes.on('end', () => resolve({ status: apiRes.statusCode, data }));
    });
    apiReq.on('timeout', () => { apiReq.destroy(); reject(new Error('Timeout')); });
    apiReq.on('error', e => reject(e));
    apiReq.write(payload); apiReq.end();
  });

  let lastError = 'No response from AI.';

  for (const model of modelsToTry) {
    for (let i = 0; i < GEMINI_KEYS.length; i++) {
      const apiKey = getGeminiKey();
      try {
        const response = await callGemini(model, apiKey);
        if (response.status === 200) {
          const p = JSON.parse(response.data);
          if (p.candidates?.[0]?.content?.parts?.[0]?.text)
            return res.json({ content: [{ type: 'text', text: p.candidates[0].content.parts[0].text }] });
          lastError = 'Empty response from AI.';
        } else if (response.status === 429) {
          console.warn(`[Key ${i+1}][${model}] Rate limited → next key`);
          continue;
        } else {
          try { lastError = JSON.parse(response.data).error?.message || `Status ${response.status}`; }
          catch { lastError = `Status ${response.status}`; }
          console.warn(`[Key ${i+1}][${model}]:`, lastError);
        }
      } catch (err) {
        lastError = err.message || 'Network error';
        console.warn(`[Key ${i+1}][${model}] Exception:`, lastError);
      }
    }
  }

  res.status(500).json({ error: lastError });
});

app.get('*', (_, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

mongoose.connection.once('open', async () => {
  await seedAdmin();
  app.listen(PORT, () => {
    console.log(`\n⚡  CodeMentor AI → http://localhost:${PORT}`);
    console.log(`    🔑  Gemini keys: ${GEMINI_KEYS.length}`);
    if (!BREVO_KEY) console.log(`    📧  Email OTP → DEV mode`);
  });
});

