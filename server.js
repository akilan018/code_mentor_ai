require('dotenv').config();

const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const { v4: uuidv4 } = require('uuid');
const path = require('path');
const https = require('https');
const mongoose = require('mongoose');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const Brevo = require('@getbrevo/brevo');
const Tesseract = require('tesseract.js');
const pdfParse = require('pdf-parse');
const mammoth = require('mammoth');

const app = express();
app.set('trust proxy', 1);

const PORT = process.env.PORT || 3000;

/* ── Gemini key hierarchy: rotate across 3 keys ── */
const GEMINI_KEYS = [
  process.env.GEMINI_API_KEY || '',
  process.env.GEMINI_API_KEY_2 || '',
  process.env.GEMINI_API_KEY_3 || '',
].filter(Boolean);

/* ── NVIDIA fallback keys (3 keys) ── */
const NVIDIA_KEYS = [
  process.env.NVIDIA_API_KEY_1 || '',
  process.env.NVIDIA_API_KEY_2 || '',
  process.env.NVIDIA_API_KEY_3 || '',
].filter(Boolean);

const NVIDIA_TEXT_MODELS = [
  'meta/llama-3.1-70b-instruct',
  'meta/llama-3.1-8b-instruct',
  'mistralai/mixtral-8x7b-instruct',
  'microsoft/phi-3-medium-128k-instruct',
  'meta/llama-3.2-3b-instruct',
  'nvidia/llama-3.1-nemotron-70b-instruct',
];

const BREVO_API_KEY    = process.env.BREVO_API_KEY    || '';
const BREVO_FROM_NAME  = process.env.BREVO_FROM_NAME  || 'CodeMentor AI';
const BREVO_FROM_EMAIL = process.env.BREVO_FROM_EMAIL || '';
const FAST2SMS_KEY     = process.env.FAST2SMS_KEY     || '';

/* ── GLOBAL ADMIN userId (cannot be demoted/deleted/password-changed) ── */
const GLOBAL_ADMIN_ID = 'admin';

/* ───────────────────────────────────────
   MONGODB
─────────────────────────────────────── */
mongoose.connect(process.env.MONGODB_URI)
  .then(() => console.log('✅  MongoDB connected'))
  .catch(err => { console.error('❌  MongoDB error:', err.message); process.exit(1); });

/* ───────────────────────────────────────
   SCHEMAS
─────────────────────────────────────── */
const userSchema = new mongoose.Schema({
  id: { type: String, default: () => uuidv4() },
  userId: { type: String, required: true, unique: true, lowercase: true },
  name: { type: String, required: true },
  email: { type: String, default: '' },
  phone: { type: String, default: '' },
  password: { type: String, required: true },
  passwordHistory: { type: [String], default: [] },
  role: { type: String, enum: ['admin', 'user'], default: 'user' },
  verified: { type: Boolean, default: false },
  method: { type: String, default: 'email' },
  securityAnswer: { type: String, default: '' },
  joined: { type: Number, default: Date.now },
  lastSeen: { type: Number, default: Date.now }
}, { id: false });
/* ── { id: false } suppresses Mongoose's auto virtual 'id' getter
      so our real schema field 'id' is never shadowed ── */

const User = mongoose.model('User', userSchema);

const chatSchema = new mongoose.Schema({
  chatId:  { type: String, default: () => uuidv4() },
  ownerId: { type: String, required: true },   // stores user.id
  title:   { type: String, default: 'New Chat' },
  ts:      { type: Number, default: Date.now },
  history:  { type: mongoose.Schema.Types.Mixed, default: [] },
  rendered: { type: mongoose.Schema.Types.Mixed, default: [] }
});
const Chat = mongoose.model('Chat', chatSchema);

const otpStore = new Map();

/* ───────────────────────────────────────
   SEED ADMIN
─────────────────────────────────────── */
async function migrateUserIds() {
  /* One-time migration: backfill any user documents that are missing the 'id' field.
     This fixes all existing users created before the id field was explicit. */
  try {
    const usersWithoutId = await User.find({ id: { $in: [null, '', undefined] } });
    for (const u of usersWithoutId) {
      u.id = uuidv4();
      await u.save();
      console.log(`🔧  Migrated user '${u.userId}' → id: ${u.id}`);
    }
    if (usersWithoutId.length === 0) {
      console.log('✅  All users have id field — no migration needed');
    } else {
      console.log(`✅  Migrated ${usersWithoutId.length} user(s) successfully`);
    }
  } catch (e) { console.error('Migration error:', e.message); }
}

async function seedAdmin() {
  try {
    const adminPwd = process.env.ADMIN_PASSWORD;
    const exists   = await User.findOne({ userId: GLOBAL_ADMIN_ID });

    if (!exists) {
      const password = adminPwd || 'Admin@123!';
      const hashed   = await bcrypt.hash(password, 10);
      await User.create({
        id: uuidv4(), userId: GLOBAL_ADMIN_ID, name: 'Admin',
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
        console.log('✅  Admin password synced from ADMIN_PASSWORD in .env');
      }
    }
  } catch (e) { console.error('Seed error:', e.message); }
}

/* ───────────────────────────────────────
   HELPERS
─────────────────────────────────────── */

const safe = u => {
  const o = u.toObject ? u.toObject() : { ...u };
  delete o.password;
  delete o.passwordHistory;
  delete o.securityAnswer;
  return o;
};

function validatePassword(password) {
  if (password.length < 8)
    return 'Password must be at least 8 characters.';
  if (!/[A-Z]/.test(password))
    return 'Password must contain at least one uppercase letter.';
  if (!/[a-z]/.test(password))
    return 'Password must contain at least one lowercase letter.';
  if (!/[0-9]/.test(password))
    return 'Password must contain at least one number.';
  if (!/[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?`~]/.test(password))
    return 'Password must contain at least one special character (!@#$%...).';
  return null;
}

async function isPasswordReused(password, history = []) {
  for (const h of history) {
    if (await bcrypt.compare(password, h)) return true;
  }
  return false;
}

function isGlobalAdmin(userId) {
  return (userId || '').toLowerCase().trim() === GLOBAL_ADMIN_ID;
}

/* ───────────────────────────────────────
   FILE HELPERS
─────────────────────────────────────── */
const IMAGE_TYPES = ['image/png','image/jpeg','image/jpg','image/webp','image/gif','image/bmp'];
const TEXT_TYPES  = [
  'text/plain','text/markdown','text/csv','text/html','text/css',
  'application/json','application/xml','application/javascript','application/typescript'
];
const TEXT_EXTENSIONS = [
  '.txt','.md','.csv','.js','.ts','.py','.java','.cpp','.c','.h',
  '.html','.css','.json','.xml','.yaml','.yml','.sql','.sh','.rb',
  '.go','.rs','.php','.swift','.kt','.r','.scala'
];

function getFileCategory(mimeType, fileName) {
  if (IMAGE_TYPES.includes(mimeType)) return 'image';
  if (mimeType === 'application/pdf')  return 'pdf';
  if (mimeType === 'application/vnd.openxmlformats-officedocument.wordprocessingml.document') return 'docx';
  if (mimeType === 'application/msword') return 'doc';
  if (mimeType === 'application/zip' || mimeType === 'application/x-zip-compressed') return 'zip';
  if (TEXT_TYPES.includes(mimeType))   return 'text';
  const ext = path.extname(fileName || '').toLowerCase();
  if (ext === '.docx') return 'docx';
  if (ext === '.doc')  return 'doc';
  if (TEXT_EXTENSIONS.includes(ext)) return 'text';
  return 'binary';
}

function extractTextFromBase64(base64Data) {
  try {
    const buf  = Buffer.from(base64Data, 'base64');
    const text = buf.toString('utf-8');
    const nullCount = (text.match(/\0/g) || []).length;
    if (nullCount > text.length * 0.1) return null;
    return text.slice(0, 15000);
  } catch { return null; }
}

async function fileToText(file) {
  if (!file || !file.data) return null;
  const category = getFileCategory(file.mimeType || '', file.name || '');

  if (category === 'image') {
    // Images are sent directly to Gemini as inlineData — no OCR needed.
    // For NVIDIA fallback, just send a note that an image was attached.
    return `[IMAGE UPLOADED: ${file.name || 'image'}]\nPlease analyze and explain this image in detail.`;
  }

  if (category === 'pdf') {
    try {
      const buf  = Buffer.from(file.data, 'base64');
      const data = await pdfParse(buf);
      const text = data.text.trim();
      return text
        ? `[PDF DOCUMENT: ${file.name || 'document.pdf'}]\n\nExtracted Content:\n${text.slice(0, 30000)}\n\nNote: Analyze this extracted PDF text completely.`
        : `[PDF DOCUMENT: ${file.name || 'document.pdf'}]\nCould not find any clear text in this PDF.`;
    } catch (e) {
      return `[PDF DOCUMENT: ${file.name || 'document.pdf'}]\nCould not extract text: ${e.message}`;
    }
  }

  if (category === 'docx') {
    try {
      const buf    = Buffer.from(file.data, 'base64');
      const result = await mammoth.extractRawText({ buffer: buf });
      const text   = result.value.trim();
      return text
        ? `[DOCX DOCUMENT: ${file.name || 'document.docx'}]\n\nExtracted Content:\n${text.slice(0, 30000)}`
        : `[DOCX DOCUMENT: ${file.name || 'document.docx'}]\nCould not find any clear text in this document.`;
    } catch (e) {
      return `[DOCX DOCUMENT: ${file.name || 'document.docx'}]\nCould not extract text: ${e.message}`;
    }
  }

  if (category === 'doc') {
    return `[DOC DOCUMENT: ${file.name || 'document.doc'}]\nOlder .doc format. Please use .docx or PDF for better results.`;
  }

  if (category === 'text') {
    const extracted = extractTextFromBase64(file.data);
    return extracted
      ? `[CODE/TEXT FILE: ${file.name || 'file'}]\n\`\`\`\n${extracted}\n\`\`\``
      : `[CODE/TEXT FILE: ${file.name || 'file'}]\nCould not read file contents.`;
  }

  if (category === 'zip') {
    return `[ZIP ARCHIVE: ${file.name || 'archive.zip'}]\nZIP contents cannot be read directly. Please share individual files.`;
  }

  return `[FILE: ${file.name || 'file'} (${file.mimeType || 'unknown type'})]`;
}

/* ───────────────────────────────────────
   BREVO EMAIL
─────────────────────────────────────── */
async function sendEmailOTP(to, otp, purpose) {
  console.log(`\n📧  Email OTP for ${to} → ${otp}\n`);

  if (!BREVO_API_KEY || !BREVO_FROM_EMAIL) {
    console.log('  [DEV] Brevo not configured — OTP logged above.');
    return;
  }

  const subject = purpose === 'register'
    ? 'CodeMentor AI — Verify Account'
    : 'CodeMentor AI — Reset Password';

  const html = `
<div style="font-family:monospace;background:#0d0d0d;color:#f0ece4;padding:32px;max-width:420px;border-radius:10px">
  <p style="font-size:20px;font-weight:800;margin-bottom:4px">⚡ Code<span style="color:#f59e0b">Mentor</span> AI</p>
  <p style="color:#6b7280;font-size:11px;margin-bottom:24px">INTELLIGENT CODING COMPANION</p>
  <p style="font-size:13px;margin-bottom:16px">${purpose === 'register' ? 'Your verification OTP' : 'Your password reset OTP'}:</p>
  <div style="background:#1a1a1a;border:1px solid #f59e0b44;border-radius:8px;padding:18px;text-align:center;margin-bottom:16px">
    <span style="font-size:38px;font-weight:800;letter-spacing:.2em;color:#f59e0b">${otp}</span>
  </div>
  <p style="color:#555;font-size:11px">Valid for 10 minutes. Do not share this OTP.</p>
</div>`;

  const payload = JSON.stringify({
    sender:      { name: BREVO_FROM_NAME, email: BREVO_FROM_EMAIL },
    to:          [{ email: to }],
    subject,
    htmlContent: html
  });

  await new Promise((resolve, reject) => {
    const req = https.request({
      hostname: 'api.brevo.com',
      path: '/v3/smtp/email',
      method: 'POST',
      headers: {
        'Accept': 'application/json',
        'api-key': BREVO_API_KEY,
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(payload)
      }
    }, res => {
      let d = ''; res.on('data', c => d += c); res.on('end', () => resolve(d));
    }).on('error', reject);
    req.write(payload); req.end();
  });
}

async function sendPhoneOTP(phone, otp) {
  if (!FAST2SMS_KEY) {
    console.log(`\n📱  [DEV] Phone OTP for ${phone} → ${otp}\n`); return;
  }
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
  if (Date.now() > r.expires) { otpStore.delete(key); return 'OTP expired. Please request a new one.'; }
  if (r.otp !== String(otp).trim()) return 'Incorrect OTP. Please try again.';
  const data = { ...r }; otpStore.delete(key); return { ok: true, data };
}

/* ───────────────────────────────────────
   MIDDLEWARE
─────────────────────────────────────── */
app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));

app.use((req, res, next) => {
  res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate');
  res.setHeader('Pragma', 'no-cache');
  res.setHeader('Expires', '0');
  next();
});

app.use((req, res, next) => {
  const ext = path.extname(req.path).toLowerCase();
  if ((ext === '.js' || ext === '.css') && req.headers['sec-fetch-dest'] === 'document') {
    return res.status(403).send('<html><head><title>Forbidden</title></head><body style="background:#0d0d0d;color:#ef4444;font-family:monospace;padding:40px;text-align:center;"><h2>⚠️ 403 Forbidden</h2><p>Direct access to source files is not allowed.</p></body></html>');
  }
  next();
});

app.use(express.static(path.join(__dirname, 'public')));

/* ── FIX: session cookie now persists for 7 days so history survives logout/reopen ── */
app.use(session({
  secret: process.env.SESSION_SECRET || 'cm-secret',
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    sameSite: 'strict',
    maxAge: 7 * 24 * 60 * 60 * 1000   // 7 days — survives tab/browser close
  }
}));

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, max: 30,
  message: { error: 'Too many requests. Please try again in 15 minutes.' },
  standardHeaders: true, legacyHeaders: false
});

const forgotLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, max: 5,
  message: { error: 'Too many reset attempts. Please wait 15 minutes before trying again.' },
  standardHeaders: true, legacyHeaders: false
});

const auth  = (q, s, n) => q.session.user ? n() : s.status(401).json({ error: 'Not authenticated' });
const admin = (q, s, n) => q.session.user?.role === 'admin' ? n() : s.status(403).json({ error: 'Forbidden' });

/* ───────────────────────────────────────
   REGISTER
─────────────────────────────────────── */
app.post('/api/auth/register/send-otp', authLimiter, async (req, res) => {
  const { userId, name, password, method, contact, securityAnswer } = req.body;
  if (!userId || !name || !password || !method || !contact || !securityAnswer)
    return res.status(400).json({ error: 'All fields are required (including security answer).' });
  if (!/^[a-zA-Z0-9_]{3,20}$/.test(userId))
    return res.status(400).json({ error: 'User ID: 3-20 chars, letters/numbers/underscore only.' });
  if (isGlobalAdmin(userId))
    return res.status(400).json({ error: 'This User ID is reserved. Please choose another.' });

  const pwErr = validatePassword(password);
  if (pwErr) return res.status(400).json({ error: pwErr });

  if (method === 'email' && !/\S+@\S+\.\S+/.test(contact))
    return res.status(400).json({ error: 'Enter a valid email address.' });
  if (method === 'phone' && !/^\d{10}$/.test(contact))
    return res.status(400).json({ error: 'Enter a valid 10-digit mobile number.' });

  const key      = userId.toLowerCase();
  const existing = await User.findOne({ userId: key });
  if (existing) return res.status(400).json({ error: 'This User ID is already taken. Please choose another.' });

  const dupContact = await User.findOne(method === 'email' ? { email: contact } : { phone: contact });
  if (dupContact) return res.status(400).json({ error: `This ${method} is already registered.` });

  const otp    = String(Math.floor(100000 + Math.random() * 900000));
  const otpKey = `reg_${key}`;
  storeOTP(otpKey, otp, { pending: { userId: key, name: name.trim(), password, method, contact, securityAnswer } });

  res.json({ success: true, message: `OTP sent to your ${method}.` });

  if (method === 'email') {
    sendEmailOTP(contact, otp, 'register').catch(e => console.error('Email OTP error:', e.message));
  } else {
    sendPhoneOTP(contact, otp).catch(e => console.error('Phone OTP error:', e.message));
  }
});

app.post('/api/auth/register/verify-otp', authLimiter, async (req, res) => {
  const { userId, otp } = req.body;
  if (!userId || !otp) return res.status(400).json({ error: 'Missing fields.' });

  const key    = userId.toLowerCase();
  const otpKey = `reg_${key}`;
  const result = checkOTP(otpKey, otp);
  if (typeof result === 'string') return res.status(400).json({ error: result });

  const { pending } = result.data;
  if (!pending) return res.status(400).json({ error: 'Session expired. Please start again.' });

  const existing = await User.findOne({ userId: key });
  if (existing) return res.status(400).json({ error: 'This User ID was just taken. Please choose another.' });

  const hashed  = await bcrypt.hash(pending.password, 10);
  const secHash = await bcrypt.hash((pending.securityAnswer || '').toLowerCase().trim(), 10);

  const user = await User.create({
    id: uuidv4(), userId: key, name: pending.name,
    email: pending.method === 'email' ? pending.contact : '',
    phone: pending.method === 'phone' ? pending.contact : '',
    password: hashed, passwordHistory: [hashed],
    role: 'user', verified: true, method: pending.method,
    securityAnswer: secHash
  });

  req.session.user = safe(user);
  res.json({ success: true, user: safe(user) });
});

/* ───────────────────────────────────────
   LOGIN
─────────────────────────────────────── */
app.post('/api/auth/login', authLimiter, async (req, res) => {
  const { userId, password } = req.body;
  if (!userId || !password) return res.status(400).json({ error: 'All fields required.' });

  const user = await User.findOne({ userId: userId.toLowerCase().trim() });
  if (!user || !(await bcrypt.compare(password, user.password)))
    return res.status(401).json({ error: 'Incorrect User ID or password.' });

  user.lastSeen = Date.now();
  await user.save();
  req.session.user = safe(user);
  res.json({ success: true, user: safe(user) });
});

app.post('/api/auth/logout', (req, res) => {
  req.session.destroy(() => {
    res.json({ success: true });
  });
});
app.get('/api/auth/me', (req, res) => res.json({ user: req.session?.user || null }));

/* ───────────────────────────────────────
   FORGOT PASSWORD
─────────────────────────────────────── */
app.post('/api/auth/forgot/send-otp', forgotLimiter, async (req, res) => {
  const { userId } = req.body;
  if (!userId) return res.status(400).json({ error: 'User ID is required.' });
  if (isGlobalAdmin(userId))
    return res.status(403).json({ error: 'Global admin password cannot be reset here. Update ADMIN_PASSWORD in .env.' });

  const user = await User.findOne({ userId: userId.toLowerCase().trim() });
  if (!user) return res.status(404).json({ error: 'No account found with this User ID.' });

  const otp = String(Math.floor(100000 + Math.random() * 900000));
  otpStore.set(`fpw_${userId.toLowerCase()}`, { otp, expires: Date.now() + 10 * 60 * 1000 });

  res.json({ success: true, message: 'OTP sent to your registered email.' });

  const contact = user.email || user.phone;
  if (user.method === 'email' || user.email) {
    sendEmailOTP(contact, otp, 'reset').catch(e => console.error('Forgot OTP email error:', e.message));
  } else {
    sendPhoneOTP(contact, otp).catch(e => console.error('Forgot OTP phone error:', e.message));
  }
});

app.post('/api/auth/forgot/verify-otp', forgotLimiter, async (req, res) => {
  const { userId, otp } = req.body;
  if (!userId || !otp) return res.status(400).json({ error: 'User ID and OTP are required.' });

  const key    = `fpw_${userId.toLowerCase().trim()}`;
  const stored = otpStore.get(key);
  if (!stored) return res.status(400).json({ error: 'No OTP found. Please request a new one.' });
  if (Date.now() > stored.expires) { otpStore.delete(key); return res.status(400).json({ error: 'OTP expired. Please request a new one.' }); }
  if (stored.otp !== String(otp).trim()) return res.status(400).json({ error: 'Incorrect OTP. Please try again.' }); // fixed: was !== String
  otpStore.delete(key);

  const token = uuidv4();
  otpStore.set(`reset_${userId.toLowerCase()}`, { token, expires: Date.now() + 5 * 60 * 1000 });
  res.json({ success: true, token, message: 'OTP verified. You may now reset your password.' });
});

app.post('/api/auth/forgot/reset', forgotLimiter, async (req, res) => {
  const { userId, token, newPassword, confirmPassword } = req.body;
  if (!userId || !token || !newPassword || !confirmPassword)
    return res.status(400).json({ error: 'All fields are required.' });
  if (newPassword !== confirmPassword)
    return res.status(400).json({ error: 'Passwords do not match.' });

  const pwErr = validatePassword(newPassword);
  if (pwErr) return res.status(400).json({ error: pwErr });

  const key    = `reset_${userId.toLowerCase()}`;
  const stored = otpStore.get(key);
  if (!stored || stored.token !== token || Date.now() > stored.expires)
    return res.status(400).json({ error: 'Reset session expired. Please start again.' });
  otpStore.delete(key);

  const user = await User.findOne({ userId: userId.toLowerCase() });
  if (!user) return res.status(404).json({ error: 'No account found.' });

  if (await isPasswordReused(newPassword, user.passwordHistory))
    return res.status(400).json({ error: 'You cannot reuse a recent password. Please choose a different one.' });

  const hashed = await bcrypt.hash(newPassword, 10);
  user.password = hashed;
  user.passwordHistory = [hashed, ...(user.passwordHistory || [])].slice(0, 5);
  await user.save();
  res.json({ success: true, message: 'Password reset successfully. You can now sign in.' });
});

/* ───────────────────────────────────────
   SETTINGS
─────────────────────────────────────── */
app.post('/api/auth/settings/update-name', auth, async (req, res) => {
  const { name } = req.body;
  if (!name || name.trim().length < 2)
    return res.status(400).json({ error: 'Name must be at least 2 characters.' });

  const user = await User.findOne({ userId: req.session.user.userId });
  if (!user) return res.status(404).json({ error: 'User not found.' });

  user.name = name.trim();
  await user.save();
  req.session.user = safe(user);
  res.json({ success: true, message: 'Name updated successfully.', user: safe(user) });
});

app.post('/api/auth/settings/update-userid', auth, async (req, res) => {
  const { newUserId, currentPassword } = req.body;
  if (isGlobalAdmin(req.session.user.userId))
    return res.status(403).json({ error: 'Global admin ID cannot be changed.' });
  if (!newUserId || !currentPassword)
    return res.status(400).json({ error: 'New User ID and current password are required.' });
  if (!/^[a-zA-Z0-9_]{3,20}$/.test(newUserId))
    return res.status(400).json({ error: 'User ID: 3-20 chars, letters/numbers/underscore only.' });
  if (isGlobalAdmin(newUserId))
    return res.status(400).json({ error: 'This User ID is reserved.' });

  const user = await User.findOne({ userId: req.session.user.userId });
  if (!user) return res.status(404).json({ error: 'User not found.' });

  const pwMatch = await bcrypt.compare(currentPassword, user.password);
  if (!pwMatch) return res.status(400).json({ error: 'Current password is incorrect.' });

  const existing = await User.findOne({ userId: newUserId.toLowerCase() });
  if (existing) return res.status(400).json({ error: 'This User ID is already taken.' });

  user.userId = newUserId.toLowerCase();
  await user.save();
  req.session.user = safe(user);
  res.json({ success: true, message: 'User ID updated successfully.', user: safe(user) });
});

app.post('/api/auth/change-password', auth, async (req, res) => {
  const { currentPassword, securityAnswer, newPassword, confirmPassword } = req.body;
  if (isGlobalAdmin(req.session.user.userId))
    return res.status(403).json({ error: 'Global admin password can only be changed via ADMIN_PASSWORD in the .env file.' });
  if (!currentPassword || !securityAnswer || !newPassword || !confirmPassword)
    return res.status(400).json({ error: 'All fields are required.' });
  if (newPassword !== confirmPassword)
    return res.status(400).json({ error: 'Passwords do not match.' });

  const pwErr = validatePassword(newPassword);
  if (pwErr) return res.status(400).json({ error: pwErr });

  const user = await User.findOne({ userId: req.session.user.userId });
  if (!user) return res.status(404).json({ error: 'User not found.' });

  const pwMatch = await bcrypt.compare(currentPassword, user.password);
  if (!pwMatch) return res.status(400).json({ error: 'Current password is incorrect.' });

  if (!user.securityAnswer)
    return res.status(400).json({ error: 'No security question set on this account.' });
  const ansMatch = await bcrypt.compare(securityAnswer.toLowerCase().trim(), user.securityAnswer);
  if (!ansMatch) return res.status(400).json({ error: 'Incorrect security answer. Please try again.' });

  if (await isPasswordReused(newPassword, user.passwordHistory))
    return res.status(400).json({ error: 'You cannot reuse a recent password. Please choose a different one.' });

  const hashed = await bcrypt.hash(newPassword, 10);
  user.password = hashed;
  user.passwordHistory = [hashed, ...(user.passwordHistory || [])].slice(0, 5);
  await user.save();
  res.json({ success: true, message: 'Password updated successfully.' });
});

/* ───────────────────────────────────────
   CHATS — ownerId uses uid (stable)
─────────────────────────────────────── */
app.get('/api/chats', auth, async (req, res) => {
  const chats = await Chat.find(
    { ownerId: req.session.user.id },
    { history: 0, rendered: 0 }
  ).sort({ ts: -1 });
  res.json({ chats: chats.map(c => ({ id: c.chatId, title: c.title, ts: c.ts })) });
});

app.post('/api/chats', auth, async (req, res) => {
  const c = await Chat.create({
    ownerId: req.session.user.id,
    title: (req.body.title || 'New Chat').slice(0, 80)
  });
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

/* ───────────────────────────────────────
   ADMIN
─────────────────────────────────────── */
app.get('/api/admin/users', auth, admin, async (req, res) => {
  const users    = await User.find({}, { password: 0, passwordHistory: 0, securityAnswer: 0 });
  const enriched = await Promise.all(users.map(async u => {
    const chats    = await Chat.find({ ownerId: u.id });
    const msgCount = chats.reduce((n, c) => n + Math.floor((c.history?.length || 0) / 2), 0);
    return { ...u.toObject(), chatCount: chats.length, msgCount };
  }));
  res.json({ users: enriched });
});

app.get('/api/admin/users/:uid/messages', auth, admin, async (req, res) => {
  const user = await User.findOne({ userId: req.params.uid.toLowerCase() });
  if (!user) return res.status(404).json({ error: 'User not found.' });
  const chats = await Chat.find({ ownerId: user.id });
  const data  = chats.map(c => ({
    chatId: c.chatId, title: c.title, ts: c.ts,
    messages: (c.history || []).map(m => ({
      role: m.role,
      content: m.content ? m.content.replace(/^\[MODE:[^\]]+\]\[LANG:[^\]]+\]\n\n/, '') : ''
    }))
  }));
  res.json({ user: { userId: user.userId, name: user.name, email: user.email }, chats: data });
});

app.get('/api/admin/users/:uid/messages/download', auth, admin, async (req, res) => {
  const user = await User.findOne({ userId: req.params.uid.toLowerCase() });
  if (!user) return res.status(404).json({ error: 'User not found.' });
  const chats = await Chat.find({ ownerId: user.id });
  const data  = {
    exportedAt: new Date().toISOString(),
    user: { userId: user.userId, name: user.name, email: user.email },
    chats: chats.map(c => ({
      chatId: c.chatId, title: c.title,
      date: new Date(c.ts).toISOString(),
      messages: (c.history || []).map(m => ({
        role: m.role,
        content: m.content ? m.content.replace(/^\[MODE:[^\]]+\]\[LANG:[^\]]+\]\n\n/, '') : ''
      }))
    }))
  };
  res.setHeader('Content-Disposition', `attachment; filename="${user.userId}_chats.json"`);
  res.setHeader('Content-Type', 'application/json');
  res.send(JSON.stringify(data, null, 2));
});

app.put('/api/admin/users/:uid/role', auth, admin, async (req, res) => {
  const { role } = req.body;
  if (!['admin', 'user'].includes(role))
    return res.status(400).json({ error: 'Invalid role.' });

  const targetUid = req.params.uid.toLowerCase();
  if (isGlobalAdmin(targetUid))
    return res.status(403).json({ error: 'The global admin role cannot be changed by any admin.' });

  const u = await User.findOne({ userId: targetUid });
  if (!u) return res.status(404).json({ error: 'User not found.' });
  if (u.userId === req.session.user.userId)
    return res.status(400).json({ error: 'Cannot change your own role.' });

  u.role = role; await u.save();
  res.json({ success: true });
});

app.delete('/api/admin/users/:uid', auth, admin, async (req, res) => {
  const targetUid = req.params.uid.toLowerCase();
  if (isGlobalAdmin(targetUid))
    return res.status(403).json({ error: 'The global admin account cannot be deleted.' });

  const u = await User.findOne({ userId: targetUid });
  if (!u) return res.status(404).json({ error: 'User not found.' });
  if (u.userId === req.session.user.userId)
    return res.status(400).json({ error: 'You cannot delete your own account.' });

  await Chat.deleteMany({ ownerId: u.id });
  await User.deleteOne({ userId: u.userId });
  res.json({ success: true });
});

/* ───────────────────────────────────────
   CHAT — Gemini + NVIDIA fallback
─────────────────────────────────────── */
let preferredKeyIndex = 0;

app.post('/api/chat', auth, async (req, res) => {
  if (!GEMINI_KEYS.length && !NVIDIA_KEYS.length)
    return res.status(500).json({ error: 'No API keys set in environment.' });

  const { system, messages } = req.body;
  if (!messages?.length) return res.status(400).json({ error: 'messages required' });

  const contents = messages.map(m => {
    const parts = [];
    if (m.file && m.file.data && m.file.mimeType) {
      parts.push({ inlineData: { mimeType: m.file.mimeType, data: m.file.data } });
    }
    parts.push({ text: m.content });
    return { role: m.role === 'assistant' ? 'model' : 'user', parts };
  });

  const payload = JSON.stringify({
    system_instruction: { parts: [{ text: system || '' }] },
    contents,
    generationConfig: { maxOutputTokens: 8192, temperature: 0.7 }
  });

  const hasImage      = messages.some(m => m.file && m.file.data);
  const lastUserMsg   = [...messages].reverse().find(m => m.role === 'user');
  const queryLen      = (lastUserMsg?.content || '').length;
  const isSimple      = !hasImage && queryLen < 300;
  const requestTimeout = hasImage ? 120000 : (isSimple ? 45000 : 90000);

  const modelsToTry = [
    'gemini-2.0-flash',
    'gemini-2.0-flash-lite',
    'gemini-flash-latest',
    'gemini-pro-latest',
    'gemini-2.5-flash-lite',
    'gemini-3-flash-preview'
  ];

  const callGemini = (model, apiKey) => new Promise((resolve, reject) => {
    const opts = {
      hostname: 'generativelanguage.googleapis.com',
      path: `/v1beta/models/${model}:generateContent?key=${apiKey}`,
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(payload) },
      timeout: requestTimeout
    };
    const apiReq = https.request(opts, apiRes => {
      let data = ''; apiRes.on('data', c => data += c);
      apiRes.on('end', () => resolve({ status: apiRes.statusCode, data }));
    });
    apiReq.on('timeout', () => { apiReq.destroy(); reject(new Error('Timeout')); });
    apiReq.on('error', e => reject(e));
    apiReq.write(payload); apiReq.end();
  });

  async function buildNvidiaMessages() {
    // Send same system prompt as Gemini + one extra reminder about Easy/Optimized order
    const nvidiaReminder = '\n\nCRITICAL REMINDER: The div class="sol-easy" must contain the SIMPLE EASY beginner version of the code. The div class="sol-opt" must contain the OPTIMIZED efficient version. Never put optimized code in sol-easy or easy code in sol-opt.';
    const msgs = [{ role: 'system', content: (system || '') + nvidiaReminder }];
    for (const m of messages) {
      if (m.role === 'assistant') {
        // Strip HTML from old replies for context — keep it short
        const plain = (m.content || '').replace(/<[^>]+>/g, ' ').replace(/\s+/g, ' ').trim().slice(0, 500);
        msgs.push({ role: 'assistant', content: plain }); continue;
      }
      const fileText = m.file?.data ? await fileToText(m.file) : null;
      const userContent = fileText
        ? fileText + '\n\nUser question: ' + (m.content || 'Please explain this.')
        : (m.content || '');
      msgs.push({ role: 'user', content: userContent });
    }
    return msgs;
  }

  // Fix code that NVIDIA collapses onto one line
  function fixCollapsedCode(code) {
    let fixed = code;
    const fromImports = [];
    fixed = fixed.replace(/from [\w.]+ import [\w, *()]+/g, function(m) {
      fromImports.push(m);
      return '__FI' + (fromImports.length - 1) + '__';
    });
    fixed = fixed.replace(/(#[^\n]*?)  +([a-zA-Z_#])/g, '$1\n$2');
    const kwds = ['import ','def ','class ','elif ','else:','for ','while ','with ','try:','except ','finally:','return ','if '];
    kwds.forEach(function(kw) {
      const parts = fixed.split(kw); const rebuilt = [];
      for (let i = 0; i < parts.length; i++) {
        rebuilt.push(parts[i]);
        if (i < parts.length - 1) {
          const lc = parts[i].slice(-1);
          rebuilt.push((lc !== '\n' && parts[i].trim().length > 0) ? '\n' + kw : kw);
        }
      }
      fixed = rebuilt.join('');
    });
    fromImports.forEach(function(fi, idx) { fixed = fixed.replace('__FI' + idx + '__', fi); });
    fixed = fixed.replace(/([^\n]) +(from [\w.]+ import)/g, '$1\n$2');
    fixed = fixed.replace(/([^#\n]+) (#[^\n]+)/g, function(m, c, cm) {
      if (c.trim().startsWith('#')) return m;
      return c.trimEnd() + '\n' + cm;
    });
    fixed = fixed.replace(/; *(\/\/)/g, ';\n$1');
    fixed = fixed.replace(/ +\n/g, '\n');
    fixed = fixed.replace(/\n{2,}/g, '\n');
    return fixed.trim();
  }

  // Detect language from code
  function detectLang(code) {
    if (!code) return 'python';
    if (code.includes('public class ') || code.includes('public static void main')) return 'java';
    if (code.includes('#include') || code.includes('int main()') || code.includes('printf(')) return 'c';
    if (code.includes('interface ') || code.includes(': string') || code.includes(': number') || code.includes(': boolean')) return 'typescript';
    if (code.includes('SELECT ') || code.includes('FROM ') || code.includes('INSERT INTO') || code.includes('CREATE TABLE')) return 'sql';
    if (code.includes('<!DOCTYPE') || code.includes('<html') || code.includes('<div') || code.includes('<body')) return 'html';
    if (code.includes('func ') && code.includes('package ')) return 'go';
    if ((code.includes('fn ') && code.includes('let mut')) || code.includes('impl ')) return 'rust';
    if (code.includes('function ') || code.includes('const ') || code.includes('console.log') || code.includes('=>')) return 'javascript';
    if (code.includes('def ') || code.includes('print(') || code.includes('import ')) return 'python';
    return 'python';
  }

  // Auto-explain a single line of code
  function autoExplainLine(line) {
    const t = line.trim();
    if (!t) return null;
    if (t.startsWith('#') || t.startsWith('//') || t.startsWith('/*'))
      return { icon: '🟢 BUILT-IN', label: t, desc: 'Comment — ' + t.replace(/^[#/]+\s*/, '') };
    if (t.startsWith('def '))
      return { icon: '🔷 KEYWORD', label: t, desc: 'Defines function <strong>' + (t.match(/def (\w+)/)||['','?'])[1] + '</strong>' };
    if (t.startsWith('class '))
      return { icon: '🔷 KEYWORD', label: t, desc: 'Creates class <strong>' + (t.match(/class (\w+)/)||['','?'])[1] + '</strong>' };
    if (t.startsWith('import ') || t.startsWith('from '))
      return { icon: '🔷 KEYWORD', label: t, desc: 'Imports: <strong>' + t + '</strong>' };
    if (t.startsWith('return '))
      return { icon: '🔷 KEYWORD', label: t, desc: 'Returns <strong>' + t.replace('return ','') + '</strong> as the answer' };
    if (t.startsWith('if ') || t.startsWith('elif '))
      return { icon: '🔷 KEYWORD', label: t, desc: 'Checks condition: <strong>' + t.replace(/^(if|elif) /,'').replace(':','') + '</strong>' };
    if (t === 'else:')
      return { icon: '🔷 KEYWORD', label: t, desc: 'Runs when none of the above conditions matched' };
    if (t.startsWith('for '))
      return { icon: '🔷 KEYWORD', label: t, desc: 'Loops — <strong>' + t.replace(':','') + '</strong>' };
    if (t.startsWith('while '))
      return { icon: '🔷 KEYWORD', label: t, desc: 'Keeps looping while <strong>' + t.replace(/^while /,'').replace(':','') + '</strong>' };
    if (t.startsWith('print(') || t.startsWith('console.log') || t.startsWith('printf('))
      return { icon: '🟢 BUILT-IN', label: t, desc: 'Prints output: <strong>' + t + '</strong>' };
    if (t.includes('public class'))
      return { icon: '🔷 KEYWORD', label: t, desc: 'Declares the main Java class' };
    if (t.includes('public static void main'))
      return { icon: '🔷 KEYWORD', label: t, desc: 'Entry point — program starts running here' };
    if (t.includes('public static'))
      return { icon: '🔷 KEYWORD', label: t, desc: 'Public static method — callable without creating an object' };
    if (t.startsWith('#include'))
      return { icon: '🔷 KEYWORD', label: t, desc: 'Includes library: <strong>' + t + '</strong>' };
    if (t === 'return 0;')
      return { icon: '🔷 KEYWORD', label: t, desc: 'Returns 0 — signals the program ended successfully' };
    if (t === '{')  return { icon: '⬜ CODE', label: t, desc: 'Opens a block of code' };
    if (t === '}' || t === '};') return { icon: '⬜ CODE', label: t, desc: 'Closes the block of code' };
    if (t.startsWith('if __name__'))
      return { icon: '🔷 KEYWORD', label: t, desc: 'Runs code below only when this file is run directly' };
    if (t.includes(' = ')) {
      const parts = t.split(' = ');
      return { icon: '⬜ CODE', label: t, desc: 'Sets <strong>' + parts[0].trim() + '</strong> to <strong>' + parts.slice(1).join(' = ').trim() + '</strong>' };
    }
    return { icon: '⬜ CODE', label: t, desc: 'Executes: <strong>' + t + '</strong>' };
  }

  // Build full line-by-line explanation — one bullet per line
  function buildExplHtml(explText, lang, codeText) {
    const items = [];

    // Try to use NVIDIA-provided explanation first
    if (explText && explText.trim().length > 30) {
      const lines = explText.split('\n').filter(function(l){ return l.trim(); });
      lines.forEach(function(l) {
        l = l.replace(/^[-*•\d.)\s] ?/, '').trim();
        if (!l) return;
        const sep = l.indexOf(' — ') > -1 ? ' — ' : l.indexOf(' - ') > -1 ? ' - ' : null;
        if (sep) {
          const idx  = l.indexOf(sep);
          const lbl  = l.slice(0, idx).trim();
          const desc = l.slice(idx + sep.length).trim();
          const isKw = /^(def|class|if|elif|else|for|while|return|import|from|public|static|void|int|print|with|try|except|break|continue)\b/.test(lbl);
          const isCm = lbl.startsWith('#') || lbl.startsWith('//');
          const icon = isKw ? '🔷 KEYWORD' : isCm ? '🟢 BUILT-IN' : '⬜ CODE';
          items.push('<li><strong>' + icon + '</strong> <code>' + lbl + '</code> — ' + desc + '</li>');
        } else {
          items.push('<li>' + l + '</li>');
        }
      });
    }

    // If fewer than 3 bullets or no explanation — auto-generate from every code line
    if (items.length < 3 && codeText) {
      items.length = 0;
      codeText.split('\n').forEach(function(line) {
        if (!line.trim()) return;
        const ex = autoExplainLine(line);
        if (ex) {
          items.push('<li><strong>' + ex.icon + '</strong> <code>' + ex.label + '</code> — ' + ex.desc + '</li>');
        }
      });
    }

    if (!items.length) return '';
    return '<h3>&#128218; Line-by-Line Explanation</h3><ul>' + items.join('') + '</ul>';
  }

  // Build output block
  function buildOutBlock(input, result, reason) {
    return '<div class="out-block"><div class="out-header">&#9654; Expected Output</div>' +
      '<div class="out-body">' +
      '<p class="out-line"><strong>Input &nbsp;&nbsp;:</strong> ' + input + '</p>' +
      '<p class="out-line"><strong>Result &nbsp;:</strong> ' + result + '</p>' +
      '<p class="out-line"><strong>Reason &nbsp;:</strong> ' + reason + '</p>' +
      '</div></div>';
  }

  // Detect language from user message context
  function detectLangFromMsg(msgContent) {
    const lower = (msgContent || '').toLowerCase();
    if (lower.includes('java ') || lower.includes(' java')) return 'java';
    if (lower.includes(' c ') || lower.includes('c program') || lower.includes('in c')) return 'c';
    if (lower.includes('python')) return 'python';
    if (lower.includes('typescript') || lower.includes(' ts ')) return 'typescript';
    if (lower.includes('javascript') || lower.includes(' js ')) return 'javascript';
    if (lower.includes('sql') || lower.includes('database')) return 'sql';
    if (lower.includes('html') || lower.includes('css')) return 'html';
    if (lower.includes('go ') || lower.includes('golang')) return 'go';
    if (lower.includes('rust')) return 'rust';
    return null;
  }

  // Parse NVIDIA section to extract code + metadata
  function parseNvidiaSection(sectionText, hintLang) {
    let code = '';
    let remaining = sectionText;

    // Try fenced code block first
    const fenced = sectionText.match(/```(\w*)[\r\n]([\s\S]*?)```/);
    if (fenced) {
      code = fixCollapsedCode(fenced[2].trim());
      remaining = sectionText.replace(fenced[0], '').trim();
    } else {
      // Fallback: extract lines that look like code
      const lines = sectionText.split('\n');
      const codeLines = []; const textLines = [];
      lines.forEach(function(line) {
        const t = line.trim();
        if (t.match(/^(def |class |import |from |public |private |static |#include|int |void |if |elif |else:|for |while |return |print|func |fn |let |const |var |SELECT |FROM |INSERT|CREATE|UPDATE|DELETE|<html|<div|<!DOCTYPE|interface )/i) ||
            line.startsWith('    ') || line.startsWith('\t')) {
          codeLines.push(line);
        } else { textLines.push(line); }
      });
      if (codeLines.length > 1) {
        code = fixCollapsedCode(codeLines.join('\n').trim());
        remaining = textLines.join('\n').trim();
      }
    }

    const inputM  = remaining.match(/INPUT:\s*(.+)/i);
    const resultM = remaining.match(/RESULT:\s*(.+)/i);
    const reasonM = remaining.match(/REASON:\s*(.+)/i);
    let resultVal = resultM ? resultM[1].trim() : 'See output';
    resultVal = resultVal.replace(/[",)]/g,'').replace(/result\s*$/,'').trim() || 'See code output';

    return {
      code, lang: detectLang(code) || hintLang || 'python',
      desc: remaining.split('\n')[0].trim(),
      input:  inputM  ? inputM[1].trim()  : 'See code above',
      result: resultVal,
      reason: reasonM ? reasonM[1].trim() : 'Code runs correctly',
      explanation: remaining.replace(/INPUT:.+/gi,'').replace(/RESULT:.+/gi,'').replace(/REASON:.+/gi,'').trim()
    };
  }

  // Process NVIDIA response — fix collapsed code + fix Easy/Optimized swap
  function nvidiaMarkdownToHtml(text) {
    if (!text) return '<p>No response received.</p>';

    // Fix collapsed code inside any <code> blocks
    text = text.replace(/<code([^>]*)>([\s\S]*?)<\/code>/g, function(m, attrs, code) {
      return '<code' + attrs + '>' + fixCollapsedCode(code) + '</code>';
    });

    // Detect and fix Easy/Optimized swap
    // NVIDIA sometimes puts optimized code in sol-easy and easy code in sol-opt
    // We detect this by checking if sol-easy contains complexity keywords like O(log n)
    const easyMatch = text.match(/<div class="sol-easy">([\s\S]*?)<\/div>\s*<div class="sol-opt"/);
    const optMatch  = text.match(/<div class="sol-opt"[^>]*>([\s\S]*?)<\/div>\s*<div class="tipb"/);

    if (easyMatch && optMatch) {
      const easyContent = easyMatch[1];
      const optContent  = optMatch[1];
      // If easy content has complexity indicators — they are swapped
      const easyHasComplexity = /O\(log|O\(n log|bisect|more efficient|better complexity/i.test(easyContent);
      const optIsSimpler      = /simple|basic|brute|linear|O\(n\)/i.test(optContent);

      if (easyHasComplexity || optIsSimpler) {
        // Swap the content back to correct order
        text = text.replace(
          /<div class="sol-easy">([\s\S]*?)(<\/div>\s*<div class="sol-opt")([^>]*>)([\s\S]*?)(<\/div>\s*<div class="tipb")/,
          function(m, easyC, mid, optAttrs, optC, after) {
            return '<div class="sol-easy">' + optC + mid + optAttrs + easyC + after;
          }
        );
      }
    }

    return text;
  }


  const callNvidiaModel = (model, apiKey, msgs) => new Promise((resolve, reject) => {
    const nvidiaPayload = JSON.stringify({
      model, messages: msgs, max_tokens: 8192, temperature: 0.7, stream: false
    });
    const opts = {
      hostname: 'integrate.api.nvidia.com',
      path: '/v1/chat/completions',
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${apiKey}`,
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(nvidiaPayload)
      },
      timeout: requestTimeout
    };
    const apiReq = https.request(opts, apiRes => {
      let data = ''; apiRes.on('data', c => data += c);
      apiRes.on('end', () => resolve({ status: apiRes.statusCode, data }));
    });
    apiReq.on('timeout', () => { apiReq.destroy(); reject(new Error(`NVIDIA ${model} Timeout`)); });
    apiReq.on('error', e => reject(e));
    apiReq.write(nvidiaPayload); apiReq.end();
  });

  let lastError = 'No response from AI models.';

  if (GEMINI_KEYS.length > 0) {
    const keyOrder = GEMINI_KEYS.map((_, i) => (preferredKeyIndex + i) % GEMINI_KEYS.length);
    for (const model of modelsToTry) {
      for (const keyIdx of keyOrder) {
        const apiKey = GEMINI_KEYS[keyIdx];
        try {
          const response = await callGemini(model, apiKey);
          if (response.status === 200) {
            const p = JSON.parse(response.data);
            if (p.candidates?.[0]?.content?.parts?.[0]?.text) {
              preferredKeyIndex = keyIdx;
              return res.json({ content: [{ type: 'text', text: p.candidates[0].content.parts[0].text }] });
            }
          } else if (response.status === 429 || response.status === 403) {
            try { lastError = JSON.parse(response.data).error?.message || `Key ${keyIdx + 1} quota exceeded`; } catch {}
            console.warn(`[Key ${keyIdx + 1}] ${model} quota/rate-limited. Trying next key...`);
          } else {
            try { lastError = JSON.parse(response.data).error?.message || `${model} status ${response.status}`; } catch {}
            console.warn(`[Key ${keyIdx + 1}] ${model} failed: ${lastError}`);
          }
        } catch (err) {
          lastError = err.message || 'Network error';
          console.warn(`[Key ${keyIdx + 1}] ${model} error: ${lastError}`);
        }
      }
    }
  }

  if (NVIDIA_KEYS.length > 0) {
    console.warn('⚠️ All Gemini exhausted → NVIDIA fallback...');
    let nvidiaMsgs = null;
    for (const model of NVIDIA_TEXT_MODELS) {
      for (let ki = 0; ki < NVIDIA_KEYS.length; ki++) {
        try {
          if (!nvidiaMsgs) nvidiaMsgs = await buildNvidiaMessages();
          const response = await callNvidiaModel(model, NVIDIA_KEYS[ki], nvidiaMsgs);
          if (response.status === 200) {
            const p    = JSON.parse(response.data);
            const text = p.choices?.[0]?.message?.content;
            if (text) {
              console.log(`✅ NVIDIA success: ${model} (key ${ki + 1})`);
              // If NVIDIA didn't include optimized section, request it separately
              let fullText = text;
              if (!text.includes('===OPTIMIZED===') && nvidiaMsgs) {
                try {
                  const optMsgs = nvidiaMsgs.concat([
                    { role: 'assistant', content: text.slice(0, 500) },
                    { role: 'user', content: 'Now write the ===OPTIMIZED=== version of the same code with better time/space complexity. Use the exact same format: ===OPTIMIZED===, code block, INPUT, RESULT, REASON.' }
                  ]);
                  const optResp = await callNvidiaModel(model, NVIDIA_KEYS[ki], optMsgs);
                  if (optResp.status === 200) {
                    const optParsed = JSON.parse(optResp.data);
                    const optText   = optParsed.choices?.[0]?.message?.content || '';
                    if (optText) fullText = text + '\n' + optText;
                  }
                } catch(e) { /* ignore optimized fetch error */ }
              }
              const cleanText = nvidiaMarkdownToHtml(fullText);
              return res.json({ content: [{ type: 'text', text: cleanText }] });
            }
          } else if (response.status === 429) {
            console.warn(`[NVIDIA Key ${ki + 1}] ${model} rate limited → next...`);
          } else if (response.status === 404) {
            console.warn(`[NVIDIA Key ${ki + 1}] ${model} not available → next model...`);
            break;
          } else {
            try { lastError = JSON.parse(response.data).detail || `NVIDIA ${model} status ${response.status}`; } catch {}
            console.warn(`[NVIDIA Key ${ki + 1}] ${model} failed: ${lastError}`);
          }
        } catch (err) {
          lastError = err.message || 'NVIDIA network error';
          console.warn(`[NVIDIA Key ${ki + 1}] ${model} error: ${lastError}`);
        }
      }
    }
  }

  res.status(500).json({ error: lastError });
});

app.get('*', (_, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

/* ───────────────────────────────────────
   START
─────────────────────────────────────── */
mongoose.connection.once('open', async () => {
  await migrateUserIds();  // backfill id for existing users
  await seedAdmin();
  app.listen(PORT, () => {
    console.log(`\n⚡  CodeMentor AI → http://localhost:${PORT}`);
    console.log(`    🔑  Gemini keys: ${GEMINI_KEYS.length} | NVIDIA keys: ${NVIDIA_KEYS.length}`);
    console.log(`    📝  NVIDIA models: ${NVIDIA_TEXT_MODELS.length} (${NVIDIA_TEXT_MODELS.length * NVIDIA_KEYS.length} total fallback attempts)`);
    if (!BREVO_API_KEY) console.log(`    📧  Brevo not configured — OTP will be logged to console`);
  });
});
