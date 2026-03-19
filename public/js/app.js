/* ══════════════════════════════════════════════════

   CodeMentor AI — app.js (v6)
   - Brevo email, Gemini key hierarchy
   - Settings modal: name / userId / password
   - Attach menu: Image / Document / Project
   - Global admin protections
   - Desktop hamburger sidebar
══════════════════════════════════════════════════ */

/* ── STATE ── */
let CU = null, mode = 'code', lang = 'Auto', busy = false, activeId = null, cache = {};
let regUserId = '', forgotResetToken = '', forgotResetUserId = '';
let currentFile = null;
let sidebarOpen = true; // desktop: sidebar visible by default

/* ── ATTACH MENU ── */
function triggerFileInput(type) {
  closeAttachMenu();
  const ids = { image: 'fileInputImage', document: 'fileInputDoc', project: 'fileInputProject' };
  document.getElementById(ids[type])?.click();
}

function toggleAttachMenu(e) {
  e.stopPropagation();
  const m = document.getElementById('attachMenu');
  const isOpen = m.classList.toggle('open');
  if (isOpen) {
    // close on outside click
    setTimeout(() => document.addEventListener('click', closeAttachMenu, { once: true }), 10);
  }
}

function closeAttachMenu() {
  document.getElementById('attachMenu')?.classList.remove('open');
}

function handleFileUpload(e, fileType) {
  const file = e.target.files[0];
  if (!file) return;
  if (file.size > 10 * 1024 * 1024) return alert('File too large. Max 10MB limit.');
  e.target.value = '';

  const icons = { image: '🖼', document: '📄', project: '📁' };
  const icon = icons[fileType] || '📎';

  const fpEl = document.getElementById('filePreview');
  const fnEl = document.getElementById('fileName');
  if (fpEl) fpEl.style.display = 'flex';
  if (fnEl) fnEl.innerHTML = '<span class="upload-spinner"></span><span class="upload-label">Reading file…</span>';

  const reader = new FileReader();
  reader.onprogress = evt => {
    if (evt.lengthComputable && fnEl) {
      const pct = Math.round((evt.loaded / evt.total) * 100);
      fnEl.innerHTML = `<span class="upload-spinner"></span><span class="upload-label">Loading ${pct}%…</span>`;
    }
  };
  reader.onload = evt => {
    const base64 = evt.target.result.split(',')[1];
    currentFile = { data: base64, mimeType: file.type, name: file.name };
    if (fnEl) fnEl.innerHTML = icon + ' ' + file.name;
    if (fpEl) fpEl.style.display = 'flex';
  };
  reader.readAsDataURL(file);
}

function clearFile() {
  currentFile = null;
  ['fileInputImage','fileInputDoc','fileInputProject'].forEach(id => {
    const el = document.getElementById(id); if (el) el.value = '';
  });
  const fp = document.getElementById('filePreview');
  if (fp) fp.style.display = 'none';
}

/* ── THEME ── */
const savedTh = localStorage.getItem('cm_theme') || 'dark';
document.documentElement.setAttribute('data-theme', savedTh);
updateThemeBtn(savedTh);
function toggleTheme() {
  const n = document.documentElement.getAttribute('data-theme') === 'dark' ? 'light' : 'dark';
  document.documentElement.setAttribute('data-theme', n);
  localStorage.setItem('cm_theme', n);
  updateThemeBtn(n);
}
function updateThemeBtn(t) {
  const b = document.getElementById('themeBtn');
  if (b) b.textContent = t === 'dark' ? '🌙' : '☀️';
}

/* ── API HELPER ── */
async function api(method, url, body) {
  const r = await fetch(url, {
    method, credentials: 'include',
    headers: { 'Content-Type': 'application/json' },
    body: body ? JSON.stringify(body) : undefined
  });
  return r.json();
}
const esc = s => String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');

/* ── INIT ── */
(async () => {
  const res = await api('GET', '/api/auth/me'); // just check session — no forced logout
  if (res.user) loginOk(res.user);
  else document.getElementById('authModal').classList.add('open');
})();


/* ══════════════════════════════════════

   AUTH TABS
══════════════════════════════════════ */

function switchAuthTab(tab) {
  ['login','reg','forgot'].forEach(t => {
    document.getElementById('form-' + t).style.display = 'none';
  });
  document.getElementById('form-' + tab).style.display = 'block';
  document.getElementById('tab-login')?.classList.toggle('active', tab === 'login');
  document.getElementById('tab-reg')?.classList.toggle('active', tab === 'reg');
  // Reset forgot steps
  if (tab === 'forgot') {
    document.getElementById('forgot-step1').style.display = '';
    document.getElementById('forgot-step2').style.display = 'none';
    document.getElementById('forgot-step3').style.display = 'none';
    const otp = document.getElementById('forgotOtpInput'); if (otp) otp.value = '';
  }
  clearAuthErrors();
}
function clearAuthErrors() {
  ['loginErr','regErr','forgotErr','forgotOk','forgotOtpErr','forgotOtpOk','forgotResetErr','forgotResetOk','pwErr','pwOk'].forEach(id => {
    const el = document.getElementById(id);
    if (el) el.textContent = '';
  });
}

/* ══════════════════════════════════════

   SIGN IN
══════════════════════════════════════ */

async function doLogin() {
  const userId   = document.getElementById('loginUserId').value.trim();
  const password = document.getElementById('loginPass').value;
  const err      = document.getElementById('loginErr');
  err.textContent = '';
  if (!userId || !password) { err.textContent = 'Please fill in all fields.'; return; }
  const res = await api('POST', '/api/auth/login', { userId, password });
  if (res.error) { err.textContent = res.error; return; }
  loginOk(res.user);
}

function loginOk(user) {
  CU = user;
  document.getElementById('authModal').classList.remove('open');
  const ini = user.name.split(' ').map(w => w[0]).join('').toUpperCase().slice(0, 2);
  document.getElementById('userAvatar').textContent = ini;
  document.getElementById('userName').textContent   = user.name;
  const roleEl = document.getElementById('userRole');
  const isGlobalAdmin = (user.userId === 'admin');
  roleEl.textContent = user.role === 'admin'
    ? (isGlobalAdmin ? '⬡ Global Admin' : '⬡ Administrator')
    : '@' + user.userId;
  roleEl.className = 'user-role' + (user.role === 'admin' ? ' admin-role' : '');
  const adm = user.role === 'admin';
  document.getElementById('sbAdminBtn').style.display  = adm ? '' : 'none';
  document.getElementById('topAdminBtn').style.display = adm ? '' : 'none';
  loadChatList();
}

async function doLogout() {
  await api('POST', '/api/auth/logout');
  CU = null; activeId = null; cache = {};
  document.getElementById('authModal').classList.add('open');
  // Clear login fields
  document.getElementById('loginUserId').value = '';
  document.getElementById('loginPass').value   = '';
  // Clear sign-up fields so data doesn't persist after logout
  ['regName','regUserId','regEmail','regPass','regSecAnswer'].forEach(id => {
    const el = document.getElementById(id); if (el) el.value = '';
  });

  // Clear displayed user details so they don't leak
  const userNameEl = document.getElementById('userName');
  if (userNameEl) userNameEl.textContent = '—';
  const userAvatarEl = document.getElementById('userAvatar');
  if (userAvatarEl) userAvatarEl.textContent = '?';
  const roleEl = document.getElementById('userRole');
  if (roleEl) { roleEl.textContent = 'member'; roleEl.className = 'user-role'; }
  document.getElementById('sbAdminBtn').style.display = 'none';
  document.getElementById('topAdminBtn').style.display = 'none';

  document.getElementById('uidHint').textContent = '';
  document.getElementById('pwHint').textContent  = 'Enter a password';
  ['pb1','pb2','pb3'].forEach(id => { const el = document.getElementById(id); if (el) el.className = 'pw-bar'; });
  switchAuthTab('login');
  closeSidebar();
}

/* ══════════════════════════════════════

   REGISTER (2 steps: info → OTP)
══════════════════════════════════════ */

function checkUid(val) {
  const hint = document.getElementById('uidHint');
  if (!val) { hint.textContent = ''; return; }
  if (!/^[a-zA-Z0-9_]{3,20}$/.test(val)) {
    hint.textContent = '✗ Letters, numbers and underscore only (3–20 chars)';
    hint.style.color = 'var(--red)';
  } else {
    hint.textContent = '✓ Looks good';
    hint.style.color = 'var(--green)';
  }
}

function pwStrength(val) {
  const b1 = document.getElementById('pb1');
  const b2 = document.getElementById('pb2');
  const b3 = document.getElementById('pb3');
  const h  = document.getElementById('pwHint');
  [b1,b2,b3].forEach(b => { b.className = 'pw-bar'; });
  if (!val) { h.textContent = 'Enter a password'; h.style.color = ''; return; }
  let score = 0;
  if (val.length >= 8) score++;
  if (/[A-Z]/.test(val) && /[a-z]/.test(val)) score++;
  if (/[0-9]/.test(val) && /[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>/?`~]/.test(val)) score++;
  const cls   = ['','w','m','s'];
  const label = ['Too weak','Weak','Medium','Strong'];
  const color = ['var(--red)','var(--red)','var(--amber)','var(--green)'];
  for (let i = 0; i < score; i++) [b1,b2,b3][i].classList.add(cls[score]);
  h.textContent = label[score] || 'Too weak'; h.style.color = color[score] || 'var(--red)';
}

function validatePasswordClient(pass) {
  if (pass.length < 8)                   return 'Password must be at least 8 characters.';
  if (!/[A-Z]/.test(pass))              return 'Need at least one uppercase letter.';
  if (!/[a-z]/.test(pass))              return 'Need at least one lowercase letter.';
  if (!/[0-9]/.test(pass))              return 'Need at least one number.';
  if (!/[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>/?`~]/.test(pass)) return 'Need at least one special character.';
  return null;
}

function togglePw(btn, inputId) {
  const inp = document.getElementById(inputId);
  if (!inp) return;
  if (inp.type === 'password') {
    inp.type = 'text';
    btn.textContent = '🙈';
    btn.classList.add('active');
  } else {
    inp.type = 'password';
    btn.textContent = '👁';
    btn.classList.remove('active');
  }
}

async function doRegister() {
  const name      = document.getElementById('regName').value.trim();
  const userId    = document.getElementById('regUserId').value.trim();
  const email     = document.getElementById('regEmail').value.trim();
  const pass      = document.getElementById('regPass').value;
  const secAnswer = document.getElementById('regSecAnswer').value.trim();
  const err       = document.getElementById('regErr');
  err.textContent = ''; err.style.color = 'var(--red)';

  if (!name || !userId || !email || !pass || !secAnswer) { err.textContent = 'All fields are required, including the security answer.'; return; }
  if (!/^[a-zA-Z0-9_]{3,20}$/.test(userId)) { err.textContent = 'Invalid User ID format.'; return; }

  const pwErr = validatePasswordClient(pass);
  if (pwErr) { err.textContent = pwErr; return; }

  const btn = document.querySelector('#form-reg .auth-btn');
  btn.disabled = true; btn.textContent = 'Creating account…';

  const res = await api('POST', '/api/auth/register/send-otp', {
    userId, name, password: pass, method: 'email', contact: email, securityAnswer: secAnswer
  });
  btn.disabled = false; btn.textContent = 'Create Account →';

  if (res.error) { err.textContent = res.error; return; }

  regUserId = userId;
  err.style.color = 'var(--green)';
  err.textContent = `✓ OTP sent to ${email} — check your inbox.`;

  const existing = document.getElementById('regOtpSection');
  if (!existing) {
    const otpSec = document.createElement('div');
    otpSec.id = 'regOtpSection';
    otpSec.innerHTML = `
      <div class="fg" style="margin-top:14px">
        <label class="fl">Enter 6-digit OTP from your email</label>
        <input class="fi" id="regOtpInput" type="text" maxlength="6" placeholder="123456"
          style="letter-spacing:.2em;font-size:18px;text-align:center;font-weight:700">
      </div>
      <button class="auth-btn" onclick="verifyRegOtp()" style="margin-top:0">Verify & Sign In →</button>
      <div class="f-err" id="regOtpErr"></div>`;
    document.querySelector('#form-reg').appendChild(otpSec);
  }
  document.getElementById('regOtpInput')?.focus();
}

async function verifyRegOtp() {
  const otp = document.getElementById('regOtpInput')?.value?.trim();
  const err = document.getElementById('regOtpErr');
  if (err) err.textContent = '';
  if (!otp || otp.length < 6) { if (err) err.textContent = 'Enter the 6-digit OTP.'; return; }

  const btn = document.querySelector('#regOtpSection .auth-btn');
  btn.disabled = true; btn.textContent = 'Verifying…';

  const res = await api('POST', '/api/auth/register/verify-otp', { userId: regUserId, otp });
  btn.disabled = false; btn.textContent = 'Verify & Sign In →';

  if (res.error) { if (err) err.textContent = res.error; return; }
  loginOk(res.user);
}

/* ══════════════════════════════════════

   FORGOT PASSWORD — 3-step OTP flow
   Step 1: Enter userId → OTP emailed
   Step 2: Enter OTP → get reset token
   Step 3: Set new password
══════════════════════════════════════ */

async function doForgotSendOtp() {
  const userId = document.getElementById('forgotUserId').value.trim();
  const err    = document.getElementById('forgotErr');
  const ok     = document.getElementById('forgotOk');
  err.textContent = ''; ok.textContent = '';
  if (!userId) { err.textContent = 'Please enter your User ID.'; return; }
  const btn = document.querySelector('#forgot-step1 .auth-btn');
  btn.disabled = true; btn.textContent = 'Sending OTP...';
  const res = await api('POST', '/api/auth/forgot/send-otp', { userId });
  btn.disabled = false; btn.textContent = 'Send OTP to Email →';
  if (res.error) { err.textContent = res.error; return; }
  forgotResetUserId = userId;
  ok.textContent = '✓ OTP sent! Check your email inbox.';
  setTimeout(() => {
    document.getElementById('forgot-step1').style.display = 'none';
    document.getElementById('forgot-step2').style.display = '';
  }, 800);
}

async function doForgotVerifyOtp() {
  const otp = document.getElementById('forgotOtpInput').value.trim();
  const err = document.getElementById('forgotOtpErr');
  const ok  = document.getElementById('forgotOtpOk');
  err.textContent = ''; ok.textContent = '';
  if (!otp || otp.length !== 6) { err.textContent = 'Enter the 6-digit OTP from your email.'; return; }
  const btn = document.querySelector('#forgot-step2 .auth-btn');
  btn.disabled = true; btn.textContent = 'Verifying...';
  const res = await api('POST', '/api/auth/forgot/verify-otp', { userId: forgotResetUserId, otp });
  btn.disabled = false; btn.textContent = 'Verify OTP →';
  if (res.error) { err.textContent = res.error; return; }
  forgotResetToken = res.token;
  ok.textContent = '✓ OTP verified!';
  setTimeout(() => {
    document.getElementById('forgot-step2').style.display = 'none';
    document.getElementById('forgot-step3').style.display = '';
  }, 600);
}

async function doForgotReset() {
  const newPass = document.getElementById('forgotNew').value;
  const confirm = document.getElementById('forgotConfirm').value;
  const err     = document.getElementById('forgotResetErr');
  const ok      = document.getElementById('forgotResetOk');
  err.textContent = ''; ok.textContent = '';
  if (!newPass || !confirm) { err.textContent = 'All fields are required.'; return; }
  if (newPass !== confirm)  { err.textContent = 'Passwords do not match.'; return; }
  const pwErr = validatePasswordClient(newPass);
  if (pwErr) { err.textContent = pwErr; return; }
  const btn = document.querySelector('#forgot-step3 .auth-btn');
  btn.disabled = true; btn.textContent = 'Resetting…';
  const res = await api('POST', '/api/auth/forgot/reset', {
    userId: forgotResetUserId, token: forgotResetToken,
    newPassword: newPass, confirmPassword: confirm
  });
  btn.disabled = false; btn.textContent = 'Reset Password →';
  if (res.error) { err.textContent = res.error; return; }
  ok.textContent = '✓ ' + res.message;
  setTimeout(() => switchAuthTab('login'), 2200);
}

/* ══════════════════════════════════════

   CHANGE PASSWORD
══════════════════════════════════════ */

function openPasswordModal() {
  ['pwCurrent','pwSecAnswer','pwNew','pwConfirm'].forEach(id => {
    const el = document.getElementById(id); if (el) el.value = '';
  });
  document.getElementById('pwErr').textContent = '';
  document.getElementById('pwOk').textContent  = '';
  document.getElementById('passwordModal').classList.add('open');
}
function closePasswordModal() {
  document.getElementById('passwordModal').classList.remove('open');
}
async function doChangePassword() {
  const current   = document.getElementById('pwCurrent').value;
  const secAnswer = document.getElementById('pwSecAnswer')?.value?.trim() || '';
  const newPass   = document.getElementById('pwNew').value;
  const confirm   = document.getElementById('pwConfirm').value;
  const err = document.getElementById('pwErr');
  const ok  = document.getElementById('pwOk');
  err.textContent = ''; ok.textContent = '';

  if (!current || !secAnswer || !newPass || !confirm) { err.textContent = 'All fields are required.'; return; }
  if (newPass !== confirm) { err.textContent = 'Passwords do not match.'; return; }
  const pwErr = validatePasswordClient(newPass);
  if (pwErr) { err.textContent = pwErr; return; }

  const res = await api('POST', '/api/auth/change-password', {
    currentPassword: current, securityAnswer: secAnswer,
    newPassword: newPass, confirmPassword: confirm
  });
  if (res.error) { err.textContent = res.error; return; }
  ok.textContent = '✓ ' + res.message;

  // Clear the inputs immediately to prevent cache / back-button stealing
  document.getElementById('pwCurrent').value = '';
  if (document.getElementById('pwSecAnswer')) document.getElementById('pwSecAnswer').value = '';
  document.getElementById('pwNew').value = '';
  document.getElementById('pwConfirm').value = '';

  setTimeout(() => {
    closePasswordModal();
    doLogout();
  }, 2000);
}

/* ══════════════════════════════════════

   SIDEBAR
══════════════════════════════════════ */

function toggleSidebar() {
  const sb   = document.getElementById('sidebar');
  const ov   = document.getElementById('ov');
  const main = document.getElementById('mainArea');
  const isMobile = window.innerWidth <= 768;
  if (isMobile) {
    sb.classList.toggle('open');
    ov.classList.toggle('show');
  } else {
    sidebarOpen = !sidebarOpen;
    sb.classList.toggle('sb-hidden', !sidebarOpen);
    main.classList.toggle('sb-collapsed', !sidebarOpen);
  }
}
function closeSidebar() {
  document.getElementById('sidebar').classList.remove('open');
  document.getElementById('ov').classList.remove('show');
}

/* ══════════════════════
   SETTINGS MODAL
══════════════════════ */
function openSettingsModal() {
  const nameEl = document.getElementById('settingsName');
  if (nameEl && CU) nameEl.value = CU.name || '';
  ['nameErr','nameOk','uidErr','uidOk','pwErr','pwOk'].forEach(id => {
    const el = document.getElementById(id); if (el) el.textContent = '';
  });
  ['pwCurrent','pwSecAnswer','pwNew','pwConfirm','settingsNewUserId','settingsUidPass'].forEach(id => {
    const el = document.getElementById(id); if (el) el.value = '';
  });
  const h = document.getElementById('uidHintSettings'); if (h) h.textContent = '';
  switchSettingsTab('profile');
  document.getElementById('settingsModal').classList.add('open');
}
function closeSettingsModal() {
  document.getElementById('settingsModal').classList.remove('open');
}
function switchSettingsTab(tab) {
  ['profile','userid','password'].forEach(t => {
    document.getElementById('spane-' + t).style.display = t === tab ? '' : 'none';
    document.getElementById('stab-'  + t).classList.toggle('active', t === tab);
  });
}
function checkUidSettings(val) {
  const hint = document.getElementById('uidHintSettings');
  if (!hint) return;
  if (!val) { hint.textContent = ''; return; }
  if (!/^[a-zA-Z0-9_]{3,20}$/.test(val)) {
    hint.textContent = '✗ Letters, numbers and underscore only (3–20 chars)';
    hint.style.color = 'var(--red)';
  } else {
    hint.textContent = '✓ Looks good';
    hint.style.color = 'var(--green)';
  }
}
async function doUpdateName() {
  const name = document.getElementById('settingsName').value.trim();
  const err = document.getElementById('nameErr');
  const ok  = document.getElementById('nameOk');
  err.textContent = ''; ok.textContent = '';
  if (!name) { err.textContent = 'Name cannot be empty.'; return; }
  const res = await api('POST', '/api/auth/settings/update-name', { name });
  if (res.error) { err.textContent = res.error; return; }
  CU = res.user || CU;
  document.getElementById('userName').textContent = CU.name;
  const ini = CU.name.split(' ').map(w => w[0]).join('').toUpperCase().slice(0, 2);
  document.getElementById('userAvatar').textContent = ini;
  ok.textContent = '✓ ' + res.message;
}
async function doUpdateUserId() {
  const newUserId = document.getElementById('settingsNewUserId').value.trim();
  const pass      = document.getElementById('settingsUidPass').value;
  const err = document.getElementById('uidErr');
  const ok  = document.getElementById('uidOk');
  err.textContent = ''; ok.textContent = '';
  if (!newUserId || !pass) { err.textContent = 'All fields are required.'; return; }
  if (!/^[a-zA-Z0-9_]{3,20}$/.test(newUserId)) { err.textContent = 'Invalid User ID format.'; return; }
  const res = await api('POST', '/api/auth/settings/update-userid', { newUserId, currentPassword: pass });
  if (res.error) { err.textContent = res.error; return; }
  CU = res.user || CU;
  document.getElementById('userRole').textContent = CU.role === 'admin' ? '◡ Administrator' : '@' + CU.userId;
  ok.textContent = '✓ ' + res.message;
  // Clear inputs immediately
  document.getElementById('settingsNewUserId').value = '';
  document.getElementById('settingsUidPass').value = '';
}
/* alias for old calls */
function openPasswordModal()  { openSettingsModal(); switchSettingsTab('password'); }
function closePasswordModal() { closeSettingsModal(); }

/* ══════════════════════════════════════

   CHAT LIST
══════════════════════════════════════ */

async function loadChatList(silent = false) {
  const res   = await api('GET', '/api/chats');
  const list  = document.getElementById('chatList');
  const empty = document.getElementById('sbEmpty');
  list.querySelectorAll('.cl-label, .chat-item').forEach(e => e.remove());

  if (!res.chats?.length) {
    empty.style.display = 'block';
    if (!activeId && !silent) showWelcome();
    return;
  }
  empty.style.display = 'none';

  const now = Date.now(), DAY = 86400000;
  const grp = { Today: [], Yesterday: [], Older: [] };
  res.chats.forEach(c => {
    const age = now - c.ts;
    if (age < DAY)        grp.Today.push(c);
    else if (age < 2*DAY) grp.Yesterday.push(c);
    else                  grp.Older.push(c);
  });

  Object.entries(grp).forEach(([lbl, chats]) => {
    if (!chats.length) return;
    const l = document.createElement('div');
    l.className = 'cl-label'; l.textContent = lbl;
    list.appendChild(l);
    chats.forEach(c => list.appendChild(buildChatItem(c)));
  });

  list.querySelectorAll('.chat-item').forEach(el =>
    el.classList.toggle('active', el.dataset.id === activeId)
  );

  if (!activeId && !silent && res.chats.length) switchChat(res.chats[0].id);
  else if (!activeId && !silent) showWelcome();
}

function buildChatItem(c) {
  const el = document.createElement('div');
  el.className = 'chat-item' + (c.id === activeId ? ' active' : '');
  el.dataset.id = c.id;
  el.innerHTML = `
    <div class="ci-dot"></div>
    <span class="chat-item-title">${esc(c.title)}</span>
    <div class="chat-item-actions">
      <button class="ci-btn" title="Rename" onclick="event.stopPropagation();startRename('${c.id}',this)">✎</button>
      <button class="ci-btn danger" title="Delete" onclick="event.stopPropagation();deleteChat('${c.id}')">✕</button>
    </div>`;
  el.onclick = () => switchChat(c.id);
  return el;
}

function startRename(id, btn) {
  const item  = btn.closest('.chat-item');
  const title = item.querySelector('.chat-item-title');
  const inp   = document.createElement('input');
  inp.className = 'ci-rename-input'; inp.value = title.textContent;
  item.replaceChild(inp, title); inp.focus(); inp.select();
  const commit = async () => {
    const val = inp.value.trim() || title.textContent;
    title.textContent = val; item.replaceChild(title, inp);
    if (id === activeId) document.getElementById('chatTitleDisplay').textContent = val;
    await api('PUT', `/api/chats/${id}`, { title: val });
  };
  inp.onblur    = commit;
  inp.onkeydown = e => { if (e.key === 'Enter') inp.blur(); if (e.key === 'Escape') item.replaceChild(title, inp); };
}

async function newChat() {
  const res = await api('POST', '/api/chats', { title: 'New Chat' });
  if (!res.chat) return;
  cache[res.chat.id] = { history: [], rendered: [] };
  activeId = res.chat.id;
  document.getElementById('chatTitleDisplay').textContent = 'New Chat';
  showWelcome();
  await loadChatList();
  closeSidebar();
}

async function switchChat(id) {
  activeId = id;
  const res = await api('GET', `/api/chats/${id}`);
  const chatData = res.chat || res;
  cache[id] = { history: chatData.history || [], rendered: chatData.rendered || [] };
  const listRes = await api('GET', '/api/chats');
  const meta    = (listRes.chats || []).find(c => c.id === id);
  document.getElementById('chatTitleDisplay').textContent = meta?.title || 'Chat';
  const msgs = document.getElementById('messages');
  msgs.innerHTML = '';
  if (cache[id].rendered?.length) cache[id].rendered.forEach(r => renderMessage(r.role, r.content, r.isHTML));
  else showWelcome();
  document.querySelectorAll('.chat-item').forEach(el => el.classList.toggle('active', el.dataset.id === id));
  scrollToBottom();
  closeSidebar();
}

async function deleteChat(id) {
  if (!confirm('Delete this chat?')) return;
  await api('DELETE', `/api/chats/${id}`);
  delete cache[id];
  if (id === activeId) activeId = null;
  loadChatList();
}

function goHome() {
  activeId = null;
  document.getElementById('chatTitleDisplay').textContent = 'New Chat';
  showWelcome(); closeSidebar();
}

/* ══════════════════════════════════════

   WELCOME SCREEN
══════════════════════════════════════ */

function showWelcome() {
  document.getElementById('messages').innerHTML = `
    <div class="welcome" id="welcomeScreen">
      <div class="welcome-headline">
        <h1>Code <em>Smarter.</em><br>Ship Faster.</h1>
        <div class="wh-sub">
          <span class="wh-badge amber">✦ Ask Anything</span>
          <span class="wh-badge blue">⚡ AI for Students</span>
          <span class="wh-badge green">📎 Upload Code</span>
        </div>
      </div>
      <div class="suggestions">
        <div class="suggestion-card" onclick="quickAsk('Write a binary search in Python — easy and optimized versions')"><div class="sg-tag">Algorithm</div><div class="sg-title">Binary Search</div><div class="sg-desc">Easy + Optimized</div></div>
        <div class="suggestion-card" onclick="quickAsk('Frontend developer roadmap 2025 — structured phases')"><div class="sg-tag">Roadmap</div><div class="sg-title">Dev Roadmap</div><div class="sg-desc">Phase-by-phase path</div></div>
        <div class="suggestion-card" onclick="quickAsk('Explain recursion with simple then advanced example')"><div class="sg-tag">Concept</div><div class="sg-title">Recursion</div><div class="sg-desc">Simple → Advanced</div></div>
        <div class="suggestion-card" onclick="quickAsk('Build a REST API in Node.js — beginner friendly')"><div class="sg-tag">Backend</div><div class="sg-title">REST API</div><div class="sg-desc">Node.js explained</div></div>
        <div class="suggestion-card" onclick="quickAsk('Explain Big O notation with code examples')"><div class="sg-tag">Complexity</div><div class="sg-title">Big O</div><div class="sg-desc">With real examples</div></div>
        <div class="suggestion-card" onclick="quickAsk('React todo app with hooks — easy and optimized')"><div class="sg-tag">Frontend</div><div class="sg-title">React App</div><div class="sg-desc">Hooks + Best practices</div></div>
      </div>
    </div>`;
}

/* ══════════════════════════════════════

   MODE & LANG
══════════════════════════════════════ */

function setMode(m, el) {
  mode = m;
  document.querySelectorAll('.mode-pill').forEach(p => p.classList.remove('active'));
  el.classList.add('active');
  const lbl = { code:'✦ code', explain:'◎ explain', debug:'⚑ debug', roadmap:'◈ roadmap', optimize:'⌬ optimize' };
  document.getElementById('modeTag').textContent = lbl[m] || '✦ code';
  const ph = { code:'Ask anything — write code, debug, explain a concept…', explain:'Paste code or describe a concept to explain…', debug:'Paste buggy code and describe the error…', roadmap:'Name a skill or technology to learn…', optimize:'Paste code to optimize…' };
  document.getElementById('msgInput').placeholder = ph[m] || ph.code;
}
function setLang(btn, l) {
  lang = l;
  document.querySelectorAll('.lang-btn').forEach(b => b.classList.remove('active'));
  btn.classList.add('active');
  document.getElementById('langTag').textContent = '◎ ' + l.toLowerCase();
}
function handleKey(e) { if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); sendMessage(); } }
function autoResize(el) { el.style.height = 'auto'; el.style.height = Math.min(el.scrollHeight, 155) + 'px'; document.getElementById('charCount').textContent = el.value.length + ' / 2000'; }
function quickAsk(t) { document.getElementById('msgInput').value = t; autoResize(document.getElementById('msgInput')); sendMessage(); }

/* ══════════════════════════════════════

   SYSTEM PROMPT
══════════════════════════════════════ */

const SYSTEM = `You are CodeMentor AI — a friendly coding teacher for beginners and students.
Respond in PURE HTML ONLY. Zero markdown. Zero asterisks. Zero hash symbols. Zero backticks.

════════════════════════════════════════════

RULE 1 — ALWAYS GIVE TWO CODE VERSIONS
════════════════════════════════════════════

Unless the user uploaded ANY file (like an image, PDF, document, or code script), structure EVERY plain code request like this:

<h3>🧠 Concept Explanation</h3>
<p>[Give a clear, 2-to-3 sentence explanation with a real-world analogy.]</p>

<div class="solution-tabs"><button class="sol-tab easy-tab active" onclick="showSolution(this,'easy')">⬡ Easy</button><button class="sol-tab opt-tab" onclick="showSolution(this,'optimized')">⌬ Optimized</button></div>
<div class="sol-easy">
<p>[How the Easy version works]</p>
[CODE with green comments on EVERY single line, never smashed]
<div class="out-block"><div class="out-header">▶ Expected Output</div><div class="out-body"><p class="out-line"><strong>Input &nbsp;&nbsp;:</strong> [the exact input values used in this code]</p><p class="out-line"><strong>Result &nbsp;:</strong> [the exact output value printed or returned]</p><p class="out-line"><strong>Reason &nbsp;:</strong> [one short sentence — why is this the correct answer]</p></div></div>
<h3>📖 Line-by-Line Explanation</h3>
<ul>
<li><strong>🔷 KEYWORD</strong> <code>def</code> — Explanation...</li>
<li><strong>⬜ CODE</strong> <code>x = 0</code> — Explanation...</li>
</ul>
<div class="trace-block"><div class="trace-header">🔍 Real-Time Test Case Execution</div><div class="trace-body">Step-by-step trace here (5-6 steps)...</div></div>
</div>
<div class="sol-opt" style="display:none">
<p>[Why this Optimized version is better]</p>
[OPTIMIZED CODE with green comments]
<div class="out-block"><div class="out-header">▶ Expected Output</div><div class="out-body"><p class="out-line"><strong>Input &nbsp;&nbsp;:</strong> [the exact input values used in this code]</p><p class="out-line"><strong>Result &nbsp;:</strong> [the exact output value printed or returned]</p><p class="out-line"><strong>Reason &nbsp;:</strong> [one short sentence — why is this the correct answer]</p></div></div>
<h3>📖 Line-by-Line Explanation</h3>
<ul><li>... (full list for ALL lines here) ...</li></ul>
</div>

════════════════════════════════════════════

RULE 2 — CODE FORMAT & COMMENTS
════════════════════════════════════════════

CRITICAL: Every line of code MUST have a comment.
- Green comment on one line, actual code on the VERY NEXT line.
- NEVER put multiple code statements on a single line.
- Use correct syntax (// for Java/C/JS/C++, # for Python).

LAYOUT CRITICAL — NO PARALLEL / SIDE-BY-SIDE CODE EVER:
- NEVER place two code blocks next to each other horizontally.
- NEVER use columns, grids, flex-row, or tables to show code side by side.
- ALL code blocks must stack VERTICALLY, one after another, full width.
- Easy version first → then Optimized version below it (hidden by tab).

FULL PROGRAM WRAPPERS — ALWAYS wrap in complete runnable program:

JAVA — ALWAYS use full class. NEVER show a bare method alone.
  Use data-lang="java" on the code block.
  public class Main {
    public static void main(String[] args) {
      // call the method and print result here
    }
    public static [returnType] methodName(...) {
      // method body here
    }
  }

C — ALWAYS include #include headers and int main(). NEVER show a bare function.
  Use data-lang="c" on the code block.
  CRITICAL: The data-lang attribute MUST be exactly "c" (lowercase).
  #include <stdio.h>
  #include <stdlib.h>
  // function definition above main
  int methodName(int arr[], int n, int target) {
    // function body
  }
  int main() {
    // declare variables and call the function here
    printf("Result: ...");
    return 0;
  }

PYTHON — ALWAYS wrap with if __name__ == "__main__":
  Use data-lang="python" on the code block.
  def method_name(...):
    # function body
  if __name__ == "__main__":
    # call the function and print result here

════════════════════════════════════════════

RULE 3 — NO SKIPPING IN EXPLANATIONS
════════════════════════════════════════════

CRITICAL: You MUST create a bullet point in "Line-by-Line Explanation" for absolutely EVERY SINGLE line of code shown in the blocks above.
Labels: 🔷 KEYWORD, 🟡 FUNCTION, 🟢 BUILT-IN, ⬜ CODE.

════════════════════════════════════════════

Always provide a deep, step-by-step trace in the "Real-Time Test Case Execution".
- Use the <div class="trace-block"> structure.
- EVERY step must be its own <div class="trace-step">.
- NEVER write steps as a single paragraph.

Example:
<div class="trace-block">
  <div class="trace-step"><span class="trace-n">Input</span><span class="trace-desc">We start with...</span></div>
  <div class="trace-step"><span class="trace-n">Step 1</span><span class="trace-desc">Calculate mid...</span></div>
</div>

════════════════════════════════════════════

RULE 6 — HTML ELEMENTS TO USE
════════════════════════════════════════════
- Paragraph: <p>text</p>
- Bold word: <strong>word</strong>
- Section heading: <h3>Heading</h3>
- Bullet list: <ul><li>item</li></ul>
- Code block: <pre><code data-lang="python">
// Every line must be beautifully indented
// One statement per line
your code here
</code></pre>
- Inline code reference: <code>variable_name</code>
- Time complexity: <span class="cx easy">O(n²)</span>  (or cx medium or cx hard)
- Tip / encouragement: <div class="tipb">your tip here</div>

════════════════════════════════════════════
RULE 7 — WRITING STYLE
════════════════════════════════════════════
- Write explanations like a kind, patient teacher talking to a beginner
- Use real-world analogies (like comparing a loop to shuffling cards)
- NEVER use words like: iterate, traverse, instantiate, invoke, implement, algorithm (unless explaining it)
- Instead use: go through, run, create, call, step, method, recipe

════════════════════════════════════════════
RULE 8 — END EVERY RESPONSE WITH A TIP
════════════════════════════════════════════
Always finish with: <div class="tipb">encouraging message for the student</div>

════════════════════════════════════════════
RULE 9 — ROADMAP MODE: DYNAMIC PHASE BOXES
════════════════════════════════════════════
When in Roadmap mode, use this EXACT structure for each phase (do NOT use rmg/rs classes):

<div class="rm-phase-grid">
  <div class="rm-phase-card">
    <div class="rm-phase-head">
      <span class="rm-phase-num">Phase 1</span>
      <span class="rm-phase-time">⏱ 2–4 weeks</span>
    </div>
    <div class="rm-phase-title">Foundation</div>
    <div class="rm-phase-skills">
      <span class="rm-skill">HTML Basics</span>
      <span class="rm-skill">CSS Selectors</span>
      <span class="rm-skill">JavaScript Variables</span>
    </div>
    <div class="rm-phase-goal">By the end of this phase you will be able to build a simple web page.</div>
  </div>
  <div class="rm-phase-card">
    ... next phase ...
  </div>
</div>

Always show 4 to 6 phases going from Beginner → Intermediate → Advanced → Expert.
Use real skill names as rm-skill tags. The rm-phase-time should be realistic for a student learning on their own.
After the grid, add a short motivational paragraph and a tipb box.

════════════════════════════════════════════
RULE 10 — FILE UPLOADS (IMAGES, SCRIPTS, DOCUMENTS)
════════════════════════════════════════════
When a user uploads ANY file, you will receive its contents like [IMAGE UPLOADED: ...], [CODE/TEXT FILE: ...], or [PDF DOCUMENT: ...]:
- CRITICAL: IGNORE RULE 1 (Do NOT generate Easy/Optimized tabs!).
- Read the content and purely EXPLAIN the information logically in plain English paragraphs and bullet points.
- If it's a code script, diagram, or pseudocode, explain what it is doing logically.
- DO NOT output implemented code blocks unless the user explicitly types a written request like "Write the code for this" or "Fix and run this code".
- NEVER write python/javascript code to try to open or process the raw file itself!`;

/* ══════════════════════════════════════
   SERVICE UNAVAILABLE BANNER
══════════════════════════════════════ */

function showServiceBanner() {
  // Remove any existing banner
  document.getElementById('serviceBanner')?.remove();

  const banner = document.createElement('div');
  banner.id = 'serviceBanner';
  banner.className = 'service-banner';
  banner.innerHTML = `
    <div class="sb-icon">⚡</div>
    <div class="sb-content">
      <div class="sb-title">Service Temporarily Unavailable</div>
      <div class="sb-msg">Our AI models are currently overwhelmed or out of quota. Please try again shortly.</div>
    </div>
    <button class="sb-close" onclick="document.getElementById('serviceBanner')?.remove()" title="Dismiss">✕</button>
  `;
  document.getElementById('messages').appendChild(banner);
  scrollToBottom();
}

/* ══════════════════════════════════════
   SEND MESSAGE
══════════════════════════════════════ */
async function sendMessage() {
  const inp  = document.getElementById('msgInput');
  const text = inp.value.trim();
  if ((!text && !currentFile) || busy) return;

  const displayTitle = text || (currentFile
    ? `📎 ${currentFile.name.replace(/\.[^.]+$/, '')}` // Use filename without extension
    : 'New Chat');

  if (!activeId) {
    const title = displayTitle.slice(0,50) + (displayTitle.length > 50 ? '…' : '');
    const res   = await api('POST', '/api/chats', { title });
    if (!res.chat) return;
    activeId = res.chat.id;
    cache[activeId] = { history: [], rendered: [] };
    document.getElementById('chatTitleDisplay').textContent = res.chat.title;
    await loadChatList();
  }

  document.getElementById('welcomeScreen')?.remove();
  busy = true;
  document.getElementById('sendBtn').disabled = true;

  const hints = {
    code:     `Give EASY and OPTIMIZED versions. Language: ${lang}.`,
    explain:  'Use a real-world analogy first, then code examples.',
    debug:    'Explain the bug in plain English first, then show the fix.',
    roadmap:  'Give a dynamic phased roadmap using the rm-phase-grid HTML structure described in the system prompt. Show beginner → advanced phases with time estimates and skills for each.',
    optimize: 'Show original vs optimized, explain every improvement.'
  };

  const cd = cache[activeId];
  // If there's a file, render a small indicator to the user
  const displayContent = currentFile ? `📎 [Attached: ${currentFile.name}]\n\n${text}` : text;

  cd.rendered.push({ role: 'user', content: displayContent, isHTML: false });
  renderMessage('user', displayContent, false);
  inp.value = ''; inp.style.height = 'auto';
  document.getElementById('charCount').textContent = '0 / 2000';

  const payloadText = text || 'Please analyze the attached file.';
  const msgPayload = { role: 'user', content: `[MODE:${mode.toUpperCase()}][LANG:${lang}]\n\n${payloadText}` };
  if (currentFile) {
    msgPayload.file = currentFile;
    clearFile();
  }
  cd.history.push(msgPayload);

  const tid = 'ty' + Date.now();
  addTyping(tid); scrollToBottom();

  try {
    const res   = await api('POST', '/api/chat', {
      system:   SYSTEM + '\n\nMode: ' + (hints[mode] || ''),
      messages: cd.history
    });

    document.getElementById(tid)?.remove();

    if (res.error) {
      // Show service unavailable banner
      showServiceBanner();
      busy = false;
      document.getElementById('sendBtn').disabled = false;
      scrollToBottom();
      return;
    }

    const reply = res.content?.[0]?.text || '<p>⚑ No response received.</p>';

    cd.history.push({ role: 'assistant', content: reply });
    cd.rendered.push({ role: 'ai', content: reply, isHTML: true });

    // Save history + rendered to server so chat survives page reload / chat switch
    const savePayload = { history: cd.history, rendered: cd.rendered };

    // Auto-rename if still 'New Chat'
    const listRes = await api('GET', '/api/chats');
    const meta    = (listRes.chats || []).find(c => c.id === activeId);
    if (meta?.title === 'New Chat') {
      let newTitle = text.slice(0, 40) + (text.length > 40 ? '…' : '');
      if (!newTitle && currentFile) newTitle = `📎 ${currentFile.name.split('.')[0]}`;
      if (newTitle) {
        savePayload.title = newTitle;
        document.getElementById('chatTitleDisplay').textContent = newTitle;
      }
    }

    // Single PUT saves history, rendered, and title together
    await api('PUT', `/api/chats/${activeId}`, savePayload);

    renderMessage('ai', reply, true);
    await loadChatList(true);
  } catch (e) {
    document.getElementById(tid)?.remove();
    showServiceBanner();
  }

  busy = false;
  document.getElementById('sendBtn').disabled = false;
  scrollToBottom();
}

/* ══════════════════════════════════════
   RENDER MESSAGES
══════════════════════════════════════ */
function renderMessage(role, content, isHTML) {
  const c  = document.getElementById('messages');
  const w  = document.createElement('div'); w.className = 'msg ' + role;
  const av = document.createElement('div'); av.className = 'msg-avatar ' + role;
  if (role === 'ai') {
    av.innerHTML = '<svg viewBox="0 0 100 100" fill="none" style="width:100%; height:100%; display:block; margin:auto;" xmlns="http://www.w3.org/2000/svg"><rect width="100" height="100" rx="20" fill="#f59e0b" /><rect width="100" height="100" rx="20" fill="url(#gradT3)" /><defs><linearGradient id="gradT3" x1="0" y1="0" x2="1" y2="1"><stop offset="0%" stop-color="rgba(255,255,255,0.22)"/><stop offset="100%" stop-color="rgba(255,255,255,0)"/></linearGradient></defs><g transform="translate(18, 18) scale(2.666)"><path d="M 5.5 3.5 L 14 3.5 L 18.5 8 L 18.5 20.5 L 5.5 20.5 Z" fill="rgba(0,0,0,0.22)" stroke="rgba(0,0,0,0.22)" stroke-width="1.5" stroke-linejoin="round" /><path d="M 14 3.5 V 8 H 18.5" fill="none" stroke="#171717" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" /><path d="M 13.5 6.5 L 9.5 12.5 H 14.5 L 10.5 18.5" fill="none" stroke="#171717" stroke-width="3" stroke-linecap="round" stroke-linejoin="round" /></g></svg>';
  } else {
    av.textContent = CU?.name?.[0]?.toUpperCase() || 'U';
  }
  const b = document.createElement('div'); b.className = 'msg-bubble ' + role;
  if (isHTML) {
    b.innerHTML = processHTML(content);
    wrapCodeBlocks(b);
    if (role === 'ai') addMessageActions(b);
  } else {
    b.textContent = content;
  }
  w.appendChild(av); w.appendChild(b); c.appendChild(w);
}

function wrapCodeBlocks(el) {
  el.querySelectorAll('pre').forEach(pre => {
    if (pre.closest('.code-wrap')) return;
    const code = pre.querySelector('code');
    const ln   = code?.getAttribute('data-lang') || 'code';
    const wrap = document.createElement('div'); wrap.className = 'code-wrap';
    const head = document.createElement('div'); head.className = 'code-header';
    const badge = document.createElement('span'); badge.className = 'code-lang'; badge.textContent = ln;
    const cp = document.createElement('button'); cp.className = 'copy-btn'; cp.textContent = 'Copy';
    cp.onclick = () => { navigator.clipboard.writeText(code?.textContent || pre.textContent).then(() => { cp.textContent = '✓ Copied'; setTimeout(() => cp.textContent = 'Copy', 2200); }); };
    head.appendChild(badge); head.appendChild(cp); wrap.appendChild(head);
    if (code) highlightCode(code);
    pre.parentNode.insertBefore(wrap, pre); wrap.appendChild(pre);
  });
}

function addMessageActions(b) {
  const d = document.createElement('div'); d.className = 'msg-actions';
  d.innerHTML = `<button class="msg-action" onclick="regenerate()">↺ Regenerate</button><button class="msg-action" onclick="quickAsk('Give me a simpler beginner version')">↓ Simpler</button><button class="msg-action" onclick="quickAsk('Optimize this further for best performance')">⌬ Optimize</button><button class="msg-action" onclick="quickAsk('Show a real-world production example')">◎ Example</button>`;
  b.appendChild(d);
}

window.showSolution = function(btn, type) {
  const b = btn.closest('.msg-bubble'); if (!b) return;
  const easy = b.querySelector('.sol-easy'), opt = b.querySelector('.sol-opt');
  b.querySelectorAll('.sol-tab').forEach(t => t.classList.remove('active'));
  btn.classList.add('active');
  if (type === 'easy') { if (easy) easy.style.display = ''; if (opt) opt.style.display = 'none'; }
  else                 { if (easy) easy.style.display = 'none'; if (opt) opt.style.display = ''; }
};

function processHTML(html) {
  return html.replace(/<code data-lang="([^"]*)">([\s\S]*?)<\/code>/g, (_, l, c) => `<code data-lang="${l}">${highlight(decode(c), l)}</code>`);
}
function decode(s) { return s.replace(/&amp;/g,'&').replace(/&lt;/g,'<').replace(/&gt;/g,'>').replace(/&quot;/g,'"'); }
function highlightCode(el) { const l = el.getAttribute('data-lang') || ''; el.innerHTML = highlight(decode(el.textContent), l); }

function highlight(raw, lang) {
  let s = raw.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
  const KW = {
    python:     /\b(def|class|return|if|elif|else|for|while|import|from|in|not|and|or|True|False|None|print|self|with|as|try|except|finally|lambda|yield|pass|break|continue|raise|async|await)\b/g,
    javascript: /\b(function|const|let|var|return|if|else|for|while|class|new|this|import|export|default|async|await|true|false|null|undefined|typeof|switch|case|break|continue|throw|try|catch|finally|of|in|static|extends|int|float|double|bool|boolean|string|char|void)\b/g,
    typescript: /\b(function|const|let|var|return|if|else|for|while|class|interface|type|enum|extends|implements|public|private|protected|readonly|abstract|async|await|import|export|default|true|false|null|undefined|int|float|double|bool|boolean|string|char|void)\b/g,
    java:       /\b(public|private|protected|class|void|int|long|double|float|boolean|String|return|if|else|for|while|new|static|final|import|null|true|false|this|extends|implements|try|catch|finally|throw|super|switch|case|break)\b/g,
    go:         /\b(func|var|const|type|struct|interface|return|if|else|for|range|import|package|nil|true|false|make|new|len|append|defer|go|select|chan|map|string|int|bool)\b/g,
    rust:       /\b(fn|let|mut|const|struct|enum|impl|trait|return|if|else|for|while|loop|match|use|mod|pub|self|true|false|None|Some|Ok|Err|String|Vec|async|await)\b/g,
    sql:        /\b(SELECT|FROM|WHERE|AND|OR|NOT|INSERT|INTO|VALUES|UPDATE|SET|DELETE|CREATE|TABLE|DROP|JOIN|LEFT|RIGHT|ON|GROUP|BY|ORDER|HAVING|LIMIT|AS|COUNT|SUM|AVG|NULL|PRIMARY|KEY)\b/gi,
    'c++':      /\b(int|long|double|float|char|bool|void|auto|const|static|return|if|else|for|while|class|struct|new|delete|namespace|using|template|nullptr|true|false|try|catch|throw)\b/g
  };
  const k  = lang.toLowerCase().replace(/^js$/,'javascript').replace(/^ts$/,'typescript');
  const re = KW[k] || KW.javascript;

  const ph = [];
  const addPh = (html) => { ph.push(html); return `__CODE_PH_${ph.length - 1}__`; };

  s = s.replace(/(['"`])(?:(?!\1)[^\\]|\\.)*?\1/g, m => addPh(`<span class="hl-str">${m}</span>`));
  s = s.replace(/(\/\/[^\n]*|#[^\n]*|\/\*[\s\S]*?\*\/)/g, m => addPh(`<span class="hl-cmt">${m}</span>`));
  s = s.replace(/\b(\d+\.?\d*)\b/g, m => addPh(`<span class="hl-num">${m}</span>`));
  s = s.replace(re, m => addPh(`<span class="hl-kwd">${m}</span>`));
  s = s.replace(/\b([a-zA-Z_]\w*)\s*(?=\()/g, m => addPh(`<span class="hl-fun">${m}</span>`));

  // Re-insert exactly what was placed, backwards so nested placeholders are correctly ordered
  for (let i = ph.length - 1; i >= 0; i--) {
    s = s.split(`__CODE_PH_${i}__`).join(ph[i]);
  }
  return s;
}

function addTyping(id) {
  const c = document.getElementById('messages');
  const w = document.createElement('div'); w.className = 'msg ai'; w.id = id;
  const av = document.createElement('div'); av.className = 'msg-avatar ai'; av.textContent = '⚡';
  const ind = document.createElement('div'); ind.className = 'typing-indicator';
  ind.innerHTML = '<div class="typing-dot"></div><div class="typing-dot"></div><div class="typing-dot"></div>';
  w.appendChild(av); w.appendChild(ind); c.appendChild(w);
}

function scrollToBottom() { const el = document.getElementById('messages'); setTimeout(() => el.scrollTop = el.scrollHeight, 80); }

async function regenerate() {
  if (!activeId) return;
  const cd = cache[activeId];
  if (!cd || cd.history.length < 2) return;
  cd.history.pop(); cd.rendered.pop();
  const lu = cd.history.pop(); cd.rendered.pop();
  await api('PUT', `/api/chats/${activeId}`, { history: cd.history, rendered: cd.rendered });
  document.getElementById('messages').innerHTML = '';
  cd.rendered.forEach(r => renderMessage(r.role, r.content, r.isHTML));
  const rawText = (lu?.content || '').replace(/^\[MODE:[^\]]+\]\[LANG:[^\]]+\]\n\n/, '');
  document.getElementById('msgInput').value = rawText;
  autoResize(document.getElementById('msgInput'));
  sendMessage();
}

/* ══════════════════════════════════════
   ADMIN
══════════════════════════════════════ */
let _adminUsers = [];
let _viewingUid = '';

function openAdmin()  { if (CU?.role !== 'admin') return; document.getElementById('adminPanel').classList.add('open'); refreshAdmin(); }
function closeAdmin() { document.getElementById('adminPanel').classList.remove('open'); }

async function refreshAdmin() {
  const res = await api('GET', '/api/admin/users');
  _adminUsers = res.users || [];

  const total  = _adminUsers.length;
  const chats  = _adminUsers.reduce((n,u) => n + (u.chatCount||0), 0);
  const msgs   = _adminUsers.reduce((n,u) => n + (u.msgCount||0), 0);
  const admins = _adminUsers.filter(u => u.role === 'admin').length;

  document.getElementById('adminStats').innerHTML = `
    <div class="stat-card amber">
      <div class="stat-icon-wrap"><div class="stat-icon-bg amber-bg">👥</div></div>
      <div class="stat-content"><div class="stat-value">${total}</div><div class="stat-label">Total Users</div></div>
      <div class="stat-glow amber-glow"></div>
    </div>
    <div class="stat-card green">
      <div class="stat-icon-wrap"><div class="stat-icon-bg green-bg">💬</div></div>
      <div class="stat-content"><div class="stat-value">${chats}</div><div class="stat-label">Total Chats</div></div>
      <div class="stat-glow green-glow"></div>
    </div>
    <div class="stat-card blue">
      <div class="stat-icon-wrap"><div class="stat-icon-bg blue-bg">✉</div></div>
      <div class="stat-content"><div class="stat-value">${msgs}</div><div class="stat-label">Messages Sent</div></div>
      <div class="stat-glow blue-glow"></div>
    </div>
    <div class="stat-card purple">
      <div class="stat-icon-wrap"><div class="stat-icon-bg purple-bg">⬡</div></div>
      <div class="stat-content"><div class="stat-value">${admins}</div><div class="stat-label">Admins</div></div>
      <div class="stat-glow purple-glow"></div>
    </div>`;

  const now = Date.now();
  const events = [];
  _adminUsers.forEach(u => {
    events.push({ ts: u.lastSeen, text: `<strong>${esc(u.name)}</strong> was active`, dot: 'green' });
    if (u.joined > now - 7*86400000) events.push({ ts: u.joined, text: `<strong>${esc(u.name)}</strong> joined`, dot: 'amber' });
  });
  events.sort((a,b) => b.ts - a.ts);
  document.getElementById('activityList').innerHTML = events.slice(0,8).map(e => `
    <div class="activity-item">
      <div class="act-dot ${e.dot}"></div>
      <div class="act-text">${e.text}</div>
      <div class="act-time">${timeAgo(e.ts)}</div>
    </div>`).join('') || '<div style="padding:14px;font-family:var(--mono);font-size:11px;color:var(--t3)">No activity.</div>';

  document.getElementById('topUsersBody').innerHTML =
    [..._adminUsers].sort((a,b) => b.chatCount - a.chatCount).slice(0,5)
      .map((u,i) => `<tr>
        <td><div class="top-user-row"><span class="rank-badge">${['①','②','③','④','⑤'][i]}</span>${esc(u.name)}</div></td>
        <td class="td-mono"><span class="badge-count">${u.chatCount}</span></td>
        <td class="td-mono"><span class="badge-count">${u.msgCount}</span></td>
      </tr>`).join('');

  renderUserTable(_adminUsers);
}

function renderUserTable(users) {
  document.getElementById('userTableBody').innerHTML = users.map(u => {
    const uid = u.userId || u.email;
    const isGlobal  = uid === 'admin';
    const isSelf    = uid === (CU?.userId || CU?.email);
    const roleBadge = isGlobal
      ? `<span class="role-badge admin" title="Global Admin cannot be modified">⬡ global</span>`
      : `<span class="role-badge ${u.role}">${u.role}</span>`;

    let actionBtns = `<button class="tbl-btn view-btn" onclick="viewUserMessages('${esc(uid)}','${esc(u.name)}')">👁 View</button>`;
    if (!isGlobal) {
      if (u.role !== 'admin') {
        actionBtns += `<button class="tbl-btn" onclick="promoteUser('${esc(uid)}')">⬡ Promote</button>`;
      } else if (!isSelf) {
        actionBtns += `<button class="tbl-btn" onclick="demoteUser('${esc(uid)}')">↓ Demote</button>`;
      }
      if (!isSelf) {
        actionBtns += `<button class="tbl-btn del" onclick="deleteUser('${esc(uid)}')">✕ Delete</button>`;
      }
    }
    return `<tr>
    <td><div class="user-row-name"><div class="user-mini-av">${(u.name||'?')[0].toUpperCase()}</div><strong>${esc(u.name)}</strong>${isGlobal ? ' <span style="font-size:9px;color:var(--amber)">★</span>' : ''}</div></td>
    <td class="td-mono"><code class="uid-code">${esc(uid)}</code></td>
    <td class="td-mono">${esc(u.email||'—')}</td>
    <td>${roleBadge}</td>
    <td class="td-mono"><span class="badge-count">${u.chatCount}</span></td>
    <td class="td-mono"><span class="badge-count">${u.msgCount}</span></td>
    <td class="td-mono">${new Date(u.joined).toLocaleDateString()}</td>
    <td><div class="action-btns">${actionBtns}</div></td>
  </tr>`;
  }).join('');
}

function filterUserTable() {
  const q = document.getElementById('userSearch').value.toLowerCase();
  renderUserTable(_adminUsers.filter(u => u.name.toLowerCase().includes(q) || (u.userId||'').toLowerCase().includes(q) || u.email.toLowerCase().includes(q)));
}
async function promoteUser(id) {
  if (!confirm(`Promote ${id} to admin?`)) return;
  const res = await api('PUT', `/api/admin/users/${id}/role`, { role:'admin' });
  if (res.error) return alert(res.error);
  refreshAdmin();
}
async function demoteUser(id) {
  if (!confirm(`Demote ${id} to user?`)) return;
  const res = await api('PUT', `/api/admin/users/${id}/role`, { role:'user' });
  if (res.error) return alert(res.error);
  refreshAdmin();
}
async function deleteUser(id) {
  if (!confirm(`Delete ${id} and all their data? This cannot be undone.`)) return;
  const res = await api('DELETE', `/api/admin/users/${id}`);
  if (res.error) return alert(res.error);
  refreshAdmin();
}

/* ── ADMIN: VIEW USER MESSAGES ── */
async function viewUserMessages(uid, name) {
  _viewingUid = uid;
  document.getElementById('msgViewerTitle').textContent = `${name}'s Conversations`;
  document.getElementById('msgViewerSubtitle').textContent = `@${uid}`;
  document.getElementById('msgViewerBody').innerHTML = `<div style="padding:24px;text-align:center;color:var(--t3)">Loading…</div>`;
  document.getElementById('msgViewerModal').classList.add('open');

  const res = await api('GET', `/api/admin/users/${uid}/messages`);
  if (res.error) {
    document.getElementById('msgViewerBody').innerHTML = `<div style="padding:24px;color:var(--red)">${res.error}</div>`;
    return;
  }

  const chats = res.chats || [];
  if (!chats.length) {
    document.getElementById('msgViewerBody').innerHTML = `<div style="padding:24px;text-align:center;color:var(--t3)">No conversations yet.</div>`;
    return;
  }

  document.getElementById('msgViewerBody').innerHTML = chats.map(chat => `
    <div class="msg-chat-block">
      <div class="msg-chat-header">
        <span class="msg-chat-title">💬 ${esc(chat.title)}</span>
        <span class="msg-chat-date">${new Date(chat.ts).toLocaleDateString('en-IN', { day:'numeric', month:'short', year:'numeric' })}</span>
      </div>
      <div class="msg-chat-messages">
        ${(chat.messages||[]).map(m => `
          <div class="msg-row ${m.role}">
            <div class="msg-role-badge ${m.role}">${m.role === 'user' ? '👤 User' : '⚡ AI'}</div>
            <div class="msg-content-text">${esc(m.content).replace(/\n/g,'<br>')}</div>
          </div>`).join('') || '<div style="padding:12px;color:var(--t3);font-size:12px">No messages.</div>'}
      </div>
    </div>`).join('');
}

function closeMsgViewer() {
  document.getElementById('msgViewerModal').classList.remove('open');
  _viewingUid = '';
}

function downloadUserMessages() {
  if (!_viewingUid) return;
  window.open(`/api/admin/users/${_viewingUid}/messages/download`, '_blank');
}

function timeAgo(ts) {
  const s = Math.floor((Date.now() - ts) / 1000);
  if (s < 60)    return 'just now';
  if (s < 3600)  return Math.floor(s/60) + 'm ago';
  if (s < 86400) return Math.floor(s/3600) + 'h ago';
  return Math.floor(s/86400) + 'd ago';
}
