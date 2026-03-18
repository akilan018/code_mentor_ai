/* ── STATE ── */
let CU=null,mode='code',lang='Auto',busy=false,activeId=null,cache={};
let regUserId='',forgotResetToken='',forgotResetUserId='',currentFile=null;

/* ── FILE UPLOAD ── */
function triggerFile(type){
  closePlusMenu();
  ({image:'fileInputImage',document:'fileInputDocument',project:'fileInputProject'})[type]
    && document.getElementById(({image:'fileInputImage',document:'fileInputDocument',project:'fileInputProject'})[type])?.click();
}
function handleFileUpload(e,type){
  const file=e.target.files[0]; if(!file) return;
  if(file.size>10*1024*1024){alert('File too large. Max 10MB.');return;}
  const fpEl=document.getElementById('filePreview'),fnEl=document.getElementById('fileName');
  if(fpEl)fpEl.style.display='flex';
  if(fnEl)fnEl.innerHTML='<span class="upload-spinner"></span><span class="upload-label">Reading…</span>';
  const reader=new FileReader();
  reader.onload=evt=>{
    const base64=evt.target.result.split(',')[1];
    const icon=type==='image'?'🖼':type==='document'?'📄':'📁';
    currentFile={data:base64,mimeType:file.type,name:file.name,fileType:type};
    if(fnEl)fnEl.innerHTML=`${icon} ${file.name}`;
  };
  reader.readAsDataURL(file);
  e.target.value='';
}
function clearFile(){
  currentFile=null;
  ['fileInputImage','fileInputDocument','fileInputProject'].forEach(id=>{const el=document.getElementById(id);if(el)el.value='';});
  const fp=document.getElementById('filePreview');if(fp)fp.style.display='none';
}

/* ── PLUS MENU ── */
function togglePlusMenu(e){
  e?.stopPropagation();
  const dd=document.getElementById('plusDropdown'),btn=document.querySelector('.plus-btn');
  if(dd.classList.contains('open')){closePlusMenu();}
  else{dd.classList.add('open');btn?.classList.add('open');}
}
function closePlusMenu(){
  document.getElementById('plusDropdown')?.classList.remove('open');
  document.querySelector('.plus-btn')?.classList.remove('open');
}
document.addEventListener('click',e=>{
  if(!document.getElementById('plusWrap')?.contains(e.target))closePlusMenu();
});

/* ── THEME ── */
const savedTh=localStorage.getItem('cm_theme')||'dark';
document.documentElement.setAttribute('data-theme',savedTh);
updateThemeBtn(savedTh);
function toggleTheme(){
  const n=document.documentElement.getAttribute('data-theme')==='dark'?'light':'dark';
  document.documentElement.setAttribute('data-theme',n);
  localStorage.setItem('cm_theme',n);updateThemeBtn(n);
}
function updateThemeBtn(t){const b=document.getElementById('themeBtn');if(b)b.textContent=t==='dark'?'🌙':'☀️';}

/* ── API ── */
async function api(method,url,body){
  const r=await fetch(url,{method,credentials:'include',headers:{'Content-Type':'application/json'},body:body?JSON.stringify(body):undefined});
  return r.json();
}
const esc=s=>String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');

/* ── INIT ── */
(async()=>{const res=await api('GET','/api/auth/me');if(res.user)loginOk(res.user);})();

/* ── AUTH ── */
function switchAuthTab(tab){
  ['login','reg','forgot'].forEach(t=>{document.getElementById('form-'+t).style.display='none';});
  document.getElementById('form-'+tab).style.display='block';
  document.getElementById('tab-login')?.classList.toggle('active',tab==='login');
  document.getElementById('tab-reg')?.classList.toggle('active',tab==='reg');
  if(tab==='forgot'){
    document.getElementById('forgot-step1').style.display='';
    document.getElementById('forgot-step2').style.display='none';
    document.getElementById('forgot-step3').style.display='none';
    const o=document.getElementById('forgotOtpInput');if(o)o.value='';
  }
  clearAuthErrors();
}
function clearAuthErrors(){
  ['loginErr','regErr','forgotErr','forgotOk','forgotOtpErr','forgotOtpOk','forgotResetErr','forgotResetOk','pwErr','pwOk','nameErr','nameOk','uidErr','uidOk'].forEach(id=>{const el=document.getElementById(id);if(el)el.textContent='';});
}

async function doLogin(){
  const userId=document.getElementById('loginUserId').value.trim();
  const password=document.getElementById('loginPass').value;
  const err=document.getElementById('loginErr');err.textContent='';
  if(!userId||!password){err.textContent='Please fill in all fields.';return;}
  const res=await api('POST','/api/auth/login',{userId,password});
  if(res.error){err.textContent=res.error;return;}
  loginOk(res.user);
}

function loginOk(user){
  CU=user;
  document.getElementById('authModal').classList.remove('open');
  const ini=user.name.split(' ').map(w=>w[0]).join('').toUpperCase().slice(0,2);
  document.getElementById('userAvatar').textContent=ini;
  document.getElementById('userName').textContent=user.name;
  const roleEl=document.getElementById('userRole');
  roleEl.textContent=user.role==='admin'?'⬡ Administrator':'@'+user.userId;
  roleEl.className='user-role'+(user.role==='admin'?' admin-role':'');
  const adm=user.role==='admin';
  document.getElementById('sbAdminBtn').style.display=adm?'':'none';
  document.getElementById('topAdminBtn').style.display=adm?'':'none';
  loadChatList();
}

async function doLogout(){
  await api('POST','/api/auth/logout');
  CU=null;activeId=null;cache={};
  document.getElementById('authModal').classList.add('open');
  ['loginUserId','loginPass','regName','regUserId','regEmail','regPass','regSecAnswer'].forEach(id=>{const el=document.getElementById(id);if(el)el.value='';});
  switchAuthTab('login');
  closeSidebarMobile();
}

/* ── REGISTER ── */
function checkUid(val){
  const hint=document.getElementById('uidHint');if(!val){hint.textContent='';return;}
  if(!/^[a-zA-Z0-9_]{3,20}$/.test(val)){hint.textContent='✗ 3-20 chars, letters/numbers/underscore';hint.style.color='var(--red)';}
  else{hint.textContent='✓ Looks good';hint.style.color='var(--green)';}
}
function pwStrength(val){
  const b1=document.getElementById('pb1'),b2=document.getElementById('pb2'),b3=document.getElementById('pb3'),h=document.getElementById('pwHint');
  [b1,b2,b3].forEach(b=>{b.className='pw-bar';});
  if(!val){h.textContent='Enter a password';h.style.color='';return;}
  let score=0;
  if(val.length>=8)score++;
  if(/[A-Z]/.test(val)&&/[a-z]/.test(val))score++;
  if(/[0-9]/.test(val)&&/[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>/?`~]/.test(val))score++;
  const cls=['','w','m','s'],label=['Too weak','Weak','Medium','Strong'],color=['var(--red)','var(--red)','var(--amber)','var(--green)'];
  for(let i=0;i<score;i++)[b1,b2,b3][i].classList.add(cls[score]);
  h.textContent=label[score]||'Too weak';h.style.color=color[score]||'var(--red)';
}
function validatePasswordClient(pass){
  if(pass.length<8)return'Password must be at least 8 characters.';
  if(!/[A-Z]/.test(pass))return'Need at least one uppercase letter.';
  if(!/[a-z]/.test(pass))return'Need at least one lowercase letter.';
  if(!/[0-9]/.test(pass))return'Need at least one number.';
  if(!/[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>/?`~]/.test(pass))return'Need at least one special character.';
  return null;
}

async function doRegister(){
  const name=document.getElementById('regName').value.trim();
  const userId=document.getElementById('regUserId').value.trim();
  const email=document.getElementById('regEmail').value.trim();
  const pass=document.getElementById('regPass').value;
  const secAnswer=document.getElementById('regSecAnswer').value.trim();
  const err=document.getElementById('regErr');err.textContent='';err.style.color='var(--red)';
  if(!name||!userId||!email||!pass||!secAnswer){err.textContent='All fields are required.';return;}
  if(!/^[a-zA-Z0-9_]{3,20}$/.test(userId)){err.textContent='Invalid User ID.';return;}
  const pwErr=validatePasswordClient(pass);if(pwErr){err.textContent=pwErr;return;}
  const btn=document.querySelector('#form-reg .auth-btn');
  btn.disabled=true;btn.textContent='Sending OTP…';
  const res=await api('POST','/api/auth/register/send-otp',{userId,name,password:pass,method:'email',contact:email,securityAnswer:secAnswer});
  btn.disabled=false;btn.textContent='Create Account →';
  if(res.error){err.textContent=res.error;return;}
  regUserId=userId;err.style.color='var(--green)';err.textContent=`✓ OTP sent to ${email}`;
  const existing=document.getElementById('regOtpSection');
  if(!existing){
    const otpSec=document.createElement('div');otpSec.id='regOtpSection';
    otpSec.innerHTML=`<div class="fg" style="margin-top:14px"><label class="fl">6-digit OTP from email</label><input class="fi" id="regOtpInput" type="text" maxlength="6" placeholder="123456" style="letter-spacing:.2em;font-size:18px;text-align:center;font-weight:700"></div><button class="auth-btn" onclick="verifyRegOtp()">Verify & Sign In →</button><div class="f-err" id="regOtpErr"></div>`;
    document.querySelector('#form-reg').appendChild(otpSec);
  }
  document.getElementById('regOtpInput')?.focus();
}
async function verifyRegOtp(){
  const otp=document.getElementById('regOtpInput')?.value?.trim();
  const err=document.getElementById('regOtpErr');if(err)err.textContent='';
  if(!otp||otp.length<6){if(err)err.textContent='Enter the 6-digit OTP.';return;}
  const btn=document.querySelector('#regOtpSection .auth-btn');
  btn.disabled=true;btn.textContent='Verifying…';
  const res=await api('POST','/api/auth/register/verify-otp',{userId:regUserId,otp});
  btn.disabled=false;btn.textContent='Verify & Sign In →';
  if(res.error){if(err)err.textContent=res.error;return;}
  loginOk(res.user);
}

/* ── FORGOT ── */
async function doForgotSendOtp(){
  const userId=document.getElementById('forgotUserId').value.trim();
  const err=document.getElementById('forgotErr'),ok=document.getElementById('forgotOk');
  err.textContent='';ok.textContent='';
  if(!userId){err.textContent='Please enter your User ID.';return;}
  const btn=document.querySelector('#forgot-step1 .auth-btn');
  btn.disabled=true;btn.textContent='Sending…';
  const res=await api('POST','/api/auth/forgot/send-otp',{userId});
  btn.disabled=false;btn.textContent='Send OTP →';
  if(res.error){err.textContent=res.error;return;}
  forgotResetUserId=userId;ok.textContent='✓ OTP sent! Check your email.';
  setTimeout(()=>{document.getElementById('forgot-step1').style.display='none';document.getElementById('forgot-step2').style.display='';},800);
}
async function doForgotVerifyOtp(){
  const otp=document.getElementById('forgotOtpInput').value.trim();
  const err=document.getElementById('forgotOtpErr'),ok=document.getElementById('forgotOtpOk');
  err.textContent='';ok.textContent='';
  if(!otp||otp.length!==6){err.textContent='Enter the 6-digit OTP.';return;}
  const btn=document.querySelector('#forgot-step2 .auth-btn');
  btn.disabled=true;btn.textContent='Verifying…';
  const res=await api('POST','/api/auth/forgot/verify-otp',{userId:forgotResetUserId,otp});
  btn.disabled=false;btn.textContent='Verify OTP →';
  if(res.error){err.textContent=res.error;return;}
  forgotResetToken=res.token;ok.textContent='✓ Verified!';
  setTimeout(()=>{document.getElementById('forgot-step2').style.display='none';document.getElementById('forgot-step3').style.display='';},600);
}
async function doForgotReset(){
  const newPass=document.getElementById('forgotNew').value;
  const confirm=document.getElementById('forgotConfirm').value;
  const err=document.getElementById('forgotResetErr'),ok=document.getElementById('forgotResetOk');
  err.textContent='';ok.textContent='';
  if(!newPass||!confirm){err.textContent='All fields required.';return;}
  if(newPass!==confirm){err.textContent='Passwords do not match.';return;}
  const pwErr=validatePasswordClient(newPass);if(pwErr){err.textContent=pwErr;return;}
  const btn=document.querySelector('#forgot-step3 .auth-btn');
  btn.disabled=true;btn.textContent='Resetting…';
  const res=await api('POST','/api/auth/forgot/reset',{userId:forgotResetUserId,token:forgotResetToken,newPassword:newPass,confirmPassword:confirm});
  btn.disabled=false;btn.textContent='Reset Password →';
  if(res.error){err.textContent=res.error;return;}
  ok.textContent='✓ '+res.message;setTimeout(()=>switchAuthTab('login'),2200);
}

/* ── SETTINGS MODAL ── */
function openSettingsModal(){
  ['pwCurrent','pwSecAnswer','pwNew','pwConfirm','newNameInput','newUserIdInput','uidChangePass'].forEach(id=>{const el=document.getElementById(id);if(el)el.value='';});
  ['pwErr','pwOk','nameErr','nameOk','uidErr','uidOk'].forEach(id=>{const el=document.getElementById(id);if(el)el.textContent='';});
  if(CU?.name)document.getElementById('newNameInput').value=CU.name;
  if(CU?.userId)document.getElementById('newUserIdInput').value=CU.userId;
  document.getElementById('settingsModal').classList.add('open');
}
function closeSettingsModal(){document.getElementById('settingsModal').classList.remove('open');}

function checkNewUid(val){
  const hint=document.getElementById('newUidHint');if(!val){hint.textContent='';return;}
  if(!/^[a-zA-Z0-9_]{3,20}$/.test(val)){hint.textContent='✗ 3-20 chars, letters/numbers/underscore';hint.style.color='var(--red)';}
  else{hint.textContent='✓ Looks good';hint.style.color='var(--green)';}
}

async function doChangeName(){
  const newName=document.getElementById('newNameInput').value.trim();
  const err=document.getElementById('nameErr'),ok=document.getElementById('nameOk');
  err.textContent='';ok.textContent='';
  if(!newName||newName.length<2){err.textContent='Name must be at least 2 characters.';return;}
  const btns=document.querySelectorAll('#settingsModal .auth-btn');
  btns[0].disabled=true;btns[0].textContent='Updating…';
  const res=await api('POST','/api/auth/change-username',{newName});
  btns[0].disabled=false;btns[0].textContent='Update Name →';
  if(res.error){err.textContent=res.error;return;}
  if(CU)CU.name=res.name;
  document.getElementById('userName').textContent=res.name;
  const ini=res.name.split(' ').map(w=>w[0]).join('').toUpperCase().slice(0,2);
  document.getElementById('userAvatar').textContent=ini;
  ok.textContent='✓ '+res.message;
  setTimeout(closeSettingsModal,1800);
}

async function doChangeUserId(){
  const newUserId=document.getElementById('newUserIdInput').value.trim();
  const password=document.getElementById('uidChangePass').value;
  const err=document.getElementById('uidErr'),ok=document.getElementById('uidOk');
  err.textContent='';ok.textContent='';
  if(!newUserId||!password){err.textContent='New User ID and password are required.';return;}
  if(!/^[a-zA-Z0-9_]{3,20}$/.test(newUserId)){err.textContent='User ID: 3-20 chars, letters/numbers/underscore.';return;}
  const btns=document.querySelectorAll('#settingsModal .auth-btn');
  btns[1].disabled=true;btns[1].textContent='Updating…';
  const res=await api('POST','/api/auth/change-userid',{newUserId,password});
  btns[1].disabled=false;btns[1].textContent='Update User ID →';
  if(res.error){err.textContent=res.error;return;}
  if(CU){CU.userId=res.userId;}
  document.getElementById('userRole').textContent=CU?.role==='admin'?'⬡ Administrator':'@'+res.userId;
  ok.textContent='✓ '+res.message;
  setTimeout(closeSettingsModal,1800);
}

async function doChangePassword(){
  const current=document.getElementById('pwCurrent').value;
  const secAnswer=document.getElementById('pwSecAnswer')?.value?.trim()||'';
  const newPass=document.getElementById('pwNew').value;
  const confirm=document.getElementById('pwConfirm').value;
  const err=document.getElementById('pwErr'),ok=document.getElementById('pwOk');
  err.textContent='';ok.textContent='';
  if(!current||!secAnswer||!newPass||!confirm){err.textContent='All fields required.';return;}
  if(newPass!==confirm){err.textContent='Passwords do not match.';return;}
  const pwErr=validatePasswordClient(newPass);if(pwErr){err.textContent=pwErr;return;}
  const res=await api('POST','/api/auth/change-password',{currentPassword:current,securityAnswer:secAnswer,newPassword:newPass,confirmPassword:confirm});
  if(res.error){err.textContent=res.error;return;}
  ok.textContent='✓ '+res.message;setTimeout(closeSettingsModal,2000);
}

/* ── SIDEBAR TOGGLE ── */
function toggleSidebar(){
  const sidebar=document.getElementById('sidebar');
  const ov=document.getElementById('ov');
  const isMobile=window.innerWidth<=768;
  if(isMobile){
    const isOpen=sidebar.classList.contains('open');
    if(isOpen){sidebar.classList.remove('open');ov.classList.remove('show');}
    else{sidebar.classList.add('open');ov.classList.add('show');}
  } else {
    sidebar.classList.toggle('desktop-hidden');
  }
}
function closeSidebarOverlay(){
  if(window.innerWidth<=768){
    document.getElementById('sidebar').classList.remove('open');
    document.getElementById('ov').classList.remove('show');
  }
}
function closeSidebarMobile(){
  if(window.innerWidth<=768){
    document.getElementById('sidebar').classList.remove('open');
    document.getElementById('ov').classList.remove('show');
  }
}
function closeSidebar(){closeSidebarMobile();}

/* ── CHAT LIST ── */
async function loadChatList(){
  const res=await api('GET','/api/chats');
  const list=document.getElementById('chatList');
  const empty=document.getElementById('sbEmpty');
  list.querySelectorAll('.cl-label,.chat-item').forEach(e=>e.remove());
  if(!res.chats?.length){empty.style.display='block';if(!activeId)showWelcome();return;}
  empty.style.display='none';
  const now=Date.now(),DAY=86400000;
  const grp={Today:[],Yesterday:[],Older:[]};
  res.chats.forEach(c=>{
    const age=now-c.ts;
    if(age<DAY)grp.Today.push(c);
    else if(age<2*DAY)grp.Yesterday.push(c);
    else grp.Older.push(c);
  });
  Object.entries(grp).forEach(([lbl,chats])=>{
    if(!chats.length)return;
    const l=document.createElement('div');l.className='cl-label';l.textContent=lbl;list.appendChild(l);
    chats.forEach(c=>list.appendChild(buildChatItem(c)));
  });
  list.querySelectorAll('.chat-item').forEach(el=>el.classList.toggle('active',el.dataset.id===activeId));
  if(!activeId&&res.chats.length)switchChat(res.chats[0].id);
  else if(!activeId)showWelcome();
}

function buildChatItem(c){
  const el=document.createElement('div');
  el.className='chat-item'+(c.id===activeId?' active':'');
  el.dataset.id=c.id;
  el.innerHTML=`<div class="ci-dot"></div><span class="chat-item-title">${esc(c.title)}</span><div class="chat-item-actions"><button class="ci-btn" onclick="event.stopPropagation();startRename('${c.id}',this)">✎</button><button class="ci-btn danger" onclick="event.stopPropagation();deleteChat('${c.id}')">✕</button></div>`;
  el.onclick=()=>switchChat(c.id);
  return el;
}
function startRename(id,btn){
  const item=btn.closest('.chat-item'),title=item.querySelector('.chat-item-title');
  const inp=document.createElement('input');
  inp.className='ci-rename-input';inp.value=title.textContent;
  item.replaceChild(inp,title);inp.focus();inp.select();
  const commit=async()=>{
    const val=inp.value.trim()||title.textContent;
    title.textContent=val;item.replaceChild(title,inp);
    if(id===activeId)document.getElementById('chatTitleDisplay').textContent=val;
    await api('PUT',`/api/chats/${id}`,{title:val});
  };
  inp.onblur=commit;
  inp.onkeydown=e=>{if(e.key==='Enter')inp.blur();if(e.key==='Escape')item.replaceChild(title,inp);};
}
async function newChat(){
  const res=await api('POST','/api/chats',{title:'New Chat'});
  if(!res.chat)return;
  cache[res.chat.id]={history:[],rendered:[]};
  activeId=res.chat.id;
  document.getElementById('chatTitleDisplay').textContent='New Chat';
  showWelcome();await loadChatList();closeSidebar();
}
async function switchChat(id){
  activeId=id;
  if(!cache[id]){const res=await api('GET',`/api/chats/${id}`);cache[id]=res.chat||{history:[],rendered:[]};}
  const listRes=await api('GET','/api/chats');
  const meta=(listRes.chats||[]).find(c=>c.id===id);
  document.getElementById('chatTitleDisplay').textContent=meta?.title||'Chat';
  const msgs=document.getElementById('messages');msgs.innerHTML='';
  if(cache[id].rendered?.length)cache[id].rendered.forEach(r=>renderMessage(r.role,r.content,r.isHTML));
  else showWelcome();
  document.querySelectorAll('.chat-item').forEach(el=>el.classList.toggle('active',el.dataset.id===id));
  scrollToBottom();closeSidebar();
}
async function deleteChat(id){
  if(!confirm('Delete this chat?'))return;
  await api('DELETE',`/api/chats/${id}`);
  delete cache[id];if(id===activeId)activeId=null;loadChatList();
}
function goHome(){activeId=null;document.getElementById('chatTitleDisplay').textContent='New Chat';showWelcome();closeSidebar();}

/* ── WELCOME ── */
function showWelcome(){
  document.getElementById('messages').innerHTML=`
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
        <div class="suggestion-card" onclick="quickAsk('Frontend developer roadmap 2025 — structured phases')"><div class="sg-tag">Roadmap</div><div class="sg-title">Dev Roadmap</div><div class="sg-desc">Phase-by-phase</div></div>
        <div class="suggestion-card" onclick="quickAsk('Explain recursion with simple then advanced example')"><div class="sg-tag">Concept</div><div class="sg-title">Recursion</div><div class="sg-desc">Simple → Advanced</div></div>
        <div class="suggestion-card" onclick="quickAsk('Build a REST API in Node.js — beginner friendly')"><div class="sg-tag">Backend</div><div class="sg-title">REST API</div><div class="sg-desc">Node.js</div></div>
        <div class="suggestion-card" onclick="quickAsk('Explain Big O notation with code examples')"><div class="sg-tag">Complexity</div><div class="sg-title">Big O</div><div class="sg-desc">With examples</div></div>
        <div class="suggestion-card" onclick="quickAsk('React todo app with hooks — easy and optimized')"><div class="sg-tag">Frontend</div><div class="sg-title">React App</div><div class="sg-desc">Hooks + Best practices</div></div>
      </div>
    </div>`;
}

/* ── MODE & LANG ── */
function setMode(m,el){
  mode=m;
  document.querySelectorAll('.mode-pill').forEach(p=>p.classList.remove('active'));el.classList.add('active');
  const lbl={code:'✦ code',explain:'◎ explain',debug:'⚑ debug',roadmap:'◈ roadmap',optimize:'⌬ optimize'};
  document.getElementById('modeTag').textContent=lbl[m]||'✦ code';
  const ph={code:'Ask anything — write code, debug, explain a concept…',explain:'Paste code or describe a concept…',debug:'Paste buggy code and describe the error…',roadmap:'Name a skill or technology to learn…',optimize:'Paste code to optimize…'};
  document.getElementById('msgInput').placeholder=ph[m]||ph.code;
}
function setLang(btn,l){
  lang=l;document.querySelectorAll('.lang-btn').forEach(b=>b.classList.remove('active'));btn.classList.add('active');
  document.getElementById('langTag').textContent='◎ '+l.toLowerCase();
}
function handleKey(e){if(e.key==='Enter'&&!e.shiftKey){e.preventDefault();sendMessage();}}
function autoResize(el){el.style.height='auto';el.style.height=Math.min(el.scrollHeight,200)+'px';document.getElementById('charCount').textContent=el.value.length+' / 2000';}
function quickAsk(t){document.getElementById('msgInput').value=t;autoResize(document.getElementById('msgInput'));sendMessage();}

/* ── SYSTEM PROMPT ── */
const SYSTEM=`You are CodeMentor AI — a friendly coding teacher for beginners and students.
Respond in PURE HTML ONLY. Zero markdown. Zero asterisks. Zero hash symbols. Zero backticks.

RULE 1 — TWO CODE VERSIONS: For every code task give Easy and Optimized versions using solution-tabs.
RULE 2 — CODE COMMENTS: Add simple comments on every line explaining what it does in plain English.
RULE 3 — LINE-BY-LINE EXPLANATION after every code block.
RULE 4 — OUTPUT BLOCK: <div class="out-block"><div class="out-header">▶ Expected Output</div><div class="out-body">output here</div></div>
RULE 5 — TRACE BLOCK: Show step-by-step how it works using trace-block.
RULE 6 — HTML ELEMENTS: Use <p>, <strong>, <h3>, <ul><li>, <pre><code data-lang="python">, <span class="cx easy">, <div class="tipb">.
RULE 7 — WRITING STYLE: Friendly, patient, beginner-friendly. Use real-world analogies.
RULE 8 — END WITH TIP: <div class="tipb">encouraging message</div>
RULE 9 — ROADMAP MODE: Use rm-phase-grid with rm-phase-card, rm-phase-num, rm-phase-title, rm-phase-skills, rm-skill, rm-phase-goal.
RULE 10 — PROJECT REQUESTS: For large projects (full apps, websites, systems), take your time and provide the COMPLETE code. Do not cut short. The user expects a full working solution.`;

/* ── BANNER ── */
function showServiceBanner(errMsg){
  document.getElementById('serviceBanner')?.remove();
  const banner=document.createElement('div');banner.id='serviceBanner';banner.className='service-banner';
  banner.innerHTML=`<div class="sb-icon">⚡</div><div class="sb-content"><div class="sb-title">Service Temporarily Unavailable</div><div class="sb-msg">${esc(errMsg)}</div></div><button class="sb-close" onclick="document.getElementById('serviceBanner')?.remove()">✕</button>`;
  document.getElementById('messages').appendChild(banner);scrollToBottom();
}

/* ── SEND ── */
async function sendMessage(){
  const inp=document.getElementById('msgInput');
  const text=inp.value.trim();
  if((!text&&!currentFile)||busy)return;
  const displayTitle=text||(currentFile?`📎 ${currentFile.name.replace(/\.[^.]+$/,'')}`:'New Chat');
  if(!activeId){
    const title=displayTitle.slice(0,50)+(displayTitle.length>50?'…':'');
    const res=await api('POST','/api/chats',{title});
    if(!res.chat)return;
    activeId=res.chat.id;cache[activeId]={history:[],rendered:[]};
    document.getElementById('chatTitleDisplay').textContent=res.chat.title;
    await loadChatList();
  }
  document.getElementById('welcomeScreen')?.remove();
  busy=true;document.getElementById('sendBtn').disabled=true;
  const hints={
    code:`Give EASY and OPTIMIZED versions. Language: ${lang}.`,
    explain:'Use a real-world analogy first, then code examples.',
    debug:'Explain the bug in plain English first, then show the fix.',
    roadmap:'Give a dynamic phased roadmap using rm-phase-grid HTML. Show beginner → advanced phases.',
    optimize:'Show original vs optimized, explain every improvement.'
  };
  const cd=cache[activeId];
  const displayContent=currentFile?`📎 [Attached: ${currentFile.name}]\n\n${text}`:text;
  cd.rendered.push({role:'user',content:displayContent,isHTML:false});
  renderMessage('user',displayContent,false);
  inp.value='';inp.style.height='auto';document.getElementById('charCount').textContent='0 / 2000';
  const payloadText=text||'Please analyze the attached file.';
  const msgPayload={role:'user',content:`[MODE:${mode.toUpperCase()}][LANG:${lang}]\n\n${payloadText}`};
  if(currentFile){msgPayload.file=currentFile;clearFile();}
  cd.history.push(msgPayload);
  const tid='ty'+Date.now();addTyping(tid);scrollToBottom();
  try{
    const res=await api('POST','/api/chat',{system:SYSTEM+'\n\nMode: '+(hints[mode]||''),messages:cd.history});
    document.getElementById(tid)?.remove();
    if(res.error){showServiceBanner(res.error);busy=false;document.getElementById('sendBtn').disabled=false;scrollToBottom();return;}
    const reply=res.content?.[0]?.text||'<p>⚑ No response received.</p>';
    cd.history.push({role:'assistant',content:reply});cd.rendered.push({role:'ai',content:reply,isHTML:true});
    const listRes=await api('GET','/api/chats');
    const meta=(listRes.chats||[]).find(c=>c.id===activeId);
    const newTitle=meta?.title==='New Chat'?text.slice(0,50)+(text.length>50?'…':''):meta?.title;
    await api('PUT',`/api/chats/${activeId}`,{title:newTitle,history:cd.history,rendered:cd.rendered});
    renderMessage('ai',reply,true);await loadChatList();
  }catch(e){document.getElementById(tid)?.remove();showServiceBanner('Network error: '+e.message);}
  busy=false;document.getElementById('sendBtn').disabled=false;scrollToBottom();
}

/* ── RENDER ── */
function renderMessage(role,content,isHTML){
  const c=document.getElementById('messages');
  const w=document.createElement('div');w.className='msg '+role;
  const av=document.createElement('div');av.className='msg-avatar '+role;
  av.textContent=role==='ai'?'⚡':(CU?.name?.[0]?.toUpperCase()||'U');
  const b=document.createElement('div');b.className='msg-bubble '+role;
  if(isHTML){b.innerHTML=processHTML(content);wrapCodeBlocks(b);if(role==='ai')addMessageActions(b);}
  else b.textContent=content;
  w.appendChild(av);w.appendChild(b);c.appendChild(w);
}
function wrapCodeBlocks(el){
  el.querySelectorAll('pre').forEach(pre=>{
    if(pre.closest('.code-wrap'))return;
    const code=pre.querySelector('code');const ln=code?.getAttribute('data-lang')||'code';
    const wrap=document.createElement('div');wrap.className='code-wrap';
    const head=document.createElement('div');head.className='code-header';
    const badge=document.createElement('span');badge.className='code-lang';badge.textContent=ln;
    const cp=document.createElement('button');cp.className='copy-btn';cp.textContent='Copy';
    cp.onclick=()=>{navigator.clipboard.writeText(code?.textContent||pre.textContent).then(()=>{cp.textContent='✓ Copied';setTimeout(()=>cp.textContent='Copy',2200);});};
    head.appendChild(badge);head.appendChild(cp);wrap.appendChild(head);
    if(code)highlightCode(code);
    pre.parentNode.insertBefore(wrap,pre);wrap.appendChild(pre);
  });
}
function addMessageActions(b){
  const d=document.createElement('div');d.className='msg-actions';
  d.innerHTML=`<button class="msg-action" onclick="regenerate()">↺ Regenerate</button><button class="msg-action" onclick="quickAsk('Give me a simpler beginner version')">↓ Simpler</button><button class="msg-action" onclick="quickAsk('Optimize this further')">⌬ Optimize</button><button class="msg-action" onclick="quickAsk('Show a real-world production example')">◎ Example</button>`;
  b.appendChild(d);
}
window.showSolution=function(btn,type){
  const b=btn.closest('.msg-bubble');if(!b)return;
  const easy=b.querySelector('.sol-easy'),opt=b.querySelector('.sol-opt');
  b.querySelectorAll('.sol-tab').forEach(t=>t.classList.remove('active'));btn.classList.add('active');
  if(type==='easy'){if(easy)easy.style.display='';if(opt)opt.style.display='none';}
  else{if(easy)easy.style.display='none';if(opt)opt.style.display='';}
};
function processHTML(html){return html.replace(/<code data-lang="([^"]*)">([\s\S]*?)<\/code>/g,(_,l,c)=>`<code data-lang="${l}">${highlight(decode(c),l)}</code>`);}
function decode(s){return s.replace(/&amp;/g,'&').replace(/&lt;/g,'<').replace(/&gt;/g,'>').replace(/&quot;/g,'"');}
function highlightCode(el){const l=el.getAttribute('data-lang')||'';el.innerHTML=highlight(decode(el.textContent),l);}
function highlight(raw,lang){
  let s=raw.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
  const KW={python:/\b(def|class|return|if|elif|else|for|while|import|from|in|not|and|or|True|False|None|print|self|with|as|try|except|finally|lambda|yield|pass|break|continue|raise|async|await)\b/g,javascript:/\b(function|const|let|var|return|if|else|for|while|class|new|this|import|export|default|async|await|true|false|null|undefined|typeof|switch|case|break|continue|throw|try|catch|finally|of|in|static|extends)\b/g,typescript:/\b(function|const|let|var|return|if|else|for|while|class|interface|type|enum|extends|implements|public|private|protected|readonly|abstract|async|await|import|export|default|true|false|null|undefined)\b/g,java:/\b(public|private|protected|class|void|int|long|double|float|boolean|String|return|if|else|for|while|new|static|final|import|null|true|false|this|extends|implements|try|catch|finally|throw|super|switch|case|break)\b/g,go:/\b(func|var|const|type|struct|interface|return|if|else|for|range|import|package|nil|true|false|make|new|len|append|defer|go|select|chan|map|string|int|bool)\b/g,rust:/\b(fn|let|mut|const|struct|enum|impl|trait|return|if|else|for|while|loop|match|use|mod|pub|self|true|false|None|Some|Ok|Err|String|Vec|async|await)\b/g,sql:/\b(SELECT|FROM|WHERE|AND|OR|NOT|INSERT|INTO|VALUES|UPDATE|SET|DELETE|CREATE|TABLE|DROP|JOIN|LEFT|RIGHT|ON|GROUP|BY|ORDER|HAVING|LIMIT|AS|COUNT|SUM|AVG|NULL|PRIMARY|KEY)\b/gi,'c++':/\b(int|long|double|float|char|bool|void|auto|const|static|return|if|else|for|while|class|struct|new|delete|namespace|using|template|nullptr|true|false|try|catch|throw)\b/g};
  const k=lang.toLowerCase().replace(/^js$/,'javascript').replace(/^ts$/,'typescript');
  const re=KW[k]||KW.javascript;
  const ph=[];const addPh=html=>{ph.push(html);return`__CODE_PH_${ph.length-1}__`;};
  s=s.replace(/(['"`])(?:(?!\1)[^\\]|\\.)*?\1/g,m=>addPh(`<span class="hl-str">${m}</span>`));
  s=s.replace(/(\/\/[^\n]*|#[^\n]*|\/\*[\s\S]*?\*\/)/g,m=>addPh(`<span class="hl-cmt">${m}</span>`));
  s=s.replace(/\b(\d+\.?\d*)\b/g,m=>addPh(`<span class="hl-num">${m}</span>`));
  s=s.replace(re,m=>addPh(`<span class="hl-kwd">${m}</span>`));
  s=s.replace(/\b([a-zA-Z_]\w*)\s*(?=\()/g,m=>addPh(`<span class="hl-fun">${m}</span>`));
  for(let i=ph.length-1;i>=0;i--)s=s.split(`__CODE_PH_${i}__`).join(ph[i]);
  return s;
}
function addTyping(id){
  const c=document.getElementById('messages');
  const w=document.createElement('div');w.className='msg ai';w.id=id;
  const av=document.createElement('div');av.className='msg-avatar ai';av.textContent='⚡';
  const ind=document.createElement('div');ind.className='typing-indicator';
  ind.innerHTML='<div class="typing-dot"></div><div class="typing-dot"></div><div class="typing-dot"></div>';
  w.appendChild(av);w.appendChild(ind);c.appendChild(w);
}
function scrollToBottom(){const el=document.getElementById('messages');setTimeout(()=>el.scrollTop=el.scrollHeight,80);}
async function regenerate(){
  if(!activeId)return;const cd=cache[activeId];if(!cd||cd.history.length<2)return;
  cd.history.pop();cd.rendered.pop();const lu=cd.history.pop();cd.rendered.pop();
  await api('PUT',`/api/chats/${activeId}`,{history:cd.history,rendered:cd.rendered});
  document.getElementById('messages').innerHTML='';
  cd.rendered.forEach(r=>renderMessage(r.role,r.content,r.isHTML));
  const rawText=(lu?.content||'').replace(/^\[MODE:[^\]]+\]\[LANG:[^\]]+\]\n\n/,'');
  document.getElementById('msgInput').value=rawText;autoResize(document.getElementById('msgInput'));
  sendMessage();
}

/* ── ADMIN ── */
let _adminUsers=[],_viewingUid='';
function openAdmin(){if(CU?.role!=='admin')return;document.getElementById('adminPanel').classList.add('open');refreshAdmin();}
function closeAdmin(){document.getElementById('adminPanel').classList.remove('open');}
async function refreshAdmin(){
  const res=await api('GET','/api/admin/users');_adminUsers=res.users||[];
  const total=_adminUsers.length,chats=_adminUsers.reduce((n,u)=>n+(u.chatCount||0),0),msgs=_adminUsers.reduce((n,u)=>n+(u.msgCount||0),0),admins=_adminUsers.filter(u=>u.role==='admin').length;
  document.getElementById('adminStats').innerHTML=`
    <div class="stat-card amber"><div class="stat-icon-wrap"><div class="stat-icon-bg amber-bg">👥</div></div><div class="stat-content"><div class="stat-value">${total}</div><div class="stat-label">Total Users</div></div><div class="stat-glow amber-glow"></div></div>
    <div class="stat-card green"><div class="stat-icon-wrap"><div class="stat-icon-bg green-bg">💬</div></div><div class="stat-content"><div class="stat-value">${chats}</div><div class="stat-label">Total Chats</div></div><div class="stat-glow green-glow"></div></div>
    <div class="stat-card blue"><div class="stat-icon-wrap"><div class="stat-icon-bg blue-bg">✉</div></div><div class="stat-content"><div class="stat-value">${msgs}</div><div class="stat-label">Messages</div></div><div class="stat-glow blue-glow"></div></div>
    <div class="stat-card purple"><div class="stat-icon-wrap"><div class="stat-icon-bg purple-bg">⬡</div></div><div class="stat-content"><div class="stat-value">${admins}</div><div class="stat-label">Admins</div></div><div class="stat-glow purple-glow"></div></div>`;
  const now=Date.now();const events=[];
  _adminUsers.forEach(u=>{events.push({ts:u.lastSeen,text:`<strong>${esc(u.name)}</strong> was active`,dot:'green'});if(u.joined>now-7*86400000)events.push({ts:u.joined,text:`<strong>${esc(u.name)}</strong> joined`,dot:'amber'});});
  events.sort((a,b)=>b.ts-a.ts);
  document.getElementById('activityList').innerHTML=events.slice(0,8).map(e=>`<div class="activity-item"><div class="act-dot ${e.dot}"></div><div class="act-text">${e.text}</div><div class="act-time">${timeAgo(e.ts)}</div></div>`).join('')||'<div style="padding:14px;font-family:var(--mono);font-size:11px;color:var(--t3)">No activity.</div>';
  document.getElementById('topUsersBody').innerHTML=[..._adminUsers].sort((a,b)=>b.chatCount-a.chatCount).slice(0,5).map((u,i)=>`<tr><td><div style="display:flex;align-items:center;gap:7px"><span style="font-family:var(--mono);font-size:14px;color:var(--amber)">${['①','②','③','④','⑤'][i]}</span>${esc(u.name)}</div></td><td class="td-mono"><span class="badge-count">${u.chatCount}</span></td><td class="td-mono"><span class="badge-count">${u.msgCount}</span></td></tr>`).join('');
  renderUserTable(_adminUsers);
}
function renderUserTable(users){
  document.getElementById('userTableBody').innerHTML=users.map(u=>`<tr>
    <td><div style="display:flex;align-items:center;gap:9px"><div class="user-mini-av">${(u.name||'?')[0].toUpperCase()}</div><strong>${esc(u.name)}</strong></div></td>
    <td class="td-mono"><code class="uid-code">${esc(u.userId||u.email)}</code></td>
    <td class="td-mono">${esc(u.email||'—')}</td>
    <td><span class="role-badge ${u.role}">${u.role}</span></td>
    <td class="td-mono"><span class="badge-count">${u.chatCount}</span></td>
    <td class="td-mono"><span class="badge-count">${u.msgCount}</span></td>
    <td class="td-mono">${new Date(u.joined).toLocaleDateString()}</td>
    <td><div class="action-btns">
      <button class="tbl-btn view-btn" onclick="viewUserMessages('${esc(u.userId||u.email)}','${esc(u.name)}')">👁 View</button>
      ${u.role!=='admin'?`<button class="tbl-btn" onclick="promoteUser('${esc(u.userId||u.email)}')">⬡ Promote</button>`:`<button class="tbl-btn" onclick="demoteUser('${esc(u.userId||u.email)}')">↓ Demote</button>`}
      ${(u.userId||u.email)!==(CU?.userId||CU?.email)?`<button class="tbl-btn del" onclick="deleteUser('${esc(u.userId||u.email)}')">✕ Delete</button>`:''}
    </div></td>
  </tr>`).join('');
}
function filterUserTable(){const q=document.getElementById('userSearch').value.toLowerCase();renderUserTable(_adminUsers.filter(u=>u.name.toLowerCase().includes(q)||(u.userId||'').toLowerCase().includes(q)||u.email.toLowerCase().includes(q)));}
async function promoteUser(id){if(!confirm(`Promote ${id} to admin?`))return;await api('PUT',`/api/admin/users/${id}/role`,{role:'admin'});refreshAdmin();}
async function demoteUser(id){if(!confirm(`Demote ${id}?`))return;await api('PUT',`/api/admin/users/${id}/role`,{role:'user'});refreshAdmin();}
async function deleteUser(id){if(!confirm(`Delete ${id} and all their data?`))return;await api('DELETE',`/api/admin/users/${id}`);refreshAdmin();}
async function viewUserMessages(uid,name){
  _viewingUid=uid;
  document.getElementById('msgViewerTitle').textContent=`${name}'s Conversations`;
  document.getElementById('msgViewerSubtitle').textContent=`@${uid}`;
  document.getElementById('msgViewerBody').innerHTML='<div style="padding:24px;text-align:center;color:var(--t3)">Loading…</div>';
  document.getElementById('msgViewerModal').classList.add('open');
  const res=await api('GET',`/api/admin/users/${uid}/messages`);
  if(res.error){document.getElementById('msgViewerBody').innerHTML=`<div style="padding:24px;color:var(--red)">${res.error}</div>`;return;}
  const chats=res.chats||[];
  if(!chats.length){document.getElementById('msgViewerBody').innerHTML='<div style="padding:24px;text-align:center;color:var(--t3)">No conversations yet.</div>';return;}
  document.getElementById('msgViewerBody').innerHTML=chats.map(chat=>`
    <div class="msg-chat-block">
      <div class="msg-chat-header"><span class="msg-chat-title">💬 ${esc(chat.title)}</span><span class="msg-chat-date">${new Date(chat.ts).toLocaleDateString('en-IN',{day:'numeric',month:'short',year:'numeric'})}</span></div>
      <div class="msg-chat-messages">${(chat.messages||[]).map(m=>`<div class="msg-row ${m.role}"><div class="msg-role-badge ${m.role}">${m.role==='user'?'👤 User':'⚡ AI'}</div><div class="msg-content-text">${esc(m.content).replace(/\n/g,'<br>')}</div></div>`).join('')||'<div style="padding:12px;color:var(--t3);font-size:12px">No messages.</div>'}</div>
    </div>`).join('');
}
function closeMsgViewer(){document.getElementById('msgViewerModal').classList.remove('open');_viewingUid='';}
function downloadUserMessages(){if(!_viewingUid)return;window.open(`/api/admin/users/${_viewingUid}/messages/download`,'_blank');}
function timeAgo(ts){const s=Math.floor((Date.now()-ts)/1000);if(s<60)return'just now';if(s<3600)return Math.floor(s/60)+'m ago';if(s<86400)return Math.floor(s/3600)+'h ago';return Math.floor(s/86400)+'d ago';}

