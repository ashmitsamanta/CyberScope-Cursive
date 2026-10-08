/* =========================================================
   CYBERSCOPE — shared app shell script
   Loaded by every internal page.
   Supabase Authentication integration with role synchronization,
   automatic token propagation, and session protection.
   ========================================================= */

/* ---------- auth (Supabase Integration) ---------- */
function cyberscopeUser(){
  if(window.CyberScopeAuth && typeof window.CyberScopeAuth.getUser === 'function'){
    return window.CyberScopeAuth.getUser();
  }
  try{ return JSON.parse(localStorage.getItem('cyberscopeUser')||'null'); }
  catch(e){ return null; }
}

function cyberscopeInitials(name){
  return (name||'CS').trim().split(/\s+/).filter(Boolean).slice(0,2)
    .map(function(x){return x[0];}).join('').toUpperCase() || 'CS';
}

function cyberscopeProtect(){
  var user = cyberscopeUser();
  var session = localStorage.getItem('cyberscopeSession');
  if(session !== 'active' || !user){
    var here = location.pathname.split('/').pop() || 'dashboard.html';
    location.href = 'signin.html?redirect=' + encodeURIComponent(here);
    return false;
  }
  var name = user.name || user.email || 'User';
  var nameEl = document.getElementById('profileName');
  var avatarEl = document.getElementById('avatar');
  var roleEl = document.querySelector('.prole');
  if(nameEl) nameEl.textContent = name;
  if(avatarEl) avatarEl.textContent = cyberscopeInitials(name);
  if(roleEl && user.role) roleEl.textContent = user.role;

  // Background session verification with Supabase
  if(window.CyberScopeAuth && typeof window.CyberScopeAuth.verifySession === 'function'){
    window.CyberScopeAuth.verifySession().then(function(valid){
      if(!valid){
        var localUser = cyberscopeUser();
        var localSession = localStorage.getItem('cyberscopeSession');
        if (localSession === 'active' && localUser && (localUser.email || localUser.id)) {
          return;
        }
        var here = location.pathname.split('/').pop() || 'dashboard.html';
        location.href = 'signin.html?redirect=' + encodeURIComponent(here);
      }
    }).catch(function(err){
      console.warn("Session verification warning:", err);
    });
  }
  return true;
}

function signOut(){
  if(window.CyberScopeAuth && typeof window.CyberScopeAuth.signOut === 'function'){
    window.CyberScopeAuth.signOut().then(function(){
      location.href = 'signin.html';
    }).catch(function(){
      location.href = 'signin.html';
    });
  } else {
    localStorage.removeItem('cyberscopeSession');
    localStorage.removeItem('cyberscopeAccessToken');
    location.href = 'signin.html';
  }
}

/* ---------- active nav link, set from the current filename ---------- */
function cyberscopeSetActiveNav(){
  var here = location.pathname.split('/').pop() || 'dashboard.html';
  document.querySelectorAll('.nav a[href]').forEach(function(a){
    var target = a.getAttribute('href').split('/').pop();
    a.classList.toggle('active', target === here);
  });
}

/* ---------- mobile nav drawer ---------- */
function cyberscopeInitNav(){
  var toggle = document.getElementById('navToggle');
  var nav = document.getElementById('siteNav');
  var backdrop = document.getElementById('navBackdrop');
  if(!toggle || !nav) return;

  function close(){
    nav.classList.remove('open');
    toggle.classList.remove('open');
    toggle.setAttribute('aria-expanded','false');
    if(backdrop) backdrop.classList.remove('open');
  }
  function open(){
    nav.classList.add('open');
    toggle.classList.add('open');
    toggle.setAttribute('aria-expanded','true');
    if(backdrop) backdrop.classList.add('open');
  }
  toggle.addEventListener('click', function(){
    nav.classList.contains('open') ? close() : open();
  });
  if(backdrop) backdrop.addEventListener('click', close);
  nav.querySelectorAll('a').forEach(function(a){ a.addEventListener('click', close); });
  document.addEventListener('keydown', function(e){
    if(e.key === 'Escape') close();
  });
}

/* ---------- chat widget (one canonical version, textContent-only) ---------- */
var CYBERSCOPE_RESPONSES = [
  { test:/fraud graph|graph/, text:'The Fraud Graph visualizes relationships between phones, UPI IDs, bank accounts, domains and cases, so investigators can see links that are not obvious when incidents are viewed separately.' },
  { test:/entit/,             text:'Entities are investigation objects such as phone numbers, domains, UPI IDs and bank accounts that can be connected across fraud incidents.' },
  { test:/case/,              text:'Cases represent individual fraud incidents or investigation records. CyberScope connects cases through shared entities and infrastructure.' },
  { test:/transaction/,       text:'Transaction Explorer helps investigators examine financial flows and identify potentially connected transaction activity across cases.' },
  { test:/campaign/,          text:'Campaign Explorer groups related incidents into possible coordinated campaigns using shared infrastructure and entity signals.' },
  { test:/workspace|investigation/, text:'The Investigation Workspace brings case information, evidence, linked entities and notes together in one working area.' },
  { test:/dashboard|overview/, text:'The dashboard gives a high-level view of active cases, linked entities, risk signals, campaigns and recent activity.' },
  { test:/cyberscope|what is/, text:'CyberScope is a cyber-fraud intelligence platform for connecting fragmented incidents, entities, transactions and campaigns into one investigation environment.' },
  { test:/help/,              text:'I can explain the Dashboard, Cases, Fraud Graph, Entities, Transactions, Campaigns and Investigation Workspace.' }
];
function cyberscopeAnswer(question){
  var q = question.toLowerCase();
  for(var i=0;i<CYBERSCOPE_RESPONSES.length;i++){
    if(CYBERSCOPE_RESPONSES[i].test.test(q)) return CYBERSCOPE_RESPONSES[i].text;
  }
  return 'Try asking about the Fraud Graph, Cases, Entities, Transactions, Campaigns or the Investigation Workspace.';
}

function cyberscopeInitChat(){
  var button = document.getElementById('chatButton');
  var win = document.getElementById('chatWindow');
  var messages = document.getElementById('chatMessages');
  var input = document.getElementById('chatInput');
  var sendBtn = document.getElementById('chatSend');
  var closeBtn = document.getElementById('chatClose');
  if(!button || !win || !messages || !input) return;

  function toggle(){
    win.classList.toggle('active');
    if(win.classList.contains('active')) setTimeout(function(){ input.focus(); }, 150);
  }
  function addMessage(text, cls){
    var div = document.createElement('div');
    div.className = 'chat-message ' + cls;
    div.textContent = text; // textContent only — no innerHTML, no injected markup
    messages.appendChild(div);
    messages.scrollTop = messages.scrollHeight;
  }
  async function send(){
    var q = input.value.trim();
    if(!q) return;
    addMessage(q, 'user-message');
    input.value = '';

    var typing = document.createElement('div');
    typing.className = 'chat-message bot-message';
    typing.id = 'typingIndicator';
    var wrap = document.createElement('div');
    wrap.className = 'typing';
    wrap.innerHTML = '<span></span><span></span><span></span>'; // static markup, no user data
    typing.appendChild(wrap);
    messages.appendChild(typing);
    messages.scrollTop = messages.scrollHeight;

    try {
      var authHeaders = (window.CyberScopeAuth && typeof window.CyberScopeAuth.getAuthHeaders === 'function')
        ? window.CyberScopeAuth.getAuthHeaders()
        : {};
      var res = await fetch('/api/chat', {
        method: 'POST',
        headers: Object.assign({ 'Content-Type': 'application/json' }, authHeaders),
        body: JSON.stringify({
          model: 'meta/llama-3.2-11b-vision-instruct',
          messages: [{ role: 'user', content: q }]
        })
      });
      if (res.ok) {
        var data = await res.json();
        var reply = data.choices && data.choices[0] && data.choices[0].message ? data.choices[0].message.content : null;
        if (reply) {
          var indicator = document.getElementById('typingIndicator');
          if (indicator) indicator.remove();
          addMessage(reply, 'bot-message');
          return;
        }
      }
    } catch(e) {
      // Backend / proxy offline, fall back to local responses
    }

    setTimeout(function(){
      var indicator = document.getElementById('typingIndicator');
      if(indicator) indicator.remove();
      addMessage(cyberscopeAnswer(q), 'bot-message');
    }, 450);
  }

  button.addEventListener('click', toggle);
  if(closeBtn) closeBtn.addEventListener('click', toggle);
  if(sendBtn) sendBtn.addEventListener('click', send);
  input.addEventListener('keydown', function(e){ if(e.key === 'Enter') send(); });
  document.querySelectorAll('.chat-quick button[data-q]').forEach(function(b){
    b.addEventListener('click', function(){
      input.value = b.getAttribute('data-q');
      send();
    });
  });
}

/* cyberscopeProtect() is called explicitly by each page (like the
   original code did) rather than auto-run here, because the
   dashboard uses a different, modal-based auth gate instead of a
   redirect — see the note in dashboard.html. Nav + chat are safe
   to initialize on every page regardless of auth state. */
document.addEventListener('DOMContentLoaded', function(){
  cyberscopeSetActiveNav();
  cyberscopeInitNav();
  cyberscopeInitChat();
});
