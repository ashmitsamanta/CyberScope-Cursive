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

/* ---------- chat assistant launcher ---------- */
function cyberscopeInitChat(){
  var button = document.getElementById('chatButton');
  if(!button) return;
  button.setAttribute('title', 'Open CyberScope AI Assistant');
  button.setAttribute('aria-label', 'Open CyberScope AI Assistant');
  if(button.tagName.toLowerCase() !== 'a'){
    button.addEventListener('click', function(e){
      e.preventDefault();
      window.location.href = 'chatbot.html';
    });
  }
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
