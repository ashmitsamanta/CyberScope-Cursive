/* =========================================================
   CYBERSCOPE — shared app shell script
   Loaded by every internal page.
   Server-Verified Authentication Protection & Global Fetch Wrapper
   ========================================================= */

// Global Fetch Interceptor to propagate Bearer token and handle 401
(function() {
  if (typeof window === 'undefined') return;
  var origFetch = window.fetch;
  window.fetch = function(resource, initOptions) {
    initOptions = initOptions || {};
    var url = typeof resource === 'string' ? resource : (resource && resource.url) || '';
    var token = localStorage.getItem('cyberscopeAccessToken');

    if (token && !url.includes('/api/auth/login') && !url.includes('/api/auth/register')) {
      if (typeof Headers !== 'undefined' && initOptions.headers instanceof Headers) {
        if (!initOptions.headers.has('Authorization')) {
          initOptions.headers.append('Authorization', 'Bearer ' + token);
        }
      } else if (Array.isArray(initOptions.headers)) {
        var hasAuth = initOptions.headers.some(function(pair) {
          return pair[0] && pair[0].toLowerCase() === 'authorization';
        });
        if (!hasAuth) {
          initOptions.headers.push(['Authorization', 'Bearer ' + token]);
        }
      } else {
        initOptions.headers = initOptions.headers || {};
        var keys = Object.keys(initOptions.headers);
        var hasAuth = keys.some(function(k) { return k.toLowerCase() === 'authorization'; });
        if (!hasAuth) {
          initOptions.headers['Authorization'] = 'Bearer ' + token;
        }
      }
    }

    return origFetch.call(this, resource, initOptions).then(function(response) {
      if (response && response.status === 401) {
        if (!url.includes('/api/auth/login') && !url.includes('/api/auth/verify')) {
          localStorage.removeItem('cyberscopeSession');
          localStorage.removeItem('cyberscopeUser');
          localStorage.removeItem('cyberscopeAccessToken');
          var here = location.pathname.split('/').pop() || 'dashboard.html';
          if (!location.href.includes('signin.html') && !location.href.includes('index.html')) {
            location.replace('index.html?login=1&redirect=' + encodeURIComponent(here));
          }
        }
      }
      return response;
    });
  };
})();

function cyberscopeUser() {
  if (window.CyberScopeAuth && typeof window.CyberScopeAuth.getUser === 'function') {
    return window.CyberScopeAuth.getUser();
  }
  try { return JSON.parse(localStorage.getItem('cyberscopeUser') || 'null'); }
  catch(e) { return null; }
}

function cyberscopeInitials(name) {
  return (name || 'CS').trim().split(/\s+/).filter(Boolean).slice(0, 2)
    .map(function(x) { return x[0]; }).join('').toUpperCase() || 'CS';
}

function cyberscopeProtect() {
  var token = localStorage.getItem('cyberscopeAccessToken');
  var here = location.pathname.split('/').pop() || 'dashboard.html';
  if (!token) {
    localStorage.removeItem('cyberscopeSession');
    localStorage.removeItem('cyberscopeUser');
    localStorage.removeItem('cyberscopeAccessToken');
    location.replace('index.html?login=1&redirect=' + encodeURIComponent(here));
    return Promise.resolve(false);
  }

  function handleVerifyResult(valid) {
    if (!valid) {
      localStorage.removeItem('cyberscopeSession');
      localStorage.removeItem('cyberscopeUser');
      localStorage.removeItem('cyberscopeAccessToken');
      location.replace('index.html?login=1&redirect=' + encodeURIComponent(here));
      return false;
    }

    document.documentElement.classList.remove('cs-pending');
    var user = cyberscopeUser();
    if (user) {
      var name = user.name || user.email || 'User';
      var nameEl = document.getElementById('profileName');
      var avatarEl = document.getElementById('avatar');
      var roleEl = document.querySelector('.prole');
      if (nameEl) nameEl.textContent = name;
      if (avatarEl) avatarEl.textContent = cyberscopeInitials(name);
      if (roleEl && user.role) roleEl.textContent = user.role;
    }
    return true;
  }

  if (window.CyberScopeAuth && typeof window.CyberScopeAuth.verifySession === 'function') {
    return window.CyberScopeAuth.verifySession().then(handleVerifyResult).catch(function() {
      return handleVerifyResult(false);
    });
  }

  var endpoint = (typeof getApiEndpoint === 'function') ? getApiEndpoint('/api/auth/verify') : '/api/auth/verify';
  return fetch(endpoint, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': 'Bearer ' + token
    },
    body: JSON.stringify({ access_token: token })
  }).then(function(res) {
    if (res.ok) {
      return res.json().then(function(data) {
        if (data && data.valid && data.user) {
          localStorage.setItem('cyberscopeUser', JSON.stringify(data.user));
          localStorage.setItem('cyberscopeSession', 'active');
          return handleVerifyResult(true);
        }
        return handleVerifyResult(false);
      });
    }
    return handleVerifyResult(false);
  }).catch(function() {
    return handleVerifyResult(false);
  });
}

function signOut() {
  if (window.CyberScopeAuth && typeof window.CyberScopeAuth.signOut === 'function') {
    window.CyberScopeAuth.signOut().then(function() {
      location.href = 'signin.html';
    }).catch(function() {
      location.href = 'signin.html';
    });
  } else {
    localStorage.removeItem('cyberscopeSession');
    localStorage.removeItem('cyberscopeUser');
    localStorage.removeItem('cyberscopeAccessToken');
    location.href = 'signin.html';
  }
}

function cyberscopeSetActiveNav() {
  var here = location.pathname.split('/').pop() || 'dashboard.html';
  document.querySelectorAll('.nav a[href]').forEach(function(a) {
    var target = a.getAttribute('href').split('/').pop();
    a.classList.toggle('active', target === here);
  });
}

function cyberscopeInitNav() {
  var toggle = document.getElementById('navToggle');
  var nav = document.getElementById('siteNav');
  var backdrop = document.getElementById('navBackdrop');
  if (!toggle || !nav) return;

  function close() {
    nav.classList.remove('open');
    toggle.classList.remove('open');
    toggle.setAttribute('aria-expanded', 'false');
    if (backdrop) backdrop.classList.remove('open');
  }
  function open() {
    nav.classList.add('open');
    toggle.classList.add('open');
    toggle.setAttribute('aria-expanded', 'true');
    if (backdrop) backdrop.classList.add('open');
  }
  toggle.addEventListener('click', function() {
    nav.classList.contains('open') ? close() : open();
  });
  if (backdrop) backdrop.addEventListener('click', close);
  nav.querySelectorAll('a').forEach(function(a) { a.addEventListener('click', close); });
  document.addEventListener('keydown', function(e) {
    if (e.key === 'Escape') close();
  });
}

function cyberscopeInitChat() {
  var button = document.getElementById('chatButton');
  if (!button) return;
  button.setAttribute('title', 'Open CyberScope AI Assistant');
  button.setAttribute('aria-label', 'Open CyberScope AI Assistant');
  if (button.tagName.toLowerCase() !== 'a') {
    button.addEventListener('click', function(e) {
      e.preventDefault();
      window.location.href = 'chatbot.html';
    });
  }
}

document.addEventListener('DOMContentLoaded', function() {
  cyberscopeSetActiveNav();
  cyberscopeInitNav();
  cyberscopeInitChat();
});
