/**
 * CYBERSCOPE — Supabase & Backend Authentication Client
 * Provides unified authentication, database token verification, session persistence,
 * live duplicate email detection, and seamless fallback for local demonstration/evaluation.
 */
(function(window) {
  'use strict';

  var SUPABASE_CDN = 'https://cdn.jsdelivr.net/npm/@supabase/supabase-js@2';
  var STORAGE_USER_KEY = 'cyberscopeUser';
  var STORAGE_SESSION_KEY = 'cyberscopeSession';
  var STORAGE_TOKEN_KEY = 'cyberscopeAccessToken';
  var STORAGE_CUSTOM_URL = 'cyberscope_supabase_url';
  var STORAGE_CUSTOM_KEY = 'cyberscope_supabase_anon_key';

  var DEMO_ACCOUNT = {
    id: 'demo-investigator-001',
    email: 'investigator@cyberscope.io',
    password: 'password123',
    name: 'Investigator Demo',
    role: 'Investigator',
    phone: '+919876543210',
    organization: 'TetraByte Cyber Defense',
    is_demo: true
  };

  var state = {
    client: null,
    configured: false,
    url: '',
    anonKey: '',
    initialized: false,
    initPromise: null
  };

  function getApiEndpoint(path) {
    if (typeof window !== 'undefined' && window.location && window.location.protocol === 'file:') {
      return 'http://127.0.0.1:8000' + path;
    }
    return path;
  }

  function loadScript(src) {
    return new Promise(function(resolve, reject) {
      if (window.supabase) return resolve(window.supabase);
      var existing = document.querySelector('script[src*="@supabase/supabase-js"]');
      if (existing) {
        existing.addEventListener('load', function() { resolve(window.supabase); });
        existing.addEventListener('error', reject);
        return;
      }
      var s = document.createElement('script');
      s.src = src;
      s.async = true;
      s.onload = function() { resolve(window.supabase); };
      s.onerror = function() { reject(new Error('Failed to load Supabase SDK from CDN')); };
      document.head.appendChild(s);
    });
  }

  // Clear any legacy custom config stored in localStorage from earlier in-page settings
  try {
    localStorage.removeItem(STORAGE_CUSTOM_URL);
    localStorage.removeItem(STORAGE_CUSTOM_KEY);
  } catch(e) {}

  var PROJECT_ENV_CONFIG = {
    url: 'https://ivyzighppyaiizunvqkb.supabase.co',
    anonKey: 'sb_publishable_r0f7WBvARHXEnK2E1IqfKQ_T-t5SGrY'
  };

  async function fetchServerConfig() {
    try {
      var res = await fetch(getApiEndpoint('/api/auth/config'));
      if (res.ok) {
        var data = await res.json();
        if (data.supabase_url && data.supabase_anon_key) {
          return { url: data.supabase_url, anonKey: data.supabase_anon_key };
        }
      }
    } catch (e) {
      // Backend not running or offline
    }
    return null;
  }

  async function init() {
    if (state.initPromise) return state.initPromise;

    state.initPromise = (async function() {
      // 1. Determine Supabase config: window override -> server endpoint (/api/auth/config) -> project .env credentials
      var config = null;

      if (window.CYBERSCOPE_SUPABASE_CONFIG) {
        config = window.CYBERSCOPE_SUPABASE_CONFIG;
      }

      if (!config) {
        config = await fetchServerConfig();
      }

      if (!config || !config.url || !config.anonKey) {
        config = PROJECT_ENV_CONFIG;
      }

      if (config && config.url && config.anonKey && config.url.indexOf('your-project') === -1) {
        state.url = config.url;
        state.anonKey = config.anonKey;
        state.configured = true;
      } else {
        state.configured = false;
      }

      // 2. Load Supabase library if configured
      if (state.configured) {
        try {
          await loadScript(SUPABASE_CDN);
          if (window.supabase && typeof window.supabase.createClient === 'function') {
            state.client = window.supabase.createClient(state.url, state.anonKey, {
              auth: {
                persistSession: true,
                autoRefreshToken: true,
                detectSessionInUrl: true
              }
            });

            // Listen to auth state changes
            state.client.auth.onAuthStateChange(function(event, session) {
              if (session && session.user) {
                var meta = session.user.user_metadata || {};
                var u = {
                  id: session.user.id,
                  email: session.user.email,
                  name: meta.name || meta.full_name || (session.user.email ? session.user.email.split('@')[0] : 'Investigator'),
                  role: meta.role || 'Investigator',
                  phone: meta.phone || '',
                  organization: meta.organization || '',
                  is_demo: false
                };
                localStorage.setItem(STORAGE_USER_KEY, JSON.stringify(u));
                localStorage.setItem(STORAGE_SESSION_KEY, 'active');
                localStorage.setItem(STORAGE_TOKEN_KEY, session.access_token);
              } else if (event === 'SIGNED_OUT') {
                var activeUser = getUser();
                // Only clear if not an active database investigator
                if (!activeUser || activeUser.is_demo) {
                  localStorage.removeItem(STORAGE_USER_KEY);
                  localStorage.removeItem(STORAGE_SESSION_KEY);
                  localStorage.removeItem(STORAGE_TOKEN_KEY);
                }
              }
            });
          }
        } catch (err) {
          console.warn('Supabase initialization warning:', err);
          state.configured = false;
        }
      }

      // Fallback demo account setup if no local user is stored
      if (!localStorage.getItem(STORAGE_USER_KEY)) {
        localStorage.setItem(STORAGE_USER_KEY, JSON.stringify(DEMO_ACCOUNT));
      }

      state.initialized = true;
      return state;
    })();

    return state.initPromise;
  }

  function getUser() {
    try {
      var cached = JSON.parse(localStorage.getItem(STORAGE_USER_KEY) || 'null');
      if (cached) {
        return cached;
      }
      // Reconstruct user identity from database access token claims if present
      var token = localStorage.getItem(STORAGE_TOKEN_KEY);
      if (token && token.indexOf('.') !== -1) {
        var parts = token.split('.');
        if (parts.length === 3) {
          var payloadStr = atob(parts[1].replace(/-/g, '+').replace(/_/g, '/'));
          var payload = JSON.parse(payloadStr);
          var meta = payload.user_metadata || {};
          var userObj = {
            id: payload.sub || payload.id || 'usr-jwt',
            email: payload.email || '',
            name: meta.name || meta.full_name || (payload.email ? payload.email.split('@')[0] : 'Investigator'),
            role: meta.role || payload.role || 'Investigator',
            phone: meta.phone || '',
            organization: meta.organization || '',
            is_demo: false
          };
          localStorage.setItem(STORAGE_USER_KEY, JSON.stringify(userObj));
          return userObj;
        }
      }
      return null;
    } catch(e) {
      return null;
    }
  }

  function isAuthenticated() {
    return localStorage.getItem(STORAGE_SESSION_KEY) === 'active' && Boolean(getUser());
  }

  function getAuthHeaders() {
    var token = localStorage.getItem(STORAGE_TOKEN_KEY);
    if (token) {
      return { 'Authorization': 'Bearer ' + token };
    }
    return {};
  }

  async function checkEmail(email) {
    var cleanedEmail = (email || '').trim().toLowerCase();
    if (!cleanedEmail) {
      return { exists: false, error: 'Email cannot be empty' };
    }

    try {
      var res = await fetch(getApiEndpoint('/api/auth/check-email'), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email: cleanedEmail })
      });

      if (res.ok) {
        var data = await res.json();
        return {
          exists: Boolean(data.exists),
          email: cleanedEmail,
          message: data.message || '',
          data: data
        };
      }
    } catch (err) {
      // Backend offline or unreachable
    }

    // Fallback offline / demo check
    var savedUser = getUser();
    var demoMatch = (cleanedEmail === String(DEMO_ACCOUNT.email).toLowerCase());
    var savedMatch = (savedUser && cleanedEmail === String(savedUser.email).toLowerCase());
    return {
      exists: Boolean(demoMatch || savedMatch),
      email: cleanedEmail,
      is_offline: true
    };
  }

  async function signIn(credentials) {
    await init();
    var email = (credentials.email || '').trim().toLowerCase();
    var password = credentials.password || '';

    if (!email || !password) {
      return { success: false, error: { message: 'Please enter both email and password.' } };
    }

    // A. Coordinate with backend /api/auth/login endpoint first when available
    try {
      var loginRes = await fetch(getApiEndpoint('/api/auth/login'), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email: email, password: password })
      });

      if (loginRes.status === 200) {
        var data = await loginRes.json();
        var userObj = data.user || {
          id: data.id || 'db-user',
          email: email,
          name: data.name || email.split('@')[0],
          role: data.role || 'Investigator',
          phone: data.phone || '',
          organization: data.organization || '',
          is_demo: false
        };

        localStorage.setItem(STORAGE_USER_KEY, JSON.stringify(userObj));
        localStorage.setItem(STORAGE_SESSION_KEY, 'active');
        if (data.access_token) {
          localStorage.setItem(STORAGE_TOKEN_KEY, data.access_token);
        }

        return {
          success: true,
          user: userObj,
          session: { access_token: data.access_token },
          access_token: data.access_token
        };
      } else if (loginRes.status === 404) {
        return {
          success: false,
          status: 404,
          error: {
            code: 'USER_NOT_FOUND',
            message: 'No account found with this email. Please register a new account.'
          }
        };
      } else if (loginRes.status === 401) {
        return {
          success: false,
          status: 401,
          error: {
            code: 'INVALID_PASSWORD',
            message: 'Incorrect password. Please verify your credentials or use "Forgot password?".'
          }
        };
      } else if (loginRes.status >= 400 && loginRes.status < 500) {
        var errJson = await loginRes.json().catch(function() { return {}; });
        return {
          success: false,
          status: loginRes.status,
          error: {
            message: errJson.detail || errJson.message || 'Authentication failed.'
          }
        };
      }
      // If 5xx, proceed to Supabase / Demo fallback
    } catch (netErr) {
      // Backend offline or unreachable, fall back gracefully
    }

    // B. Use real Supabase client if configured
    if (state.configured && state.client) {
      try {
        var res = await state.client.auth.signInWithPassword({
          email: email,
          password: password
        });

        if (res.error) {
          return { success: false, error: res.error };
        }

        var session = res.data.session;
        var user = res.data.user;
        var meta = (user && user.user_metadata) || {};
        var userObj = {
          id: user.id,
          email: user.email,
          name: meta.name || meta.full_name || email.split('@')[0],
          role: meta.role || 'Investigator',
          phone: meta.phone || '',
          organization: meta.organization || '',
          is_demo: false
        };

        localStorage.setItem(STORAGE_USER_KEY, JSON.stringify(userObj));
        localStorage.setItem(STORAGE_SESSION_KEY, 'active');
        if (session) {
          localStorage.setItem(STORAGE_TOKEN_KEY, session.access_token);
        }

        return {
          success: true,
          user: userObj,
          session: session,
          access_token: session ? session.access_token : null
        };
      } catch (err) {
        return { success: false, error: { message: err.message || 'Supabase authentication failed.' } };
      }
    }

    // C. Demo mode authentication fallback
    var savedUser = getUser() || DEMO_ACCOUNT;
    var demoMatch = (email === String(DEMO_ACCOUNT.email).toLowerCase() && password === DEMO_ACCOUNT.password);
    var savedMatch = (savedUser && email === String(savedUser.email).toLowerCase() && (password === savedUser.password || password === 'password123'));

    if (demoMatch || savedMatch) {
      var activeUser = demoMatch ? DEMO_ACCOUNT : savedUser;
      localStorage.setItem(STORAGE_USER_KEY, JSON.stringify(activeUser));
      localStorage.setItem(STORAGE_SESSION_KEY, 'active');
      localStorage.setItem(STORAGE_TOKEN_KEY, 'demo-token');
      return {
        success: true,
        user: activeUser,
        session: { access_token: 'demo-token' },
        access_token: 'demo-token'
      };
    }

    return {
      success: false,
      error: { message: 'Invalid email or password. (For demo login, use investigator@cyberscope.io / password123)' }
    };
  }

  async function signUp(data) {
    await init();
    var email = (data.email || '').trim().toLowerCase();
    var password = data.password || '';
    var name = (data.name || '').trim();
    var phone = (data.phone || '').trim();
    var role = data.role || 'Investigator';
    var organization = (data.organization || '').trim();

    if (!email || !password || !name) {
      return { success: false, error: { message: 'Please provide name, email, and password.' } };
    }

    // A. Coordinate with backend /api/auth/register/initiate endpoint first when available
    try {
      var regRes = await fetch(getApiEndpoint('/api/auth/register/initiate'), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          name: name,
          email: email,
          phone: phone,
          password: password,
          role: role,
          organization: organization
        })
      });

      if (regRes.status === 200 || regRes.status === 201) {
        var regData = await regRes.json();
        return {
          success: true,
          requiresVerification: true,
          data: regData,
          delivery: regData.delivery || null,
          preview: regData.preview || null,
          email_otp: (regData.preview && regData.preview.email_otp) || null,
          message: regData.message || 'Verification code sent to your official email.'
        };
      } else if (regRes.status === 409) {
        var conflictData = await regRes.json().catch(function() { return {}; });
        return {
          success: false,
          status: 409,
          error: {
            code: 'EMAIL_ALREADY_EXISTS',
            message: conflictData.detail || 'An account with this email address already exists. Please sign in instead.'
          }
        };
      } else if (regRes.status >= 400 && regRes.status < 500) {
        var errData = await regRes.json().catch(function() { return {}; });
        return {
          success: false,
          status: regRes.status,
          error: { message: errData.detail || errData.message || 'Registration failed.' }
        };
      }
    } catch (netErr) {
      // Backend unreachable or offline, proceed to Supabase / demo fallback
    }

    // B. Use real Supabase client if configured
    if (state.configured && state.client) {
      try {
        var res = await state.client.auth.signUp({
          email: email,
          password: password,
          options: {
            data: {
              name: name,
              phone: phone,
              role: role,
              organization: organization
            }
          }
        });

        if (res.error) {
          return { success: false, error: res.error };
        }

        var sbUser = res.data.user;
        var session = res.data.session;
        var sbUserObj = {
          id: sbUser ? sbUser.id : 'sb-user',
          email: email,
          name: name,
          phone: phone,
          role: role,
          organization: organization,
          is_demo: false
        };

        // Cache details
        localStorage.setItem(STORAGE_USER_KEY, JSON.stringify(sbUserObj));
        if (session) {
          localStorage.setItem(STORAGE_SESSION_KEY, 'active');
          localStorage.setItem(STORAGE_TOKEN_KEY, session.access_token);
        }

        return {
          success: true,
          user: sbUserObj,
          session: session,
          needsEmailConfirmation: sbUser && !session
        };
      } catch (err) {
        return { success: false, error: { message: err.message || 'Supabase signup failed.' } };
      }
    }

    // C. Demo mode signup fallback
    var newUser = {
      id: 'demo-' + Date.now(),
      email: email,
      password: password,
      name: name,
      phone: phone,
      role: role,
      organization: organization,
      is_demo: true
    };
    localStorage.setItem(STORAGE_USER_KEY, JSON.stringify(newUser));
    localStorage.removeItem(STORAGE_SESSION_KEY);
    return {
      success: true,
      user: newUser,
      session: null,
      needsEmailConfirmation: false
    };
  }

  async function verifyRegistration(email, emailOtp) {
    var payload;
    if (typeof email === 'object' && email !== null) {
      payload = {
        email: (email.email || '').trim().toLowerCase(),
        email_otp: (email.email_otp || email.emailOtp || '').trim().toUpperCase()
      };
    } else {
      payload = {
        email: (email || '').trim().toLowerCase(),
        email_otp: (emailOtp || '').trim().toUpperCase()
      };
    }

    try {
      var res = await fetch(getApiEndpoint('/api/auth/register/verify'), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      });
      var data = await res.json();
      if (res.ok && data.user) {
        localStorage.setItem(STORAGE_USER_KEY, JSON.stringify(data.user));
        localStorage.setItem(STORAGE_SESSION_KEY, 'active');
        if (data.access_token) {
          localStorage.setItem(STORAGE_TOKEN_KEY, data.access_token);
        }
        return { success: true, user: data.user, access_token: data.access_token, data: data };
      }
      return {
        success: false,
        error: { message: data.detail || data.message || 'Verification failed.' }
      };
    } catch (err) {
      return { success: false, error: { message: err.message || 'Network error during verification.' } };
    }
  }

  async function resendVerification(email) {
    try {
      var res = await fetch(getApiEndpoint('/api/auth/register/resend'), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email: (email || '').trim().toLowerCase() })
      });
      var data = await res.json();
      if (res.ok) {
        return { success: true, data: data, preview: data.preview, delivery: data.delivery || null };
      }
      return {
        success: false,
        error: { message: data.detail || data.message || 'Failed to resend code.' }
      };
    } catch (err) {
      return { success: false, error: { message: err.message || 'Network error during resend.' } };
    }
  }

  async function signOut() {
    try {
      if (state.configured && state.client) {
        await state.client.auth.signOut();
      }
    } catch(e) {}
    localStorage.removeItem(STORAGE_SESSION_KEY);
    localStorage.removeItem(STORAGE_TOKEN_KEY);
    return true;
  }

  async function resetPassword(email) {
    await init();
    if (!email) return { success: false, error: { message: 'Please enter your email address.' } };

    if (state.configured && state.client) {
      try {
        var res = await state.client.auth.resetPasswordForEmail(email, {
          redirectTo: window.location.origin + '/signin.html'
        });
        if (res.error) return { success: false, error: res.error };
        return { success: true, message: 'Password reset instructions have been sent to ' + email };
      } catch(err) {
        return { success: false, error: { message: err.message } };
      }
    }

    return {
      success: true,
      message: 'Demo mode: In live mode, Supabase will dispatch an email recovery link. For demo testing, use password123.'
    };
  }

  async function verifySession() {
    await init();
    var token = localStorage.getItem(STORAGE_TOKEN_KEY);
    var session = localStorage.getItem(STORAGE_SESSION_KEY);

    if (session !== 'active') {
      return false;
    }

    // 1. Validate database token via /api/auth/verify
    if (token) {
      try {
        var res = await fetch(getApiEndpoint('/api/auth/verify'), {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ access_token: token })
        });

        if (res.status === 200) {
          var data = await res.json();
          if (data && data.valid) {
            if (data.user) {
              localStorage.setItem(STORAGE_USER_KEY, JSON.stringify(data.user));
            }
            return true;
          }
        } else if (res.status === 401 || res.status === 403) {
          // Token expired or invalid
          localStorage.removeItem(STORAGE_SESSION_KEY);
          localStorage.removeItem(STORAGE_TOKEN_KEY);
          localStorage.removeItem(STORAGE_USER_KEY);
          return false;
        }
      } catch (err) {
        // Backend offline, proceed to fallback checks
      }
    }

    // 2. Real Supabase client check if configured
    if (state.configured && state.client) {
      try {
        var sbRes = await state.client.auth.getSession();
        if (sbRes && sbRes.data && sbRes.data.session) {
          return true;
        }
      } catch (e) {}
    }

    // 3. Honor valid local database investigator sessions
    // Do NOT let null Supabase cloud session destroy authenticated database investigators
    if (session === 'active' && user && (user.email || user.id)) {
      return true;
    }

    return isAuthenticated();
  }

  function setCustomConfig(url, key) {
    if (url && key) {
      localStorage.setItem(STORAGE_CUSTOM_URL, url.trim());
      localStorage.setItem(STORAGE_CUSTOM_KEY, key.trim());
      state.initialized = false;
      state.initPromise = null;
      return true;
    }
    return false;
  }

  function clearCustomConfig() {
    localStorage.removeItem(STORAGE_CUSTOM_URL);
    localStorage.removeItem(STORAGE_CUSTOM_KEY);
    state.initialized = false;
    state.initPromise = null;
  }

  // Auto-initialize in background on page load
  if (typeof document !== 'undefined') {
    if (document.readyState === 'loading') {
      document.addEventListener('DOMContentLoaded', function() { init(); });
    } else {
      init();
    }
  }

  // Export public API
  window.CyberScopeAuth = {
    init: init,
    getUser: getUser,
    isAuthenticated: isAuthenticated,
    getAuthHeaders: getAuthHeaders,
    signIn: signIn,
    signUp: signUp,
    signOut: signOut,
    resetPassword: resetPassword,
    verifySession: verifySession,
    checkEmail: checkEmail,
    verifyRegistration: verifyRegistration,
    resendVerification: resendVerification,
    setCustomConfig: setCustomConfig,
    clearCustomConfig: clearCustomConfig,
    isConfigured: function() { return state.configured; },
    getConfig: function() { return { url: state.url, configured: state.configured }; },
    DEMO_ACCOUNT: DEMO_ACCOUNT
  };

})(typeof window !== 'undefined' ? window : this);
