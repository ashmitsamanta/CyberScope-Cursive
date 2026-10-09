/**
 * CYBERSCOPE — Supabase & Backend Authentication Client
 * Provides unified authentication, database token verification, session persistence,
 * live duplicate email detection, and server-first authentication security.
 */
(function(window) {
  'use strict';

  var SUPABASE_CDN = 'https://cdn.jsdelivr.net/npm/@supabase/supabase-js@2';
  var STORAGE_USER_KEY = 'cyberscopeUser';
  var STORAGE_SESSION_KEY = 'cyberscopeSession';
  var STORAGE_TOKEN_KEY = 'cyberscopeAccessToken';
  var STORAGE_CUSTOM_URL = 'cyberscope_supabase_url';
  var STORAGE_CUSTOM_KEY = 'cyberscope_supabase_anon_key';

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

            state.client.auth.onAuthStateChange(function(event, session) {
              if (session && session.user && session.access_token) {
                localStorage.setItem(STORAGE_TOKEN_KEY, session.access_token);
              } else if (event === 'SIGNED_OUT') {
                localStorage.removeItem(STORAGE_USER_KEY);
                localStorage.removeItem(STORAGE_SESSION_KEY);
                localStorage.removeItem(STORAGE_TOKEN_KEY);
              }
            });
          }
        } catch (err) {
          console.warn('Supabase initialization warning:', err);
          state.configured = false;
        }
      }

      state.initialized = true;
      return state;
    })();

    return state.initPromise;
  }

  function getUser() {
    try {
      return JSON.parse(localStorage.getItem(STORAGE_USER_KEY) || 'null');
    } catch(e) {
      return null;
    }
  }

  function isAuthenticated() {
    return localStorage.getItem(STORAGE_SESSION_KEY) === 'active' && Boolean(getUser()) && Boolean(localStorage.getItem(STORAGE_TOKEN_KEY));
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
          message: data.message || (data.exists ? 'Account exists' : 'Email available')
        };
      }
    } catch (e) {}

    return {
      exists: false,
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

    try {
      var loginRes = await fetch(getApiEndpoint('/api/auth/login'), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email: email, password: password })
      });

      if (loginRes.status === 200) {
        var data = await loginRes.json();
        var userObj = data.user || {
          id: data.id,
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
      } else {
        var errData = await loginRes.json().catch(function() { return {}; });
        return {
          success: false,
          status: loginRes.status,
          error: {
            message: errData.detail || errData.message || 'Invalid email or password.'
          }
        };
      }
    } catch (netErr) {
      return {
        success: false,
        error: { message: 'Unable to connect to the authentication server. Please try again.' }
      };
    }
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
      } else {
        var errData = await regRes.json().catch(function() { return {}; });
        return {
          success: false,
          status: regRes.status,
          error: { message: errData.detail || errData.message || 'Registration failed.' }
        };
      }
    } catch (netErr) {
      return {
        success: false,
        error: { message: 'Unable to connect to the registration server. Please try again.' }
      };
    }
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
    localStorage.removeItem(STORAGE_USER_KEY);
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
      success: false,
      error: { message: 'Password reset service unavailable.' }
    };
  }

  async function verifySession() {
    var token = localStorage.getItem(STORAGE_TOKEN_KEY);
    if (!token) {
      localStorage.removeItem(STORAGE_SESSION_KEY);
      localStorage.removeItem(STORAGE_TOKEN_KEY);
      localStorage.removeItem(STORAGE_USER_KEY);
      return false;
    }

    try {
      var controller = new AbortController();
      var timeoutId = setTimeout(function() { controller.abort(); }, 60000);

      var res = await fetch(getApiEndpoint('/api/auth/verify'), {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': 'Bearer ' + token
        },
        body: JSON.stringify({ access_token: token }),
        signal: controller.signal
      });
      clearTimeout(timeoutId);

      if (res.status === 200) {
        var data = await res.json();
        if (data && data.valid && data.user) {
          localStorage.setItem(STORAGE_USER_KEY, JSON.stringify(data.user));
          localStorage.setItem(STORAGE_SESSION_KEY, 'active');
          return true;
        }
      }
    } catch (err) {
      console.warn("Server verification error:", err);
    }

    localStorage.removeItem(STORAGE_SESSION_KEY);
    localStorage.removeItem(STORAGE_TOKEN_KEY);
    localStorage.removeItem(STORAGE_USER_KEY);
    return false;
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

  if (typeof document !== 'undefined') {
    if (document.readyState === 'loading') {
      document.addEventListener('DOMContentLoaded', function() { init(); });
    } else {
      init();
    }
  }

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
    getConfig: function() { return { url: state.url, configured: state.configured }; }
  };

})(typeof window !== 'undefined' ? window : this);
