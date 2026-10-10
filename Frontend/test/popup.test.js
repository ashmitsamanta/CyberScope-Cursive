import { test, describe } from 'node:test';
import assert from 'node:assert';
import { JSDOM } from 'jsdom';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const indexPath = path.resolve(__dirname, '../index.html');
const indexHtmlContent = fs.readFileSync(indexPath, 'utf8');

function createDom(url = 'http://localhost/index.html') {
  const dom = new JSDOM(indexHtmlContent, {
    url,
    runScripts: 'dangerously',
    beforeParse(window) {
      // Stub IntersectionObserver
      window.IntersectionObserver = class {
        constructor() {}
        observe() {}
        unobserve() {}
        disconnect() {}
      };

      // Stub matchMedia
      window.matchMedia = window.matchMedia || function() {
        return {
          matches: false,
          addListener: function() {},
          removeListener: function() {},
          addEventListener: function() {},
          removeEventListener: function() {},
          dispatchEvent: function() {}
        };
      };
    }
  });

  return dom;
}

describe('Sign-In Popup (Modal) Tests', () => {
  test('Protected links and .graph-area open popup when signed out', () => {
    const dom = createDom();
    const { window } = dom;
    const { document } = window;
    window.localStorage.clear();

    const protectedSelectors = [
      'a[href="dashboard.html"]',
      'a[href="cases.html"]',
      'a[href="fraud-graph.html"]',
      'a[href="threat-map.html"]',
      'a[href="entity-explorer.html"]',
      'a[href="transaction-explorer.html"]',
      'a[href="campaign-explorer.html"]',
      'a[href="investigation-workspace.html"]',
      'a[href="chatbot.html"]',
      '.graph-area'
    ];

    const modal = document.getElementById('csAuthModal');

    protectedSelectors.forEach(selector => {
      const el = document.querySelector(selector);
      assert.ok(el, `Element for ${selector} should exist in index.html`);
      
      modal.classList.remove('active');

      const event = new window.MouseEvent('click', { bubbles: true, cancelable: true });
      el.dispatchEvent(event);

      assert.ok(modal.classList.contains('active'), `Popup should open when clicking ${selector}`);
      assert.ok(event.defaultPrevented, `Click on ${selector} should be preventDefaulted`);
    });
  });

  test('Public links are not intercepted', () => {
    const dom = createDom();
    const { window } = dom;
    const { document } = window;
    window.localStorage.clear();

    const modal = document.getElementById('csAuthModal');
    const publicSelectors = ['a[href="signin.html"]', 'a[href="register.html"]', 'a[href="#about"]'];

    publicSelectors.forEach(selector => {
      const el = document.querySelector(selector);
      if (!el) return;

      modal.classList.remove('active');
      const event = new window.MouseEvent('click', { bubbles: true, cancelable: true });
      el.dispatchEvent(event);

      assert.strictEqual(modal.classList.contains('active'), false, `Public link ${selector} should not open modal`);
    });
  });

  test('Signed-in users pass through without modal', () => {
    const dom = createDom();
    const { window } = dom;
    const { document } = window;
    window.localStorage.setItem('cyberscopeSession', 'active');
    window.localStorage.setItem('cyberscopeAccessToken', 'valid-token');

    const modal = document.getElementById('csAuthModal');
    const el = document.querySelector('a[href="fraud-graph.html"]');

    const event = new window.MouseEvent('click', { bubbles: true, cancelable: true });
    el.dispatchEvent(event);

    assert.strictEqual(modal.classList.contains('active'), false, 'Signed-in user should not trigger modal');
  });

  test('Esc key closes the popup', () => {
    const dom = createDom();
    const { window } = dom;
    const { document } = window;
    window.localStorage.clear();

    const modal = document.getElementById('csAuthModal');
    const el = document.querySelector('a[href="fraud-graph.html"]');
    el.dispatchEvent(new window.MouseEvent('click', { bubbles: true, cancelable: true }));
    assert.ok(modal.classList.contains('active'));

    document.dispatchEvent(new window.KeyboardEvent('keydown', { key: 'Escape', bubbles: true }));
    assert.strictEqual(modal.classList.contains('active'), false, 'Esc should close modal');
  });

  test('Empty form submission shows message and makes no request', async () => {
    const dom = createDom();
    const { window } = dom;
    const { document } = window;
    window.localStorage.clear();

    let fetchCalled = false;
    window.fetch = async () => {
      fetchCalled = true;
      return { status: 200, json: async () => ({}) };
    };

    const el = document.querySelector('a[href="fraud-graph.html"]');
    el.dispatchEvent(new window.MouseEvent('click', { bubbles: true, cancelable: true }));

    const form = document.getElementById('csAuthForm');
    form.dispatchEvent(new window.Event('submit', { bubbles: true, cancelable: true }));

    assert.strictEqual(fetchCalled, false, 'No fetch request should be made for empty inputs');
    const msg = document.getElementById('csMessage');
    assert.strictEqual(msg.textContent, 'Please enter your email and password.');
  });

  test('401 error shows message and stores no session', async () => {
    const dom = createDom();
    const { window } = dom;
    const { document } = window;
    window.localStorage.clear();

    window.fetch = async () => {
      return {
        status: 401,
        json: async () => ({ detail: 'Invalid credentials' })
      };
    };

    const el = document.querySelector('a[href="fraud-graph.html"]');
    el.dispatchEvent(new window.MouseEvent('click', { bubbles: true, cancelable: true }));

    document.getElementById('csEmail').value = 'wrong@example.com';
    document.getElementById('csPassword').value = 'badpass';

    const form = document.getElementById('csAuthForm');
    form.dispatchEvent(new window.Event('submit', { bubbles: true, cancelable: true }));

    await new Promise(r => setTimeout(r, 50));

    const msg = document.getElementById('csMessage');
    assert.strictEqual(msg.textContent, 'Invalid credentials');
    assert.strictEqual(window.localStorage.getItem('cyberscopeSession'), null);
    assert.strictEqual(window.localStorage.getItem('cyberscopeAccessToken'), null);
  });

  test('429 error shows rate limit message', async () => {
    const dom = createDom();
    const { window } = dom;
    const { document } = window;
    window.localStorage.clear();

    window.fetch = async () => {
      return { status: 429, json: async () => ({}) };
    };

    const el = document.querySelector('a[href="fraud-graph.html"]');
    el.dispatchEvent(new window.MouseEvent('click', { bubbles: true, cancelable: true }));

    document.getElementById('csEmail').value = 'user@example.com';
    document.getElementById('csPassword').value = 'secret';

    const form = document.getElementById('csAuthForm');
    form.dispatchEvent(new window.Event('submit', { bubbles: true, cancelable: true }));

    await new Promise(r => setTimeout(r, 50));

    const msg = document.getElementById('csMessage');
    assert.strictEqual(msg.textContent, 'Too many attempts, wait a minute');
  });

  test('Network error shows unreachable server message', async () => {
    const dom = createDom();
    const { window } = dom;
    const { document } = window;
    window.localStorage.clear();

    window.fetch = async () => {
      throw new Error('Network error');
    };

    const el = document.querySelector('a[href="fraud-graph.html"]');
    el.dispatchEvent(new window.MouseEvent('click', { bubbles: true, cancelable: true }));

    document.getElementById('csEmail').value = 'user@example.com';
    document.getElementById('csPassword').value = 'secret';

    const form = document.getElementById('csAuthForm');
    form.dispatchEvent(new window.Event('submit', { bubbles: true, cancelable: true }));

    await new Promise(r => setTimeout(r, 50));

    const msg = document.getElementById('csMessage');
    assert.strictEqual(msg.textContent, 'Cannot reach the server. If it was idle, wait a minute and try again.');
  });

  test('Successful login stores session keys and navigates', async () => {
    const dom = createDom();
    const { window } = dom;
    const { document } = window;
    window.localStorage.clear();

    window.fetch = async () => {
      return {
        status: 200,
        json: async () => ({
          access_token: 'my-token',
          user: { id: 42, email: 'investigator@cyberscope.io' }
        })
      };
    };

    const el = document.querySelector('a[href="fraud-graph.html"]');
    el.dispatchEvent(new window.MouseEvent('click', { bubbles: true, cancelable: true }));

    document.getElementById('csEmail').value = 'investigator@cyberscope.io';
    document.getElementById('csPassword').value = 'password123';

    const form = document.getElementById('csAuthForm');
    form.dispatchEvent(new window.Event('submit', { bubbles: true, cancelable: true }));

    await new Promise(r => setTimeout(r, 50));

    assert.strictEqual(window.localStorage.getItem('cyberscopeSession'), 'active');
    assert.strictEqual(window.localStorage.getItem('cyberscopeAccessToken'), 'my-token');
    assert.ok(window.localStorage.getItem('cyberscopeUser').includes('investigator@cyberscope.io'));
  });

  test('Direct visit with ?login=1&redirect=fraud-graph.html opens popup', () => {
    const dom = createDom('http://localhost/index.html?login=1&redirect=fraud-graph.html');
    const { window } = dom;
    const { document } = window;

    const modal = document.getElementById('csAuthModal');
    const sub = document.getElementById('csAuthSub');

    assert.ok(modal.classList.contains('active'), 'Modal should open on login=1 query parameter');
    assert.strictEqual(sub.textContent, 'Sign in to open the Fraud Graph');
  });

  test('Open-redirect vector targets fall back safely to dashboard.html', () => {
    const domJs = createDom('http://localhost/index.html?login=1&redirect=javascript:alert(1)');
    const modalJs = domJs.window.document.getElementById('csAuthModal');
    assert.ok(modalJs.classList.contains('active'));

    const domEvil = createDom('http://localhost/index.html?login=1&redirect=https://evil.example');
    const modalEvil = domEvil.window.document.getElementById('csAuthModal');
    assert.ok(modalEvil.classList.contains('active'));
  });
});
