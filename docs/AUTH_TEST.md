# CyberScope Authentication & Sign-In Popup Test Checklist

This document provides a step-by-step manual testing protocol for verifying the CyberScope sign-in popup modal, link interception, redirect sanitization, and session protection.

---

## Manual Test Verification Protocol

### Test Case 1: Landing Page Link Interception (Signed-Out Visitor)
1. Open a new **Private / Incognito Window**.
2. Navigate to `index.html` (e.g. `http://localhost:5173/index.html` or local server).
3. Ensure you are signed out (no `cyberscopeSession` or `cyberscopeAccessToken` in `localStorage`).
4. Click on the **Fraud Graph** module card or nav link (or click the `.graph-area` interactive box).
5. **Expected Result:**
   - The page DOES NOT navigate away.
   - The sign-in modal popup opens immediately over `index.html`.
   - The modal subtitle is context-aware: `"Sign in to open the Fraud Graph"`.
   - Focus is automatically placed in the Email Address input field.

---

### Test Case 2: Successful Sign-In & Target Navigation
1. In the open sign-in modal from Test Case 1, enter valid credentials for a registered account.
2. Click **Sign In →**.
3. **Expected Result:**
   - The submit button displays `"Authenticating..."` and is disabled during the request.
   - On 200 response, a success message appears: `"Sign in successful. Opening your workspace..."`.
   - `localStorage` receives `cyberscopeSession` (`'active'`), `cyberscopeAccessToken`, and `cyberscopeUser`.
   - Browser automatically navigates to the remembered target (`fraud-graph.html`).

---

### Test Case 3: Direct Visit to Protected Page (Signed-Out Visitor)
1. Open a new **Private / Incognito Window**.
2. Type `/fraud-graph.html` (or `http://localhost:5173/fraud-graph.html`) directly into the browser address bar while signed out.
3. **Expected Result:**
   - The page automatically redirects to `index.html?login=1&redirect=fraud-graph.html`.
   - On `index.html` load, the query parameter is stripped using `history.replaceState` (leaving clean `index.html` in address bar).
   - The sign-in modal popup opens automatically with subtitle `"Sign in to open the Fraud Graph"`.

---

### Test Case 4: Token Removal & Page Reload Protection
1. Log into CyberScope and navigate to any protected section (e.g. `dashboard.html` or `cases.html`).
2. Open Browser Developer Tools (`F12` -> Application -> Local Storage).
3. Delete `cyberscopeAccessToken` and `cyberscopeSession`.
4. Refresh the page (`F5` or `Ctrl+R`).
5. **Expected Result:**
   - The application DOES NOT display a blank page or broken UI.
   - Session keys are cleared completely.
   - Browser redirects to `index.html` with the sign-in popup open for the target section.

---

### Test Case 5: Open-Redirect & XSS Vector Resistance
1. In the browser address bar, enter a crafted URL with a malicious redirect target:
   `http://localhost:5173/index.html?login=1&redirect=javascript:alert(1)`
   or
   `http://localhost:5173/index.html?login=1&redirect=https://evil.example`
2. **Expected Result:**
   - The modal target URL is validated against the strict allowlist regex `^[a-z0-9-]+\.html$`.
   - Malicious values fall back safely to `dashboard.html`.
   - Attempting login or completing authentication never executes `javascript:` or navigates to external domains.

---

### Test Case 6: Public Links & Keyboard Accessibility
1. On `index.html` while signed out, click on **Sign In**, **Register**, or anchor links (**About**, **Open Console ↗**).
2. **Expected Result:**
   - Public links navigate directly or smooth scroll to their respective targets without opening the modal.
3. Open the modal popup, press `Tab` repeatedly.
4. **Expected Result:** Focus is trapped strictly inside modal interactive elements.
5. Press `Escape` or click the backdrop overlay / `×` button.
6. **Expected Result:** Modal closes cleanly and body scrolling is restored.
