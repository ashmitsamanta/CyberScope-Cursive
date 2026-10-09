# CyberScope Authentication Verification Manual Test Checklist

This checklist documents the manual testing procedures for verifying that CyberScope's server-first authentication model and route protection work correctly.

---

## Prerequisites
1. Start the backend service:
   ```bash
   cd Backend
   python -m uvicorn app.main:app --reload
   ```
2. Serve the frontend (e.g. Vite dev server or standard web server):
   ```bash
   cd Frontend
   npm run dev
   ```

---

## Test Cases

### 1. Private / Incognito Window Initial Access
- **Action**: Open a fresh private / incognito browser window and navigate directly to `http://localhost:5173/fraud-graph.html` (or equivalent host port).
- **Expected Behavior**:
  - The page content remains hidden initially (`cs-pending` loader indicator is visible).
  - Since `cyberscopeAccessToken` is absent from `localStorage`, `cyberscopeProtect()` immediately clears all session storage and executes `location.replace('signin.html?redirect=fraud-graph.html')`.
  - The user lands on the sign-in page (`signin.html`).

---

### 2. Manual `localStorage` Manipulation Bypass Attempt
- **Action**: 
  1. Open DevTools console on `signin.html` or any page.
  2. Manually set local session flags:
     ```js
     localStorage.setItem('cyberscopeSession', 'active');
     localStorage.setItem('cyberscopeUser', JSON.stringify({ email: 'attacker@example.com' }));
     ```
  3. Navigate to `http://localhost:5173/fraud-graph.html` or reload the page.
- **Expected Behavior**:
  - `cyberscopeProtect()` checks for `cyberscopeAccessToken`. If absent, or if an invalid/fake token exists, it calls `POST /api/auth/verify`.
  - Backend `/api/auth/verify` rejects the unauthenticated attempt with `401 Unauthorized`.
  - Frontend auth guard catches the 401 response, purges `cyberscopeSession`, `cyberscopeUser`, and `cyberscopeAccessToken` from `localStorage`, and redirects to `signin.html`.
  - Client-side fake session flags do NOT grant access.

---

### 3. Valid Login & Page Access
- **Action**:
  1. On `signin.html`, register or log in using valid, verified credentials.
  2. Upon successful login, observe successful token storage (`cyberscopeAccessToken`) and automatic redirection to `dashboard.html` or `fraud-graph.html`.
- **Expected Behavior**:
  - `/api/auth/login` returns a valid JWT Bearer token signed with `JWT_SECRET`.
  - Protected pages successfully verify the token with `POST /api/auth/verify` (HTTP 200 `valid: true`).
  - `document.documentElement` removes `cs-pending` class and reveals protected UI content and graphics.
  - Subsequent API data calls attach `Authorization: Bearer <token>` and return live data.

---

### 4. Token Deletion / Explicit Logout
- **Action**:
  1. While viewing `fraud-graph.html` or `dashboard.html`, open DevTools and delete `cyberscopeAccessToken`:
     ```js
     localStorage.removeItem('cyberscopeAccessToken');
     ```
  2. Reload the page or trigger a data request.
- **Expected Behavior**:
  - Page reload immediately triggers `cyberscopeProtect()`, missing token detected, redirecting to `signin.html`.
  - If a fetch request occurs before reload, the global fetch interceptor receives a `401 Unauthorized` response from the backend, clears session keys, and redirects to `signin.html`.

---

### 5. Expired Token Handling
- **Action**:
  1. Manually tamper with `cyberscopeAccessToken` in `localStorage` or wait for token expiration (60 minutes).
  2. Reload `fraud-graph.html` or interact with an authenticated API feature.
- **Expected Behavior**:
  - Backend token verification fails with `401 Unauthorized` (`Signature verification failed` or `Token has expired`).
  - `POST /api/auth/verify` returns 401 with `{"valid": false}`.
  - Client-side auth guard and fetch interceptor clear `localStorage` session keys and redirect to `signin.html`.
