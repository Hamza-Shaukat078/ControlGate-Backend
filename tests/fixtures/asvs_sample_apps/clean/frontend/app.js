// Clean counterpart of ../vulnerable/frontend/app.js — every issue fixed.

function renderComment(comment) {
  // V3.2.2 / V1.3.1 — safe text rendering, no HTML interpretation
  document.getElementById("comments").textContent = comment;
}

function connectRealtime() {
  // V4.4.1 — encrypted WebSocket
  const ws = new WebSocket("wss://realtime.example.com/socket");
  return ws;
}

function csrfProtectedFetch(url, body, csrfToken) {
  // Anti-forgery token attached to the state-changing request
  return fetch(url, {
    method: "POST",
    headers: { "X-CSRF-Token": csrfToken },
    body,
  });
}

function renderLoginForm() {
  // V6.2.6 — password field masked
  return `
    <form>
      <input id="password" name="password" type="password" />
    </form>
  `;
}

function renderChangePasswordForm() {
  // V6.2.7 — paste and password managers permitted (no autocomplete=off)
  return `
    <form>
      <input type="password" name="new_password" autocomplete="new-password" />
    </form>
  `;
}

function logout() {
  // V14.3.1 — client storage cleared on logout
  localStorage.removeItem("token");
  localStorage.removeItem("user");
}
