// Deliberately vulnerable frontend fixture — ASVS 5.0.0 L1 test cases.

function renderComment(comment) {
  // V3.2.2 / V1.3.1 — unsafe DOM rendering, no sanitizer
  document.getElementById("comments").innerHTML = comment;
}

function connectRealtime() {
  // V4.4.1 — unencrypted WebSocket
  const ws = new WebSocket("ws://realtime.example.com/socket");
  return ws;
}

function csrfExemptFetch(url, body) {
  // no anti-forgery token attached to a state-changing request
  return fetch(url, { method: "POST", body });
}

function renderLoginForm() {
  // V6.2.6 — password field not masked (type=text instead of type=password)
  // V2.2.2 — client-side-only validation (pattern attribute, no server-side check shown)
  return `
    <form>
      <input id="password" name="password" type="text" pattern=".{4,}" />
    </form>
  `;
}

function renderChangePasswordForm() {
  // V6.2.7 — password manager / paste blocked via autocomplete=off
  return `
    <form>
      <input type="password" name="new_password" autocomplete="off" />
    </form>
  `;
}
