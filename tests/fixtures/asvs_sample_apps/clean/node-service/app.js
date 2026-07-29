// Clean Node service — SSRF-safe webhook handler.
// ASVS V1.3.6 test fixture: strict hostname allowlist validation before
// any outbound HTTP request, plus redirect following disabled.

"use strict";
const express = require("express");
const axios = require("axios");

const app = express();
app.use(express.json());

const ALLOWED_WEBHOOK_HOSTS = new Set(["partner.example.com"]);

function isAllowedWebhook(url) {
  try {
    return ALLOWED_WEBHOOK_HOSTS.has(new URL(url).hostname);
  } catch {
    return false;
  }
}

// V1.3.6 — webhook URL validated against ALLOWED_WEBHOOK_HOSTS; redirects disabled
app.post("/webhook", async (req, res) => {
  const webhook = req.body.webhook;
  if (!isAllowedWebhook(webhook)) {
    return res.status(400).send("blocked");
  }
  const result = await axios.get(webhook /* validated against ALLOWED_WEBHOOK_HOSTS */, { maxRedirects: 0 });
  res.json(result.data);
});

module.exports = app;
