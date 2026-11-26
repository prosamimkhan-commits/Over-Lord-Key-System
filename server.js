// server.js — OVER LORD Key Server
"use strict";

const express   = require("express");
const crypto    = require("crypto");
const path      = require("path");
const rateLimit = require("express-rate-limit");
const helmet    = require("helmet");

const app = express();

// ── env config ──────────────────────────────────────────────────
const PORT       = process.env.PORT        || 3000;
const KEY_PREFIX = process.env.KEY_PREFIX  || "OVER_LORD";
const MIN_WAIT   = parseInt(process.env.MIN_WAIT_SECONDS || "8", 10);

// ── in-memory stores ─────────────────────────────────────────────
const pendingSessions = new Map(); // sessionId → { type, createdAt }
const issuedKeys      = new Map(); // key       → { type, expiresAt, hwid }

// ── cleanup every 10 min ─────────────────────────────────────────
setInterval(() => {
  const now = Date.now();
  for (const [id, v] of pendingSessions)
    if (now - v.createdAt > 10 * 60 * 1000) pendingSessions.delete(id);
  for (const [key, v] of issuedKeys)
    if (now > v.expiresAt) issuedKeys.delete(key);
}, 10 * 60 * 1000);

// ── middleware ───────────────────────────────────────────────────
app.use(helmet({ contentSecurityPolicy: false, crossOriginEmbedderPolicy: false }));
app.use(express.json({ limit: "10kb" }));
app.use(express.static(path.join(__dirname, "public")));

// ── rate limiters ────────────────────────────────────────────────
const startLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, max: 10,
  standardHeaders: true, legacyHeaders: false,
  message: { ok: false, message: "Too many requests. Try again in 15 minutes." },
});

const generateLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, max: 15,
  standardHeaders: true, legacyHeaders: false,
  message: { ok: false, message: "Too many key claims. Slow down." },
});

const verifyLimiter = rateLimit({
  windowMs: 60 * 1000, max: 30,
  standardHeaders: true, legacyHeaders: false,
  message: { ok: false, message: "Too many verify requests." },
});

// ── helpers ──────────────────────────────────────────────────────
function generateKey() {
  const seg = () => crypto.randomBytes(2).toString("hex").toUpperCase();
  return `${KEY_PREFIX}-${seg()}${seg()}`;
}

function expiryFor(type) {
  return Date.now() + (type === "12h" ? 12 : 24) * 60 * 60 * 1000;
}

function validType(t) {
  return t === "12h" || t === "24h";
}

// ── frontend ─────────────────────────────────────────────────────
app.get("/getkey", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

// ── POST /getkey/api/start ────────────────────────────────────────
// Step 1: user clicks button → server mints a sessionId + timestamp
// Returns { ok, sessionId, waitSeconds }
app.post("/getkey/api/start", startLimiter, (req, res) => {
  const { type } = req.body || {};
  if (!validType(type))
    return res.status(400).json({ ok: false, message: "Invalid type. Use '12h' or '24h'." });

  const sessionId = crypto.randomBytes(16).toString("hex");
  pendingSessions.set(sessionId, { type, createdAt: Date.now(), used: false });

  return res.json({ ok: true, sessionId, waitSeconds: MIN_WAIT });
});

// ── POST /getkey/api/generate ─────────────────────────────────────
// Step 2: after wait → client sends sessionId → server checks elapsed time → issues key
// Returns { ok, key, expiresAt }
app.post("/getkey/api/generate", generateLimiter, (req, res) => {
  const { sessionId } = req.body || {};

  if (!sessionId || typeof sessionId !== "string" || sessionId.length > 64)
    return res.status(400).json({ ok: false, message: "Missing or invalid sessionId." });

  const record = pendingSessions.get(sessionId);
  if (!record)
    return res.status(403).json({ ok: false, message: "Session not found or expired." });

  if (record.used)
    return res.status(403).json({ ok: false, message: "Session already used." });

  const elapsed = (Date.now() - record.createdAt) / 1000;
  if (elapsed < MIN_WAIT)
    return res.status(429).json({
      ok: false,
      message: `Wait at least ${MIN_WAIT} seconds before claiming your key.`,
      remainingSeconds: Math.ceil(MIN_WAIT - elapsed),
    });

  // mark used + cleanup
  record.used = true;
  setTimeout(() => pendingSessions.delete(sessionId), 5000);

  const key       = generateKey();
  const expiresAt = expiryFor(record.type);
  issuedKeys.set(key, { type: record.type, expiresAt, hwid: null });

  return res.json({ ok: true, key, expiresAt: new Date(expiresAt).toISOString() });
});

// ── POST /getkey/api/verify ───────────────────────────────────────
// Lua/app calls this. Payload: { key, hwid }
app.post("/getkey/api/verify", verifyLimiter, (req, res) => {
  const { key, hwid } = req.body || {};

  if (!key || typeof key !== "string")
    return res.status(400).json({ ok: false, valid: false, reason: "Missing key." });

  const record = issuedKeys.get(key);
  if (!record)
    return res.json({ ok: true, valid: false, reason: "Key not found or expired." });

  if (Date.now() > record.expiresAt) {
    issuedKeys.delete(key);
    return res.json({ ok: true, valid: false, reason: "Key expired." });
  }

  if (hwid && typeof hwid === "string" && hwid.length <= 128) {
    if (!record.hwid) {
      record.hwid = hwid;
    } else if (record.hwid !== hwid) {
      return res.json({ ok: true, valid: false, reason: "Key is bound to a different device." });
    }
  }

  return res.json({
    ok:        true,
    valid:     true,
    type:      record.type,
    expiresAt: new Date(record.expiresAt).toISOString(),
    hwid:      record.hwid || null,
  });
});

// ── health ────────────────────────────────────────────────────────
app.get("/health", (req, res) => res.json({ status: "ok", uptime: process.uptime() }));

// ── 404 ───────────────────────────────────────────────────────────
app.use((req, res) => res.status(404).json({ ok: false, message: "Not found." }));

// ── start ─────────────────────────────────────────────────────────
app.listen(PORT, () => console.log(`[OVER_LORD] Key server running on port ${PORT}`));
