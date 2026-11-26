// server.js — OVER LORD Key Server
// Node.js + Express | Production-ready

"use strict";

const express      = require("express");
const crypto       = require("crypto");
const path         = require("path");
const rateLimit    = require("express-rate-limit");
const helmet       = require("helmet");

const app = express();

// ── env config ─────────────────────────────────────────────────
const PORT              = process.env.PORT              || 3000;
const HMAC_SECRET       = process.env.HMAC_SECRET       || "CHANGE_ME_IN_PRODUCTION_NOW";
const KEY_PREFIX        = process.env.KEY_PREFIX        || "OVER_LORD";
const MIN_TASK_SECONDS  = parseInt(process.env.MIN_TASK_SECONDS || "8", 10);

// ── in-memory store ─────────────────────────────────────────────
// Railway restarts wipe this — fine for a key server of this scale.
// For persistence across restarts: swap with a SQLite / Redis adapter.
const pendingTokens = new Map(); // token → { type, createdAt, used }
const issuedKeys    = new Map(); // key   → { type, expiresAt, hwid }

// ── clean up expired entries every 10 min ───────────────────────
setInterval(() => {
  const now = Date.now();
  for (const [tok, v] of pendingTokens) {
    // pending tokens expire after 30 min
    if (now - v.createdAt > 30 * 60 * 1000) pendingTokens.delete(tok);
  }
  for (const [key, v] of issuedKeys) {
    if (now > v.expiresAt) issuedKeys.delete(key);
  }
}, 10 * 60 * 1000);

// ── security headers ────────────────────────────────────────────
app.use(
  helmet({
    contentSecurityPolicy: false,
    crossOriginEmbedderPolicy: false,
  })
);

app.use(express.json({ limit: "10kb" }));
app.use(express.static(path.join(__dirname, "public")));

// ── rate limiters ───────────────────────────────────────────────
const startLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 min window
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  message: { ok: false, message: "Too many requests. Try again in 15 minutes." },
});

const keyLimiter = rateLimit({
  windowMs: 5 * 60 * 1000,  // 5 min window
  max: 15,
  standardHeaders: true,
  legacyHeaders: false,
  message: { ok: false, message: "Too many key claims. Slow down." },
});

const verifyLimiter = rateLimit({
  windowMs: 60 * 1000,       // 1 min window
  max: 30,
  standardHeaders: true,
  legacyHeaders: false,
  message: { ok: false, message: "Too many verify requests." },
});

// ── helpers ─────────────────────────────────────────────────────

/** Cryptographically secure random hex string */
function secureRandom(bytes = 16) {
  return crypto.randomBytes(bytes).toString("hex");
}

/** HMAC-SHA256 of payload using HMAC_SECRET */
function makeHmac(payload) {
  return crypto
    .createHmac("sha256", HMAC_SECRET)
    .update(payload)
    .digest("hex");
}

/**
 * Build a signed token string.
 * Format: <random_id>.<timestamp>.<hmac>
 */
function buildSignedToken(id, timestamp) {
  const payload = `${id}.${timestamp}`;
  const sig     = makeHmac(payload);
  return `${payload}.${sig}`;
}

/**
 * Verify a signed token. Returns { id, timestamp } or throws.
 */
function verifySignedToken(token) {
  const parts = token.split(".");
  if (parts.length !== 3) throw new Error("Malformed token");
  const [id, ts, sig] = parts;
  const expected = makeHmac(`${id}.${ts}`);
  // Constant-time comparison to prevent timing attacks
  if (!crypto.timingSafeEqual(Buffer.from(sig, "hex"), Buffer.from(expected, "hex"))) {
    throw new Error("Invalid signature");
  }
  return { id, timestamp: parseInt(ts, 10) };
}

/** Generate a unique key string */
function generateKey() {
  const segment = () => crypto.randomBytes(2).toString("hex").toUpperCase();
  return `${KEY_PREFIX}-${segment()}${segment()}`;
  // e.g. OVER_LORD-A1B2C3D4
}

/** Return expiry timestamp in ms for given type */
function expiryFor(type) {
  const hours = type === "12h" ? 12 : 24;
  return Date.now() + hours * 60 * 60 * 1000;
}

/** Validate type field */
function validType(t) {
  return t === "12h" || t === "24h";
}

// ── Serve frontend at /getkey ────────────────────────────────────
app.get("/getkey", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

// ── POST /getkey/api/start ───────────────────────────────────────
// Frontend calls this first. Returns { ok, link, token }
app.post("/getkey/api/start", startLimiter, (req, res) => {
  const { type } = req.body || {};

  if (!validType(type)) {
    return res.status(400).json({ ok: false, message: "Invalid type. Use '12h' or '24h'." });
  }

  // Server mints the timestamp — never trust the client
  const id        = secureRandom(12);         // 24-char hex id
  const timestamp = Date.now();
  const token     = buildSignedToken(id, timestamp);

  // Store pending state
  pendingTokens.set(token, { type, createdAt: timestamp, used: false });

  // Return URL — user comes back here after completing the step
  const returnUrl = `${process.env.BASE_URL || `http://localhost:${PORT}`}/getkey?token=${encodeURIComponent(token)}`;

  return res.json({ ok: true, link: returnUrl, token });
});

// ── POST /getkey/api/key ─────────────────────────────────────────
// Called when user returns from earn task with a token.
// Returns { ok, key, expiresAt }
app.post("/getkey/api/key", keyLimiter, (req, res) => {
  const { token, type } = req.body || {};

  if (!token || typeof token !== "string" || token.length > 200) {
    return res.status(400).json({ ok: false, message: "Missing or invalid token." });
  }

  // 1. Verify HMAC signature
  let parsed;
  try {
    parsed = verifySignedToken(token);
  } catch {
    return res.status(403).json({ ok: false, message: "Token signature invalid." });
  }

  // 2. Look up pending record
  const record = pendingTokens.get(token);
  if (!record) {
    return res.status(403).json({ ok: false, message: "Token not found or already expired." });
  }

  // 3. Check one-time use (strict anti-reuse)
  if (record.used) {
    return res.status(403).json({ ok: false, message: "Token already used." });
  }

  // 4. Minimum task wait time (bot bypass protection)
  const elapsed = (Date.now() - record.createdAt) / 1000;
  if (elapsed < MIN_TASK_SECONDS) {
    return res.status(429).json({
      ok: false,
      message: `Complete the earn task first. Wait at least ${MIN_TASK_SECONDS}s.`,
    });
  }

  // 5. Token age guard (30-minute max window)
  if (Date.now() - record.createdAt > 30 * 60 * 1000) {
    pendingTokens.delete(token);
    return res.status(403).json({ ok: false, message: "Token expired. Please start over." });
  }

  // 6. Determine type (trust server record over client)
  const resolvedType = validType(record.type) ? record.type : (validType(type) ? type : "24h");

  // 7. Issue key
  const key       = generateKey();
  const expiresAt = expiryFor(resolvedType);

  issuedKeys.set(key, { type: resolvedType, expiresAt, hwid: null });

  // Mark token as used (then clean up after short delay)
  record.used = true;
  setTimeout(() => pendingTokens.delete(token), 5000);

  return res.json({ ok: true, key, expiresAt: new Date(expiresAt).toISOString() });
});

// ── POST /getkey/api/verify ──────────────────────────────────────
// Your Lua/app calls this. Payload: { key, hwid }
// Returns { ok, valid, reason?, expiresAt?, hwid? }
app.post("/getkey/api/verify", verifyLimiter, (req, res) => {
  const { key, hwid } = req.body || {};

  if (!key || typeof key !== "string") {
    return res.status(400).json({ ok: false, valid: false, reason: "Missing key." });
  }

  const record = issuedKeys.get(key);

  // Key not found
  if (!record) {
    return res.json({ ok: true, valid: false, reason: "Key not found or expired." });
  }

  // Key expired
  if (Date.now() > record.expiresAt) {
    issuedKeys.delete(key);
    return res.json({ ok: true, valid: false, reason: "Key expired." });
  }

  // HWID binding
  if (hwid && typeof hwid === "string" && hwid.length <= 128) {
    if (!record.hwid) {
      // First login — bind the device
      record.hwid = hwid;
    } else if (record.hwid !== hwid) {
      // Different device — reject
      return res.json({
        ok: true,
        valid: false,
        reason: "Key is bound to a different device.",
      });
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

// ── health check ─────────────────────────────────────────────────
app.get("/health", (req, res) => {
  res.json({ status: "ok", uptime: process.uptime() });
});

// ── 404 fallback ─────────────────────────────────────────────────
app.use((req, res) => {
  res.status(404).json({ ok: false, message: "Not found." });
});

// ── start ─────────────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`[OVER_LORD] Key server running on port ${PORT}`);
if (HMAC_SECRET === "CHANGE_ME_IN_PRODUCTION_NOW") {
  console.warn("[WARNING] HMAC_SECRET is default! ...");
  }
});
