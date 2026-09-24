// _protect v4 — shared lib for /api/raw, /api/payload, /api/verify
// v4 adds: PoW hashcash (anti mass-dump/AI), RC4-drop512 (anti bias),
// query-order + duplicate-key check, HWID entropy tiers, KV replay cross-instance,
// trap logging to Discord, LUA via ENV (repo holds no source), stricter fingerprinting.

const crypto = require("crypto");

const SCRIPT_ID = "sodiumhub_main";

function envStr(name) {
  return (process.env[name] || "").toString().trim();
}
function getLoaderSecret() {
  const s = envStr("LOADER_SECRET");
  if (s.length < 32) return null;
  return s;
}
function getTurnstile() {
  const site = envStr("TURNSTILE_SITE");
  const secret = envStr("TURNSTILE_SECRET");
  if (!site || !secret) return null;
  return { site, secret };
}
function getPowDifficulty() {
  const n = parseInt(envStr("POW_DIFFICULTY") || "2", 10);
  if (n >= 1 && n <= 3) return n;
  return 2;
}
function getEnvLua() {
  const b = envStr("LUA_B64").replace(/\s+/g, "");
  if (b.length < 20) return null;
  try {
    const s = Buffer.from(b, "base64").toString("utf8");
    if (s.length >= 5 && s.length < 500000) return s;
  } catch (e) {}
  return null;
}
const ALLOWED_PLACES = envStr("ALLOWED_PLACES");
const FAKE_HOST = envStr("FAKE_HOST");
const DISCORD_WEBHOOK = envStr("DISCORD_WEBHOOK");

const TICKET_TTL = 120;
const RC4_DROP = 512;
const usedTickets = new Map();
const ipHits = new Map();
const ipBurst = new Map();
const hwidStats = new Map();
const ipNewHwids = new Map();
const ipHostCache = new Map();
const verifyPosts = new Map();

const HWID_DAILY_LIMIT = 25;
const HWID_DAILY_LIMIT_SUS = 5;
const IP_NEW_HWID_PER_HOUR = 8;
const IP_NEW_HWID_PER_HOUR_SUS = 3;
const VERIFY_POST_PER_HOUR = 10;

// ---------- crypto ----------
function sha256Hex(s) {
  return crypto.createHash("sha256").update(s, "utf8").digest("hex");
}
function hmacHex(key, msg) {
  return crypto.createHmac("sha256", key).update(msg, "utf8").digest("hex");
}
// djb2 -> 8-char hex. Chose djb2 over FNV so Node<->Lua match 100%
// (intermediates stay below 2^53, so Lua doubles lose no precision).
function proofHash(str) {
  let h = 5381 >>> 0;
  for (let i = 0; i < str.length; i++) {
    h = ((Math.imul(h, 33) + str.charCodeAt(i)) >>> 0);
  }
  return h.toString(16).padStart(8, "0");
}
function powVerify(ticket, hwid, place, nonce, diff) {
  if (typeof nonce !== "string") return false;
  if (!/^[A-Za-z0-9]{1,16}$/.test(nonce)) return false;
  const d = diff || getPowDifficulty();
  // nonce goes FIRST so djb2 diffuses it (a trailing nonce only flips low bits
  // and the PoW would never complete).
  const h = proofHash(`${nonce}|${ticket}|${hwid}|${place}`);
  return h.startsWith("0".repeat(d));
}
function randHex(n) {
  return crypto.randomBytes(n).toString("hex");
}
// RC4-drop: discard the first N keystream bytes (kills plain-RC4
// Fluhrer-Mantin-Shamir biases).
function rc4Crypt(dataBuf, keyBuf, drop) {
  const S = new Array(256);
  for (let i = 0; i < 256; i++) S[i] = i;
  let j = 0;
  const kl = keyBuf.length || 1;
  for (let i = 0; i < 256; i++) {
    j = (j + S[i] + keyBuf[i % kl]) & 255;
    const t = S[i]; S[i] = S[j]; S[j] = t;
  }
  let i = 0; j = 0;
  const skip = drop == null ? 0 : drop;
  for (let n = 0; n < skip; n++) {
    i = (i + 1) & 255;
    j = (j + S[i]) & 255;
    const t = S[i]; S[i] = S[j]; S[j] = t;
  }
  const out = Buffer.alloc(dataBuf.length);
  for (let n = 0; n < dataBuf.length; n++) {
    i = (i + 1) & 255;
    j = (j + S[i]) & 255;
    const t = S[i]; S[i] = S[j]; S[j] = t;
    const K = S[(S[i] + S[j]) & 255];
    out[n] = dataBuf[n] ^ K;
  }
  return out;
}

// ---------- identity ----------
function getIp(req) {
  try {
    const h = (req && req.headers) || {};
    const real = (h["x-real-ip"] || "").toString().split(",")[0].trim();
    if (real && real !== "unknown") return real;
    const fwd = (h["x-forwarded-for"] || "").toString().split(",")[0].trim();
    if (fwd) return fwd;
    const v = (h["x-vercel-forwarded-for"] || "").toString().split(",")[0].trim();
    if (v) return v;
  } catch (e) {}
  return "unknown";
}
function getHost(req) {
  try {
    const h = (req.headers && (req.headers["x-forwarded-host"] || req.headers.host)) || "localhost";
    let host = h.toString().split(",")[0].trim().toLowerCase();
    host = host.replace(/[\r\n\s"'<>\\]+/g, "");
    if (!/^[a-z0-9.-]+(:\d{1,5})?$/.test(host) || host.length > 253) return "localhost";
    return host;
  } catch (e) { return "localhost"; }
}
function isPrivateIP(ip) {
  return /^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|127\.|::1|fc00:|fe80:)/i.test(ip || "");
}

const CURL_RE = /(curl|wget|python|go-http|axios|node-fetch|undici|got\/|httpclient|okhttp|java\/|libcurl|aiohttp|scrapy|powershell|invoke-webrequest|httpie|aria2|postman|insomnia|faraday|ruby|perl|php\/|lua\/|luasocket|http\.request|xmlhttp|fetch\/)/i;
const AI_RE = /(gptbot|chatgpt-user|claudebot|claude-web|anthropic|cohere|bytespider|ccbot|diffbot|omgili|youbot|perplexity|google-extended|applebot|applebot-extended|amazonbot|bingbot|mj12bot|ahrefs|semrush|dotbot|petalbot|oai-searchbot)/i;

function getUA(req) {
  try { return ((req.headers && req.headers["user-agent"]) || "").toString(); }
  catch (e) { return ""; }
}
function isBotUA(req) {
  const ua = getUA(req).toLowerCase();
  if (!ua) return true;
  if (ua.length > 512) return true;
  return CURL_RE.test(ua) || AI_RE.test(ua);
}
function hasBrowserHeaders(req) {
  try {
    const h = req.headers || {};
    return !!(
      h["sec-fetch-site"] || h["sec-fetch-mode"] || h["sec-fetch-dest"] ||
      h["sec-ch-ua"] || h["sec-ch-ua-mobile"] || h["sec-ch-ua-platform"]
    );
  } catch (e) { return false; }
}
function isTrustedExecutor(req) {
  try {
    const h = req.headers || {};
    const ua = (h["user-agent"] || "").toString();
    if (!ua.toLowerCase().includes("roblox")) return false;
    if (/(mozilla|chrome|safari|firefox|edg\/|opr\/|trident|applewebkit)/i.test(ua)) return false;
    if (hasBrowserHeaders(req)) return false;
    if (CURL_RE.test(ua) || AI_RE.test(ua)) return false;
    if (((h.cookie || "").toString().length) > 0) return false;
    if (((h.referer || h.referrer || "").toString())) return false;
    if (((h.origin || "").toString())) return false;
    const al = ((h["accept-language"] || "").toString());
    if (al) return false; // executors never send accept-language
    const acc = ((h.accept || "").toString().toLowerCase());
    if (acc.includes("text/html")) return false; // browser spoof
    return true;
  } catch (e) { return false; }
}
function isBrowser(req) {
  const ua = getUA(req).toLowerCase();
  return ua.includes("mozilla") && !ua.includes("roblox");
}
// Query must arrive in exact order with no duplicate keys (anti smuggle/reorder tools).
function checkQueryOrder(req, expected) {
  try {
    const url = (req.url || "").toString();
    const qi = url.indexOf("?");
    if (qi < 0) return expected.length === 0;
    const qs = url.slice(qi + 1).split("#")[0];
    if (!qs) return expected.length === 0;
    const keys = qs.split("&").filter(Boolean).map((p) => {
      const k = p.split("=")[0] || "";
      try { return decodeURIComponent(k); } catch (e) { return k; }
    });
    const seen = new Set();
    for (const k of keys) {
      if (seen.has(k)) return false; // duplicate -> smuggle
      seen.add(k);
    }
    if (keys.length < expected.length) return false;
    for (let i = 0; i < expected.length; i++) {
      if (keys[i] !== expected[i]) return false;
    }
    return true;
  } catch (e) { return false; }
}

async function isDatacenterIP(ip) {
  if (!ip || ip === "unknown" || isPrivateIP(ip)) return false;
  const now = Date.now();
  const c = ipHostCache.get(ip);
  if (c && c.exp > now) return c.hosting;
  try {
    const ctl = new AbortController();
    const timer = setTimeout(() => { try { ctl.abort(); } catch (e) {} }, 2000);
    const r = await fetch(`https://ip-api.com/json/${encodeURIComponent(ip)}?fields=status,hosting,proxy,query`, {
      signal: ctl.signal,
      headers: { "User-Agent": "sodiumhub-v4/1.0" },
    });
    clearTimeout(timer);
    const j = await r.json();
    const hosting = !!(
      j && j.status === "success" && (j.hosting || j.proxy)
    );
    ipHostCache.set(ip, { hosting, exp: now + 6 * 3600000 });
    if (ipHostCache.size > 5000) {
      for (const [k, v] of ipHostCache) {
        if (v.exp < now) ipHostCache.delete(k);
        if (ipHostCache.size <= 4000) break;
      }
    }
    return hosting;
  } catch (e) { return false; }
}

// ---------- rate limit ----------
function rateLimited(req) {
  const ip = getIp(req);
  const now = Date.now();
  const arr = (ipHits.get(ip) || []).filter((t) => now - t < 60000);
  arr.push(now);
  ipHits.set(ip, arr);
  if (arr.length > 20) return true;
  const b = (ipBurst.get(ip) || []).filter((t) => now - t < 10000);
  b.push(now);
  ipBurst.set(ip, b);
  if (b.length > 6) return true;
  if (ipHits.size > 20000) ipHits.clear();
  if (ipBurst.size > 20000) ipBurst.clear();
  return false;
}
function verifyPostLimited(req) {
  const ip = getIp(req);
  const now = Date.now();
  const arr = (verifyPosts.get(ip) || []).filter((t) => now - t < 3600000);
  if (arr.length >= VERIFY_POST_PER_HOUR) return true;
  arr.push(now);
  verifyPosts.set(ip, arr);
  return false;
}
function todayStr() {
  return new Date().toISOString().slice(0, 10);
}
const SUS_HWIDS = new Set(["test", "test123", "123", "1234", "12345", "unknown", "null", "nil", "none", "admin", "executor", "roblox", "owner", "abc", "aaa", "xxx", "hwid"]);
function isSuspiciousHwid(hwid) {
  const h = (hwid || "").toString();
  if (h.length < 6) return true;
  if (SUS_HWIDS.has(h.toLowerCase())) return true;
  if (/^(.)\1+$/.test(h)) return true; // single repeated char
  const uniq = new Set(h.toLowerCase().split("")).size;
  if (uniq < 3) return true;
  return false;
}
function checkHwidThrottle(hwid, ip) {
  const sus = isSuspiciousHwid(hwid);
  const daily = sus ? HWID_DAILY_LIMIT_SUS : HWID_DAILY_LIMIT;
  const perHour = sus ? IP_NEW_HWID_PER_HOUR_SUS : IP_NEW_HWID_PER_HOUR;
  const now = Date.now();
  const day = todayStr();
  let st = hwidStats.get(hwid);
  if (!st) {
    const arr = (ipNewHwids.get(ip) || []).filter((t) => now - t < 3600000);
    if (arr.length >= perHour) return false;
    arr.push(now);
    ipNewHwids.set(ip, arr);
    st = { day, count: 0, firstSeen: now };
    hwidStats.set(hwid, st);
  }
  if (st.day !== day) { st.day = day; st.count = 0; }
  st.count += 1;
  if (st.count > daily) return false;
  if (hwidStats.size > 20000) {
    for (const [k, v] of hwidStats) {
      if (now - v.firstSeen > 86400000) hwidStats.delete(k);
      if (hwidStats.size <= 15000) break;
    }
  }
  return true;
}

// ---------- KV cross-instance (Upstash Redis, optional) ----------
function kvCfg() {
  const url = envStr("UPSTASH_REDIS_REST_URL").replace(/\/$/, "");
  const token = envStr("UPSTASH_REDIS_REST_TOKEN");
  if (!url || !token) return null;
  return { url, token };
}
// true = fresh (set succeeded), false = replay. No KV / error -> true
// (fail-open; in-memory map still blocks per-instance).
async function kvCheckAndSetTicket(ticket) {
  const cfg = kvCfg();
  if (!cfg) return true;
  try {
    const ctl = new AbortController();
    const timer = setTimeout(() => { try { ctl.abort(); } catch (e) {} }, 1500);
    const r = await fetch(`${cfg.url}/set/${encodeURIComponent("sod:t:" + ticket)}/1?NX=true&EX=${TICKET_TTL + 10}`, {
      headers: { Authorization: `Bearer ${cfg.token}` },
      signal: ctl.signal,
    });
    clearTimeout(timer);
    const j = await r.json().catch(() => null);
    const ok = !!(j && (j.result === "OK"));
    return ok;
  } catch (e) { return true; }
}

// ---------- trap log (fire-and-forget) ----------
function logTrap(ip, ua, reason, extra) {
  try {
    if (!DISCORD_WEBHOOK) return;
    const body = JSON.stringify({
      content: `🪤 trap v4 | ip=\`${String(ip).slice(0, 64)}\` | ${reason} | ua=\`${String(ua).slice(0, 120)}\`${extra ? " | " + String(extra).slice(0, 200) : ""}`,
    });
    const ctl = new AbortController();
    const timer = setTimeout(() => { try { ctl.abort(); } catch (e) {} }, 1500);
    fetch(DISCORD_WEBHOOK, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body,
      signal: ctl.signal,
    }).then(() => clearTimeout(timer)).catch(() => clearTimeout(timer));
  } catch (e) {}
}
function isTrapReq(req, q) {
  try {
    const url = (req.url || "").toString().toLowerCase();
    if (url.includes("trap")) return true;
    const qq = q || {};
    for (const k of ["key", "hwid", "k"]) {
      const v = (qq[k] || "").toString().toLowerCase();
      if (v === "trap" || v.includes("trap")) return true;
    }
  } catch (e) {}
  return false;
}

// ---------- tickets ----------
function ipHash(ip) { return sha256Hex("ip|" + (ip || "unknown")).slice(0, 16); }
function hwidHash(hwid) {
  const h = sanitizeHwid(hwid);
  if (!h) return "free";
  return sha256Hex("hwid|" + h).slice(0, 16);
}
function makeTicket(ip, hwid) {
  const secret = getLoaderSecret();
  if (!secret) return null;
  const ticket = `${randHex(8)}.${Math.floor(Date.now() / 1000)}`;
  const sig = hmacHex(secret, `v4|${SCRIPT_ID}|${ticket}|${ipHash(ip)}|${hwidHash(hwid)}`);
  return { ticket, sig };
}
function verifyTicket(ticket, sig, ip, hwid) {
  const secret = getLoaderSecret();
  if (!secret) return false;
  if (typeof ticket !== "string" || typeof sig !== "string") return false;
  if (!/^[0-9a-f]{16}\.\d{10}$/.test(ticket)) return false;
  if (!/^[0-9a-f]{64}$/.test(sig)) return false;
  const ts = parseInt(ticket.split(".")[1], 10) * 1000;
  if (Math.abs(Date.now() - ts) > TICKET_TTL * 1000) return false;
  const expect = hmacHex(secret, `v4|${SCRIPT_ID}|${ticket}|${ipHash(ip)}|${hwidHash(hwid)}`);
  try {
    const a = Buffer.from(expect, "hex");
    const b = Buffer.from(sig, "hex");
    if (a.length !== b.length) return false;
    return crypto.timingSafeEqual(a, b);
  } catch (e) { return false; }
}
function markUsed(ticket) {
  prune();
  if (usedTickets.has(ticket)) return false;
  usedTickets.set(ticket, Date.now() + TICKET_TTL * 1000);
  return true;
}
function consumeTicket(ticket) {
  prune();
  usedTickets.set(ticket, Date.now() + TICKET_TTL * 1000);
}
function prune() {
  const now = Date.now();
  for (const [k, exp] of usedTickets) if (exp < now) usedTickets.delete(k);
}

// ---------- user keys ----------
function makeUserKey(hwid, days) {
  const secret = getLoaderSecret();
  if (!secret) return null;
  const exp = Math.floor(Date.now() / 1000) + (days || 365) * 86400;
  const sig = hmacHex(secret, `vkey|${hwid}|${exp}`);
  return `${exp}.${sig}`;
}
function verifyUserKey(key, hwid) {
  const secret = getLoaderSecret();
  if (!secret) return false;
  if (typeof key !== "string" || typeof hwid !== "string") return false;
  const m = key.match(/^(\d{10})\.([0-9a-f]{64})$/);
  if (!m) return false;
  const exp = parseInt(m[1], 10);
  if (exp * 1000 < Date.now()) return false;
  const expect = hmacHex(secret, `vkey|${hwid}|${exp}`);
  try {
    const a = Buffer.from(expect, "hex");
    const b = Buffer.from(m[2], "hex");
    if (a.length !== b.length) return false;
    return crypto.timingSafeEqual(a, b);
  } catch (e) { return false; }
}

async function checkTurnstile(token, ip) {
  const cfg = getTurnstile();
  if (!cfg) return false;
  try {
    if (!token || token.length < 10) return false;
    const params = new URLSearchParams({ secret: cfg.secret, response: token });
    if (ip && ip !== "unknown") params.append("remoteip", ip);
    const ctl = new AbortController();
    const timer = setTimeout(() => { try { ctl.abort(); } catch (e) {} }, 5000);
    const r = await fetch("https://challenges.cloudflare.com/turnstile/v0/siteverify", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: params.toString(),
      signal: ctl.signal,
    });
    clearTimeout(timer);
    const j = await r.json();
    return !!(j && j.success);
  } catch (e) { return false; }
}

// ---------- sanitize ----------
function sanitizeHwid(hwid) {
  return (hwid || "").toString().replace(/[^A-Za-z0-9_\-.:]/g, "").slice(0, 64);
}
function validHwid(hwid) {
  return sanitizeHwid(hwid).length >= 3;
}
function sanitizePlace(place) {
  return (place || "").toString().replace(/[^0-9]/g, "").slice(0, 12);
}
function validPlace(place) {
  const p = sanitizePlace(place);
  return p.length >= 1 && /^\d{1,12}$/.test(p);
}
function placeAllowed(place) {
  if (!ALLOWED_PLACES) return true;
  return ALLOWED_PLACES.split(",").map((x) => x.trim()).filter(Boolean).includes(place);
}

// ---------- responses ----------
function secureApi(res) {
  res.setHeader("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0");
  res.setHeader("Pragma", "no-cache");
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("Referrer-Policy", "no-referrer");
  res.setHeader("Permissions-Policy", "camera=(), microphone=(), geolocation=()");
  res.setHeader("X-Robots-Tag", "noindex, nofollow, noarchive, nosnippet, noai, noimageai");
  res.setHeader("Strict-Transport-Security", "max-age=63072000; includeSubDomains; preload");
}
function noCache(res) { secureApi(res); }

function isFake(req) {
  try {
    if (!FAKE_HOST) return false;
    const fh = FAKE_HOST.replace(/^https?:\/\//i, "").split("/")[0].toLowerCase();
    return getHost(req).toLowerCase() === fh;
  } catch (e) { return false; }
}

const buildLanding = require("./_landing");

function sendBlack(req, res) {
  secureApi(res);
  if (req && isBrowser(req) && !isFake(req) && FAKE_HOST) {
    const path = (req.url || "/").toString().slice(0, 200);
    res.setHeader("Location", FAKE_HOST.replace(/\/$/, "") + (path.startsWith("/") ? path : "/" + path));
    return res.status(302).send("");
  }
  res.setHeader("Content-Type", "text/html; charset=utf-8");
  res.setHeader("Content-Security-Policy", "default-src 'none'; img-src https:; style-src 'unsafe-inline'; script-src 'unsafe-inline' https:; frame-ancestors 'none'; base-uri 'none'");
  res.setHeader("X-Frame-Options", "DENY");
  if (req && isFake(req)) {
    try { return res.status(200).send(buildLanding(getHost(req), getHost(req))); }
    catch (e) { return res.status(200).send(""); }
  }
  try { return res.status(200).send(buildLanding(getHost(req))); }
  catch (e) { return res.status(200).send(""); }
}
function sendLuaError(res) {
  secureApi(res);
  res.setHeader("Content-Type", "text/plain; charset=utf-8");
  return res.status(200).send(`error("unauthorized [sodium v4]")`);
}

module.exports = {
  SCRIPT_ID,
  ALLOWED_PLACES,
  FAKE_HOST,
  TICKET_TTL,
  RC4_DROP,
  getLoaderSecret,
  getTurnstile,
  getPowDifficulty,
  getEnvLua,
  sha256Hex,
  hmacHex,
  proofHash,
  powVerify,
  randHex,
  rc4Crypt,
  getIp,
  getHost,
  isBotUA,
  isBrowser,
  isTrustedExecutor,
  hasBrowserHeaders,
  checkQueryOrder,
  isDatacenterIP,
  rateLimited,
  verifyPostLimited,
  isSuspiciousHwid,
  checkHwidThrottle,
  kvCheckAndSetTicket,
  logTrap,
  isTrapReq,
  ipHash,
  hwidHash,
  makeTicket,
  verifyTicket,
  markUsed,
  consumeTicket,
  makeUserKey,
  verifyUserKey,
  checkTurnstile,
  sanitizeHwid,
  validHwid,
  sanitizePlace,
  validPlace,
  placeAllowed,
  isFake,
  secureApi,
  noCache,
  sendBlack,
  sendLuaError,
};
