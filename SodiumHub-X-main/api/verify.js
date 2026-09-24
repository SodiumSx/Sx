// /api/verify v4 — browser-only Turnstile checkpoint issuing personal loaders.
// GET: browsers only (Roblox/curl get blackholed). POST: real browsers + Turnstile + honeypot.

const P = require("./_protect");

function json(res, code, obj) {
  P.secureApi(res);
  res.setHeader("Content-Type", "application/json; charset=utf-8");
  return res.status(code).send(JSON.stringify(obj));
}
function readJson(req) {
  return new Promise((resolve) => {
    let data = "";
    req.on("data", (c) => {
      data += c;
      if (data.length > 4096) {
        try { req.destroy(); } catch (e) {}
        resolve({});
      }
    });
    req.on("end", () => {
      try { resolve(JSON.parse(data || "{}")); } catch (e) { resolve({}); }
    });
    req.on("error", () => resolve({}));
  });
}

function page(hwid, site) {
  const safeHwid = (hwid || "").replace(/["'<>&\r\n\\]+/g, "").slice(0, 64);
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex, nofollow, noarchive, nosnippet, noai, noimageai">
<meta name="referrer" content="no-referrer">
<title>Sodium Hub — Verify</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
html,body{height:100%}
body{font-family:Consolas,Menlo,monospace;background:#000;color:#fff;min-height:100%;display:flex;align-items:center;justify-content:center;padding:24px}
.wrap{text-align:center;max-width:95%;width:fit-content}
.title{font-size:20px;font-weight:700;margin-bottom:8px}
.hwid{color:#9a9aa5;font-size:12px;margin-bottom:18px;word-break:break-all}
.box{background:#000;border:1px solid rgba(255,255,255,.25);padding:20px;margin-bottom:14px}
button{cursor:pointer;border:1px solid #fff;background:#fff;color:#000;font-weight:700;font-size:14px;padding:10px 22px;font-family:inherit}
button:disabled{opacity:.35;cursor:not-allowed}
button:not(:disabled):hover{background:#333;color:#fff}
#out{display:none;background:#000;border:1px solid rgba(255,255,255,.25);padding:12px;text-align:left;margin-top:14px}
#out code{color:#fff;font-size:12px;word-break:break-all;user-select:all}
.err{color:#ff7b7b;font-size:13px;margin-top:10px}
.cf-turnstile{margin:0 auto 14px;display:inline-block}
.hp{position:absolute;left:-9999px;top:auto;width:1px;height:1px;overflow:hidden}
</style>
</head>
<body>
<div class="wrap">
<div class="title">Verify — one time only</div>
<div class="hwid">HWID: ${safeHwid || "(missing hwid — run the loader to get the link)"}</div>
<div class="box">
<div class="cf-turnstile" data-sitekey="${site.replace(/["'<>&]+/g, "")}" data-callback="onOK"></div>
<div class="hp"><input id="website" type="text" value="" autocomplete="off" tabindex="-1"></div>
<div><button id="btn" disabled onclick="doVerify()">Confirm</button></div>
<div class="err" id="err"></div>
</div>
<div id="out"><code id="loader"></code><div style="margin-top:10px"><button onclick="copyL()">Copy loader</button></div></div>
</div>
<script src="https://challenges.cloudflare.com/turnstile/v0/api.js" async defer><\/script>
<script>
var HWID=${JSON.stringify(safeHwid)};
var FINAL='';
function onOK(){document.getElementById('btn').disabled=false;}
function copyL(){var d=function(){};if(navigator.clipboard&&navigator.clipboard.writeText){navigator.clipboard.writeText(FINAL).then(d).catch(function(){});}}
function doVerify(){
 var e=document.getElementById('err');e.textContent='';
 var token='';
 try{token=turnstile.getResponse();}catch(_){e.textContent='Captcha is not ready yet, wait 3s.';return;}
 if(!token){e.textContent='Please complete the captcha first.';return;}
 var hp='';try{hp=document.getElementById('website').value||'';}catch(_){}
 fetch('',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({hwid:HWID,token:token,website:hp})})
 .then(function(r){return r.json()})
 .then(function(j){
  if(j&&j.ok){FINAL=j.loader;document.getElementById('loader').textContent=j.loader;document.getElementById('out').style.display='block';}
  else{e.textContent='Verification failed, try again.';try{turnstile.reset();}catch(_){}}
 })
 .catch(function(){e.textContent='Network error, try again.';});
}
<\/script>
</body>
</html>`;
}

async function handler(req, res) {
  const method = ((req.method || "GET").toString().toUpperCase());

  if (method === "POST") {
    if (P.isBotUA(req)) return json(res, 403, { ok: false });
    if (P.isTrustedExecutor(req)) return json(res, 403, { ok: false });
    if (!P.isBrowser(req)) return json(res, 403, { ok: false });
    // A real browser must carry browser markers (stops naive Mozilla-spoofing curl)
    try {
      const h = req.headers || {};
      const marks = (h["accept-language"] ? 1 : 0) + (h["sec-fetch-site"] || h["sec-fetch-mode"] ? 1 : 0) + ((h.accept || "").toString().includes("text/html") || (h.accept || "").toString().includes("application/json") ? 1 : 0);
      if (marks < 2) {
        P.logTrap(P.getIp(req), (h["user-agent"] || ""), "verify-weak-browser", "");
        return json(res, 403, { ok: false });
      }
    } catch (e) { return json(res, 403, { ok: false }); }
    if (P.rateLimited(req)) return json(res, 429, { ok: false });
    if (P.verifyPostLimited(req)) return json(res, 429, { ok: false });
    const cfg = P.getTurnstile();
    if (!cfg || !P.getLoaderSecret()) return json(res, 503, { ok: false });
    const body = await readJson(req);
    // honeypot: auto-filling bots populate the hidden field
    if (((body.website || "").toString())) {
      P.logTrap(P.getIp(req), (req.headers && req.headers["user-agent"]) || "", "verify-honeypot", "");
      return json(res, 403, { ok: false });
    }
    const hwid = P.sanitizeHwid(body.hwid);
    if (!P.validHwid(hwid)) return json(res, 400, { ok: false, error: "bad hwid" });
    const ok = await P.checkTurnstile((body.token || "").toString(), P.getIp(req));
    if (!ok) return json(res, 403, { ok: false, error: "turnstile" });
    const key = P.makeUserKey(hwid, 365);
    if (!key) return json(res, 503, { ok: false });
    const host = P.getHost(req);
    const loader = `loadstring(game:HttpGet("https://${host}/api/raw?key=${key}&hwid=${encodeURIComponent(hwid)}"))()`;
    return json(res, 200, { ok: true, loader });
  }

  if (P.isBotUA(req) || P.isTrustedExecutor(req)) return P.sendBlack(req, res);
  if (P.isTrapReq(req, req.query || {})) {
    P.logTrap(P.getIp(req), (req.headers && req.headers["user-agent"]) || "", "verify-trap", req.url);
    return P.sendBlack(req, res);
  }
  const cfg = P.getTurnstile();
  if (!cfg) return P.sendBlack(req, res);
  const hwid = P.sanitizeHwid(((req.query || {}).hwid) || "");
  P.secureApi(res);
  res.setHeader("Content-Type", "text/html; charset=utf-8");
  res.setHeader("Content-Security-Policy", "default-src 'self' https://challenges.cloudflare.com; script-src 'self' 'unsafe-inline' https://challenges.cloudflare.com; style-src 'unsafe-inline'; frame-src https://challenges.cloudflare.com; frame-ancestors 'none'; base-uri 'none'");
  res.setHeader("X-Frame-Options", "DENY");
  return res.status(200).send(page(hwid, cfg.site));
}

module.exports = handler;
module.exports.default = handler;
