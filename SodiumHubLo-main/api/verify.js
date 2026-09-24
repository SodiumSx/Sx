// /api/verify — checkpoint Turnstile 1 lan cho HWID la, cap loader ca nhan (key bound HWID).
// GET  ?hwid=... -> trang verify (nguoi tich captcha)
// POST {hwid, token} -> {ok, loader} (loader kem ?key=, han 365 ngay, stateless)

const P = require("./_protect");

function json(res, code, obj) {
  res.setHeader("Content-Type", "application/json; charset=utf-8");
  return res.status(code).send(JSON.stringify(obj));
}

function readJson(req) {
  return new Promise((resolve) => {
    let data = "";
    req.on("data", (c) => {
      data += c;
      if (data.length > 8192) {
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

function page(hwid) {
  const safeHwid = (hwid || "").replace(/["'<>&]/g, "");
  return `<!doctype html>
<html lang="vi">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
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
</style>
</head>
<body>
<div class="wrap">
  <div class="title">Verify — 1 lan duy nhat</div>
  <div class="hwid">HWID: ${safeHwid || "(thieu hwid — chay loader de lay link)"}</div>
  <div class="box">
    <div class="cf-turnstile" data-sitekey="${P.TURNSTILE_SITE}" data-callback="onOK"></div>
    <div><button id="btn" disabled onclick="doVerify()">Xac nhan</button></div>
    <div class="err" id="err"></div>
  </div>
  <div id="out"><code id="loader"></code><div style="margin-top:10px"><button onclick="copyL()">Copy loader</button></div></div>
</div>
<script src="https://challenges.cloudflare.com/turnstile/v0/api.js" async defer></script>
<script>
var HWID=${JSON.stringify(safeHwid)};
var FINAL='';
function onOK(){document.getElementById('btn').disabled=false;}
function copyL(){
  var done=function(){};
  if(navigator.clipboard&&navigator.clipboard.writeText){navigator.clipboard.writeText(FINAL).then(done).catch(function(){});}
}
function doVerify(){
  var e=document.getElementById('err');e.textContent='';
  var token='';
  try{token=turnstile.getResponse();}catch(_){e.textContent='Captcha chua san sang, doi 3s.';return;}
  if(!token){e.textContent='Ban tich captcha truoc.';return;}
  fetch('',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({hwid:HWID,token:token})})
  .then(function(r){return r.json()})
  .then(function(j){
    if(j&&j.ok){FINAL=j.loader;document.getElementById('loader').textContent=j.loader;document.getElementById('out').style.display='block';}
    else{e.textContent='Verify that bai, thu lai.';try{turnstile.reset();}catch(_){}}
  })
  .catch(function(){e.textContent='Loi mang, thu lai.';});
}
</script>
</body>
</html>`;
}

async function handler(req, res) {
  P.noCache(res);
  const method = ((req.method || "GET").toString().toUpperCase());

  if (method === "POST") {
    if (P.rateLimited(req)) return json(res, 429, { ok: false });
    const body = await readJson(req);
    const hwid = P.sanitizeHwid(body.hwid);
    if (!P.validHwid(hwid)) return json(res, 400, { ok: false, error: "bad hwid" });
    const ok = await P.checkTurnstile((body.token || "").toString(), P.getIp(req));
    if (!ok) return json(res, 403, { ok: false, error: "turnstile" });
    const key = P.makeUserKey(hwid, 365);
    const host = P.getHost(req);
    const loader = `loadstring(game:HttpGet("https://${host}/api/raw?key=${key}"))()`;
    return json(res, 200, { ok: true, loader });
  }

  const hwid = P.sanitizeHwid(((req.query || {}).hwid) || "");
  res.setHeader("Content-Type", "text/html; charset=utf-8");
  return res.status(200).send(page(hwid));
}

module.exports = handler;
module.exports.default = handler;
