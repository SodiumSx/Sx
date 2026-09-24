// _landing v4 — loader is assembled by JS + revealed after interaction (anti headless/AI).

function b64(s) { return Buffer.from(s, "utf8").toString("base64"); }
function chunk3(s) {
  const b = b64(s);
  const n = Math.ceil(b.length / 3);
  return [b.slice(0, n), b.slice(n, n * 2), b.slice(n * 2)];
}

module.exports = function buildLanding(host, copyHost) {
  const h = ((host || "localhost").toString().replace(/["'<>&\r\n\\]+/g, "") || "localhost").slice(0, 253);
  const c = (((copyHost || host) || "localhost").toString().replace(/["'<>&\r\n\\]+/g, "") || "localhost").slice(0, 253);
  const display = `loadstring(game:HttpGet("https://${h}/api/raw"))()`;
  const copyStr = `loadstring(game:HttpGet("https://${c}/api/raw"))()`;
  const d = chunk3(display);
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex, nofollow, noarchive, nosnippet, noai, noimageai">
<meta name="referrer" content="no-referrer">
<title>Sodium Hub</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
html,body{height:100%}
body{font-family:Consolas,Menlo,monospace;background:#000 url('https://w.wallhaven.cc/full/g7/wallhaven-g7lvee.jpg') center/cover no-repeat fixed;min-height:100%;display:flex;align-items:center;justify-content:center;padding:24px;position:relative}
body::before{content:"";position:fixed;inset:0;background:rgba(0,0,0,.65)}
.wrap{position:relative;text-align:center;max-width:95%;width:fit-content}
.avatar{width:140px;height:140px;object-fit:cover;border-radius:28px;border:none;display:block;margin:0 auto 18px;background:#1a1a20}
.title{color:#fff;font-size:22px;font-weight:700;letter-spacing:.5px;margin-bottom:22px}
.codebox{display:flex;align-items:stretch;gap:8px;background:#000;border:1px solid rgba(255,255,255,.25);padding:6px 6px 6px 12px;text-align:left}
.codebox code{flex:1;color:#fff;font-size:12px;line-height:1.4;word-break:break-all;align-self:center;user-select:all}
.codebox button{flex-shrink:0;cursor:pointer;border:none;background:#000;color:#fff;font-size:20px;padding:0 12px;line-height:1;display:flex;align-items:center;justify-content:center}
.codebox button:hover{background:#333}
.honey{display:none!important}
</style>
</head>
<body>
<div class="wrap">
<img class="avatar" src="https://i.ibb.co/0RR4v081/Chat-GPT-Image-10-22-46-23-thg-9-2026.png" alt="Sodium Hub">
<div class="title">Protect By KietLacKoVui</div>
<div class="codebox"><code id="loader">Move your mouse to reveal the loader…</code>
<button id="copyBtn" title="Copy" onclick="copyLoader()">&#128203;</button></div>
<a class="honey" href="/api/raw?key=trap" rel="nofollow">mirror</a>
</div>
<script src="https://unpkg.com/lucide@latest/dist/umd/lucide.min.js"></script>
<script>
var P1='${d[0]}',P2='${d[1]}',P3='${d[2]}';
var LOADER='${copyStr.replace(/\\/g, "\\\\").replace(/'/g, "\\'")}';
var SHOWN=false;
function b64d(s){try{return atob(s)}catch(e){return ''}}
function show(){if(SHOWN)return;SHOWN=true;try{document.getElementById('loader').textContent=b64d(P1+P2+P3)}catch(e){}}
setTimeout(show,2500);
window.addEventListener('mousemove',show,{once:true});
window.addEventListener('touchstart',show,{once:true});
function renderIcon(n){var b=document.getElementById('copyBtn');if(window.lucide){b.innerHTML='<i data-lucide="'+n+'"></i>';lucide.createIcons()}else{b.textContent=(n==='check')?'\\u2713':'\\uD83D\\uDCCB'}}
renderIcon('copy');
function copyLoader(){show();var d=function(){renderIcon('check');setTimeout(function(){renderIcon('copy')},2000)};if(navigator.clipboard&&navigator.clipboard.writeText){navigator.clipboard.writeText(LOADER).then(d).catch(function(){fb()})}else{fb()}function fb(){var t=document.createElement('textarea');t.value=LOADER;document.body.appendChild(t);t.select();try{document.execCommand('copy')}catch(e){}document.body.removeChild(t);d()}}
</script>
</body>
</html>`;
};
