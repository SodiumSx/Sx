// Trang landing full (logo + o loader + nut copy).
// Build theo host -> web fake hien loader cua chinh no (ke cap copy ve chay van an loi).
// Giua dong bo voi index.html (trang chu).

module.exports = function buildLanding(host, copyHost) {
  const h = (host || "sodiumsxhub-loader.vercel.app").toString().replace(/["'<>&]/g, "");
  const c = ((copyHost || host) || "sodiumsxhub-loader.vercel.app").toString().replace(/["'<>&]/g, "");
  // Chu HIEN (mat thay) vs chu COPY (nut chep) co the khac nhau — web fake dung de bay.
  const display = `loadstring(game:HttpGet("https://${h}/api/raw"))()`;
  const copyStr = `loadstring(game:HttpGet("https://${c}/api/raw"))()`;
  const loader = display;
  return `<!doctype html>
<html lang="vi">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Sodium Hub</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
html,body{height:100%}
body{
  font-family:Consolas,Menlo,monospace;
  background:#000 url('https://w.wallhaven.cc/full/g7/wallhaven-g7lvee.jpg') center/cover no-repeat fixed;
  min-height:100%;display:flex;align-items:center;justify-content:center;padding:24px;
  position:relative;
}
body::before{content:"";position:fixed;inset:0;background:rgba(0,0,0,.65)}
.wrap{
  position:relative;text-align:center;max-width:95%;width:fit-content;
}
.avatar{
  width:140px;height:140px;object-fit:cover;border-radius:28px;
  border:none;display:block;margin:0 auto 18px;
  background:#1a1a20;
}
.title{color:#fff;font-size:22px;font-weight:700;letter-spacing:.5px;margin-bottom:22px}
.codebox{
  display:flex;align-items:stretch;gap:8px;
  background:#000;border:1px solid rgba(255,255,255,.25);border-radius:0;
  padding:6px 6px 6px 12px;text-align:left;
}
.codebox code{
  flex:1;color:#fff;font-size:12px;line-height:1.4;word-break:break-all;
  align-self:center;user-select:all;
}
.codebox button{
  flex-shrink:0;cursor:pointer;border:none;border-radius:0;
  background:#000;color:#fff;font-size:20px;padding:0 12px;line-height:1;
  display:flex;align-items:center;justify-content:center;
  transition:transform .08s,background .15s;
}
.codebox button svg{width:18px;height:18px}
.codebox button:hover{background:#333}
.codebox button:active{transform:scale(.95)}
</style>
</head>
<body>
<div class="wrap">
  <img class="avatar" src="https://i.ibb.co/0RR4v081/Chat-GPT-Image-10-22-46-23-thg-9-2026.png" alt="Sodium Hub">
  <div class="title">Protect By KietLacKoVui</div>
  <div class="codebox">
    <code id="loader">${loader.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;")}</code>
    <button id="copyBtn" title="Sao chép" onclick="copyLoader()"><i data-lucide="copy"></i></button>
  </div>
</div>
<script src="https://unpkg.com/lucide@latest/dist/umd/lucide.min.js"></script>
<script>
var LOADER='${copyStr.replace(/\\/g, "\\\\").replace(/'/g, "\\'")}';
function renderIcon(name){
  var b=document.getElementById('copyBtn');
  if(window.lucide){b.innerHTML='<i data-lucide="'+name+'"></i>';lucide.createIcons();}
  else{b.textContent=(name==='check')?'✓':'📋';}
}
renderIcon('copy');
function copyLoader(){
  var done=function(){
    renderIcon('check');
    setTimeout(function(){renderIcon('copy')},2000);
  };
  if(navigator.clipboard&&navigator.clipboard.writeText){
    navigator.clipboard.writeText(LOADER).then(done).catch(function(){fallback()});
  }else{fallback()}
  function fallback(){
    var t=document.createElement('textarea');t.value=LOADER;document.body.appendChild(t);
    t.select();try{document.execCommand('copy')}catch(e){}document.body.removeChild(t);done();
  }
}
</script>
</body>
</html>`;
};
