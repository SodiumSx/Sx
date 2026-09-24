// /api/raw v2 — Luarmor-style gọn + ticket HMAC (không lộ secret)
// Luồng: executor HttpGet(/api/raw) -> nhận loader chứa ticket+sig (hết hạn 180s, dùng 1 lần)
// -> loader tự gọi /api/payload?ticket&sig&hwid&place -> nhận blob mã hoá -> giải + chạy
// Tool cũ parse _t="..." / fetch thẳng payload với secret tĩnh -> DIE ở v2.

const P = require("./_protect");

function randName() {
  const abc = "abcdef";
  let s = "_";
  for (let i = 0; i < 5; i++) s += abc[Math.floor(Math.random() * abc.length)] + Math.floor(Math.random() * 10);
  return s;
}

// Chia host thành nhiều mảnh để regex "https://.../api/payload" cũ không match.
// Ví dụ: "https://".."sodiumsxhub-loader.vercel.app".."/api/payload"
function splitHostLua(host) {
  const cut = Math.max(4, Math.floor(host.length / 2));
  const a = host.slice(0, cut);
  const b = host.slice(cut);
  return `"https://"..'${a}'..'${b}'.."/api/".."payload"`;
}

// Chia script_id để regex local _s="..." cũ không match.
function splitIdLua(id) {
  const cut = Math.max(2, Math.floor(id.length / 2));
  return `'${id.slice(0, cut)}'..'${id.slice(cut)}'`;
}

function buildLoader(host, ticket, sig, ukey) {
  // Tên biến random mỗi request -> tool hardcode _s/_t/_u chết.
  // Dùng nháy đơn + nối chuỗi -> regex cũ "([^"]+)" chết.
  const vS = randName();
  const vT = randName();
  const vG = randName();
  const vH = randName();
  const vP = randName();
  const vU = randName();
  const idLua = splitIdLua(P.SCRIPT_ID);
  const hostLua = splitHostLua(host);
  // Key ca nhan (?key= tu loader rieng) duoc truyen tiep xuong payload. Key chi chua [0-9a-f.] nen an toan.
  const keyTail = ukey ? `..'&key=${ukey}'` : "";

  return `-- sodium loader v2
local ${vS}=${idLua}
local ${vT}='${ticket}.${sig}'
local ${vG}=(typeof(gethwid)=='function' and gethwid() or game:GetService('RbxAnalyticsService'):GetClientId())
local ${vH}=tostring(${vG} or 'unknown')
local ${vP}=tostring(game.PlaceId)
local ${vU}=(${hostLua})..'?s='..${vS}..'&k='..${vT}..'&hwid='..${vH}:gsub('[^%w%-%.:]','')..'&place='..${vP}${keyTail}
loadstring(game:HttpGet(${vU}))()
`;
}

function handler(req, res) {
  P.noCache(res);
  if (P.rateLimited(req)) return P.sendBlack(req, res);
  if (!P.isRoblox(req)) return P.sendBlack(req, res);

  // Fake mode: loader nhin y chang real (ticket format chuan) nhung payload chi tra loi.
  const ukey = (((req.query || {}).key) || "").toString().replace(/[^0-9a-f.]/g, "").slice(0, 80);
  const ticket = P.makeTicket();
  const sig = P.signTicket(ticket);
  res.setHeader("Content-Type", "text/plain; charset=utf-8");
  return res.status(200).send(buildLoader(P.getHost(req), ticket, sig, ukey));
}

module.exports = handler;
module.exports.default = handler;
