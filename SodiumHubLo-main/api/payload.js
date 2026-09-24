// /api/payload v2 — chỉ trả BLOB MÃ HOÁ khi ticket+HMAC+HWID+Place hợp lệ.
// Tool cũ: fetch ?s=&t=static&hwid=test&place=1 với UA fake -> DIE (error v2).
// Luồng đúng: phải qua /api/raw lấy ticket fresh (180s, 1 lần) rồi gọi với ?s=&k=ticket.sig&...

const P = require("./_protect");

// SOURCE THAT — dan code vao giua 2 dau ` ben duoi (ghi de 2 dong demo).
// Chi web THAT moi tra bien nay (web fake khong bao gio dung toi).
// Luu y: tranh dau backtick va ${ trong source. De repo PRIVATE.
const LUA_CODE = `-- sodiumhub
print("sodiumhub")
`;

// Stub giải mã chạy trong executor. Key = sha256(sig|hwid) -> copy blob sang HWID khác là hỏng.
function buildStub(blobB64, sigHex) {
  return `-- sodium v2 stub
local _b='${blobB64}'
local _g='${sigHex}'
local _c='ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
local _m={}
for _i=1,#_c do _m[_c:sub(_i,_i)]=_i-1 end
local function _d(_x)
 _x=_x:gsub('[^'.._c..'=]','')
 local _o={}
 local _i=1
 while _i<=#_x do
  local _a,_b,_e,_f=_m[_x:sub(_i,_i)] or 0,_m[_x:sub(_i+1,_i+1)] or 0,_m[_x:sub(_i+2,_i+2)] or 0,_m[_x:sub(_i+3,_i+3)] or 0
  local _n=_a*262144+_b*4096+_e*64+_f
  local _h1,_h2,_h3=math.floor(_n/65536)%256,math.floor(_n/256)%256,_n%256
  table.insert(_o,string.char(_h1))
  if _x:sub(_i+2,_i+2)~='=' then table.insert(_o,string.char(_h2)) end
  if _x:sub(_i+3,_i+3)~='=' then table.insert(_o,string.char(_h3)) end
  _i=_i+4
 end
 return table.concat(_o)
end
local _h=(typeof(gethwid)=='function' and gethwid() or game:GetService('RbxAnalyticsService'):GetClientId())
_h=tostring(_h or 'unknown'):gsub('[^%w%-%.:]','')
-- sha256 hex (stub gon, khong can thu vien ngoai): dung sig+hwid lam key truc tiep
local _k=_g..'|'.._h
local _r=_d(_b)
local _s={}
for _i=1,#_r do
 local _y=_r:byte(_i)
 local _z=_k:byte(((_i-1)%#_k)+1)
 _s[_i]=string.char(bit32.bxor(_y,_z))
end
-- fallback neu server dung sha256(key): thu them 1 pass sha don gian? (server v2 dung key=sha256(sig|hwid) dang hex)
-- de khop 100% giua Node va Roblox, server v2 ma hoa bang key STRING (sig|hwid), khong hash -> stub nay khop.
loadstring(table.concat(_s))()
`;
}

async function handler(req, res) {
  P.noCache(res);
  if (P.rateLimited(req)) return P.sendBlack(req, res);
  if (!P.isRoblox(req)) return P.sendBlack(req, res);

  // Fake mode: TRANG TINH — khong co source, moi request chi tra loi.
  // Loader van nhin that de ke cap tuong bypass duoc.
  if (P.isFake(req)) return P.sendLuaError(res);

  const q = req.query || {};
  const s = (q.s || "").toString();
  const k = (q.k || "").toString(); // "<ticket>.<sig>"
  const hwid = P.sanitizeHwid(q.hwid);
  const place = P.sanitizePlace(q.place);

  if (s !== P.SCRIPT_ID) return P.sendLuaError(res);
  if (!P.validHwid(hwid)) return P.sendLuaError(res);
  if (!P.validPlace(place)) return P.sendLuaError(res);
  if (!P.placeAllowed(place)) {
    res.setHeader("Content-Type", "text/plain; charset=utf-8");
    return res.status(200).send(`error("wrong game [sodium v2]")`);
  }

  // AI chay tu cloud (OpenAI/Azure/GCP): IP datacenter -> loi am, khong bao ly do.
  // Nguoi mang dan cu -> qua nhu binh thuong, khong verify gi het.
  if (await P.isDatacenterIP(P.getIp(req))) return P.sendLuaError(res);

  // k = ticket.sig  (ticket = rand16.ts10 , sig = hmac64)
  const m = k.match(/^([0-9a-f]{16}\.\d{10})\.([0-9a-f]{64})$/);
  if (!m) return P.sendLuaError(res);
  const ticket = m[1];
  const sig = m[2];
  if (!P.verifyTicket(ticket, sig)) return P.sendLuaError(res);
  if (!P.markUsed(ticket)) return P.sendLuaError(res); // replay
  if (!P.checkHwidThrottle(hwid, P.getIp(req))) return P.sendLuaError(res); // free: gioi han ngam/HWID

  // Mã hoá bằng key STRING (sig|hwid) để stub Lua khớp 100% (tránh lệch sha hex giữa Node/Roblox).
  // Watermark: nhung HWID/place/time vao source truoc khi ma hoa — source leak la biet ai leak.
  const keyStr = `${sig}|${hwid}`;
  const code = `-- licensed:${hwid}|${place}|${Date.now()}\n` + LUA_CODE;
  const keyBuf = Buffer.from(keyStr, "utf8");
  const blob = P.xorCrypt(Buffer.from(code, "utf8"), keyBuf).toString("base64");

  res.setHeader("Content-Type", "text/plain; charset=utf-8");
  return res.status(200).send(buildStub(blob, sig));
}

module.exports = handler;
module.exports.default = handler;
