// /api/payload v4 — proof + PoW + order + IP/HWID-bound ticket + KV replay + RC4-drop + watermark.

const P = require("./_protect");
const crypto = require("crypto");

// REAL SOURCE: prefer ENV LUA_B64 (repo holds no source). Dev fallback below.
const LUA_FALLBACK = `-- sodiumhub
print("Tôi Bị Đao")
`;
function getSource() {
  return P.getEnvLua() || LUA_FALLBACK;
}

function rnd(n) {
  const abc = "abcdef";
  let s = "_";
  const bytes = crypto.randomBytes(Math.max(2, n * 2));
  for (let i = 0; i < n; i++) s += abc[bytes[i] % 6] + (bytes[n + i] % 10);
  return s;
}

// RC4-drop pure-Lua stub, randomized vars per request, wipes temp globals after run.
function buildStub(blobB64, sigHex, drop) {
  const vB = rnd(6), vG = rnd(6), vC = rnd(6), vM = rnd(6), vD = rnd(6),
        vH = rnd(6), vK = rnd(6), vR = rnd(6), vS = rnd(6), vI = rnd(6),
        vJ = rnd(6), vT = rnd(6), vO = rnd(6), vN = rnd(6), vX = rnd(6);
  const junk = Math.floor(Math.random() * 900000) + 10000;
  return `-- sodium v4 stub|${junk}
local ${vB}='${blobB64}'
local ${vG}='${sigHex}'
local ${vC}='ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
local ${vM}={}
for ${vI}=1,#${vC} do ${vM}[${vC}:sub(${vI},${vI})]=${vI}-1 end
local function ${vD}(${vJ})
 ${vJ}=${vJ}:gsub('[^'..${vC}..'=]','')
 local ${vO}={}
 local ${vI}=1
 while ${vI}<=#${vJ} do
  local _a,_b,_e,_f=${vM}[${vJ}:sub(${vI},${vI})] or 0,${vM}[${vJ}:sub(${vI}+1,${vI}+1)] or 0,${vM}[${vJ}:sub(${vI}+2,${vI}+2)] or 0,${vM}[${vJ}:sub(${vI}+3,${vI}+3)] or 0
  local _n=_a*262144+_b*4096+_e*64+_f
  table.insert(${vO},string.char(math.floor(_n/65536)%256))
  if ${vJ}:sub(${vI}+2,${vI}+2)~='=' then table.insert(${vO},string.char(math.floor(_n/256)%256)) end
  if ${vJ}:sub(${vI}+3,${vI}+3)~='=' then table.insert(${vO},string.char(_n%256)) end
  ${vI}=${vI}+4
 end
 return table.concat(${vO})
end
local ${vH}=(typeof(gethwid)=='function' and gethwid() or game:GetService('RbxAnalyticsService'):GetClientId())
${vH}=tostring(${vH} or 'unknown'):gsub('[^%w%-%.:]','')
local ${vK}=${vG}..'|'..${vH}
local ${vR}=${vD}(${vB})
local ${vS}={}
for ${vI}=0,255 do ${vS}[${vI}]=${vI} end
local ${vJ}=0
for ${vI}=0,255 do
 ${vJ}=(${vJ}+${vS}[${vI}]+${vK}:byte((${vI}%#${vK})+1))%256
 ${vT}=${vS}[${vI}] ${vS}[${vI}]=${vS}[${vJ}] ${vS}[${vJ}]=${vT}
end
local ${vI}=0 ${vJ}=0
for ${vX}=1,${drop} do
 ${vI}=(${vI}+1)%256
 ${vJ}=(${vJ}+${vS}[${vI}])%256
 ${vT}=${vS}[${vI}] ${vS}[${vI}]=${vS}[${vJ}] ${vS}[${vJ}]=${vT}
end
local ${vN}={}
for ${vO}=1,#${vR} do
 ${vI}=(${vI}+1)%256
 ${vJ}=(${vJ}+${vS}[${vI}])%256
 ${vT}=${vS}[${vI}] ${vS}[${vI}]=${vS}[${vJ}] ${vS}[${vJ}]=${vT}
 local _k=${vS}[((${vS}[${vI}]+${vS}[${vJ}])%256)]
 ${vN}[${vO}]=string.char(bit32.bxor(${vR}:byte(${vO}),_k))
end
local ${vX}=table.concat(${vN})
${vB}=nil ${vR}=nil ${vN}=nil
_G['load'..'string'](${vX})()
`;
}

async function handler(req, res) {
  P.secureApi(res);
  const q0 = req.query || {};
  if (P.isTrapReq(req, q0)) {
    P.logTrap(P.getIp(req), (req.headers && req.headers["user-agent"]) || "", "payload-trap", req.url);
    return P.sendLuaError(res);
  }
  if (P.rateLimited(req)) return P.sendLuaError(res);
  if (P.isBotUA(req)) {
    P.logTrap(P.getIp(req), (req.headers && req.headers["user-agent"]) || "", "payload-bot", "");
    return P.sendBlack(req, res);
  }
  if (!P.isTrustedExecutor(req)) return P.sendBlack(req, res);
  if (P.isFake(req)) return P.sendLuaError(res);
  if (!P.getLoaderSecret()) { console.warn("[sodium] payload reject=no-secret"); return P.sendLuaError(res); }
  // Mandatory query order: s,k,hwid,place,p,n (plus trailing key when present)
  if (!P.checkQueryOrder(req, ["s", "k", "hwid", "place", "p", "n"])) return P.sendLuaError(res);

  const q = req.query || {};
  const s = (q.s || "").toString();
  const k = (q.k || "").toString();
  const hwid = P.sanitizeHwid(q.hwid);
  const place = P.sanitizePlace(q.place);
  const proof = (q.p || "").toString().toLowerCase().slice(0, 8);
  const nonce = (q.n || "").toString().slice(0, 16);
  const ukey = (q.key || "").toString().replace(/[^0-9a-f.]/g, "").slice(0, 80);

  if (s !== P.SCRIPT_ID) return P.sendLuaError(res);
  if (!P.validHwid(hwid)) return P.sendLuaError(res);
  if (!P.validPlace(place)) return P.sendLuaError(res);
  if (!/^[0-9a-f]{8}$/.test(proof)) return P.sendLuaError(res);
  if (!/^[A-Za-z0-9]{1,16}$/.test(nonce)) return P.sendLuaError(res);
  if (!P.placeAllowed(place)) {
    res.setHeader("Content-Type", "text/plain; charset=utf-8");
    return res.status(200).send(`error("wrong game [sodium v4]")`);
  }

  const ip = P.getIp(req);
  if (await P.isDatacenterIP(ip)) {
    P.logTrap(ip, (req.headers && req.headers["user-agent"]) || "", "payload-datacenter", "");
    return P.sendLuaError(res);
  }

  const m = k.match(/^([0-9a-f]{16}\.\d{10})\.([0-9a-f]{64})$/);
  if (!m) return P.sendLuaError(res);
  const ticket = m[1], sig = m[2];

  const expectProof = P.proofHash(`${ticket}|${hwid}|${place}`);
  if (proof !== expectProof) {
    P.consumeTicket(ticket);
    return P.sendLuaError(res);
  }
  if (!P.powVerify(ticket, hwid, place, nonce)) {
    P.consumeTicket(ticket);
    return P.sendLuaError(res);
  }

  const okBound = P.verifyTicket(ticket, sig, ip, hwid);
  const okFree = !okBound && P.verifyTicket(ticket, sig, ip, "");
  if (!okBound && !okFree) return P.sendLuaError(res);

  // KV cross-instance replay (Upstash). Memory map below still guards per-instance.
  const kvFresh = await P.kvCheckAndSetTicket(ticket);
  if (!kvFresh) return P.sendLuaError(res);
  if (!P.markUsed(ticket)) return P.sendLuaError(res);
  if (!P.checkHwidThrottle(hwid, ip)) return P.sendLuaError(res);

  if (ukey) {
    if (!P.verifyUserKey(ukey, hwid)) return P.sendLuaError(res);
  }

  const expTs = Math.floor(Date.now() / 1000) + 300;
  const wm = `-- licensed:${hwid}|${place}|${Date.now()}|${P.ipHash(ip).slice(0, 8)}|n=${nonce}\nif (os.time and os.time()>${expTs}) then error("expired") end\n`;
  const code = wm + getSource();
  const keyBuf = Buffer.from(`${sig}|${hwid}`, "utf8");
  const blob = P.rc4Crypt(Buffer.from(code, "utf8"), keyBuf, P.RC4_DROP).toString("base64");

  res.setHeader("Content-Type", "text/plain; charset=utf-8");
  return res.status(200).send(buildStub(blob, sig, P.RC4_DROP));
}

module.exports = handler;
module.exports.default = handler;
