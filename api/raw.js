// /api/raw v4 — PoW + polymorphic loader. Browsers/curl/AI get blackholed, no ticket.

const P = require("./_protect");
const crypto = require("crypto");

function rnd(n) {
  const abc = "abcdef";
  let s = "_";
  const bytes = crypto.randomBytes(Math.max(2, n * 2));
  for (let i = 0; i < n; i++) s += abc[bytes[i] % 6] + (bytes[n + i] % 10);
  return s;
}
function splitN(s, parts, quote) {
  const q = quote || "'";
  const out = [];
  let idx = 0;
  const sizes = [];
  for (let i = 0; i < parts - 1; i++) {
    const rest = s.length - idx - (parts - i - 1);
    const cut = 1 + Math.floor(Math.random() * Math.max(1, rest - 1));
    sizes.push(cut);
  }
  sizes.push(s.length - idx - sizes.reduce((a, b) => a + b, 0));
  let p = 0;
  for (const sz of sizes) {
    const chunk = s.slice(p, p + sz).replace(/\\/g, "\\\\").replace(new RegExp(q, "g"), "\\" + q);
    out.push(`${q}${chunk}${q}`);
    p += sz;
  }
  return out.join("..");
}

function buildLoader(host, ticket, sig, ukey, powDiff) {
  const vS = rnd(6), vT = rnd(6), vG = rnd(6), vH = rnd(6), vP = rnd(6),
        vU = rnd(6), vF = rnd(6), vJ = rnd(6), vN = rnd(6), vW = rnd(6),
        vZ = rnd(6), vQ = rnd(6);
  const idLua = splitN(P.SCRIPT_ID, 2 + Math.floor(Math.random() * 2), "'");
  const cut = Math.max(4, Math.floor(host.length / 2));
  const ha = host.slice(0, cut).replace(/'/g, "\\'"), hb = host.slice(cut).replace(/'/g, "\\'");
  const keyTail = ukey ? `..'&key=${ukey}'` : "";
  const zeros = "0".repeat(powDiff);
  const junk = Math.floor(Math.random() * 9000) + 1000;
  return `-- sodium loader v4|${junk}
local ${vS}=${idLua}
local ${vT}='${ticket}.${sig}'
local ${vG}=(typeof(gethwid)=='function' and gethwid() or game:GetService('RbxAnalyticsService'):GetClientId())
local ${vH}=tostring(${vG} or 'unknown'):gsub('[^%w%-%.:]','')
local ${vP}=tostring(game.PlaceId)
local function ${vF}(${vJ})
 local _h=5381
 for _i=1,#${vJ} do _h=((_h*33)+${vJ}:byte(_i))%4294967296 end
 return string.format('%08x',_h)
end
local ${vW}=${vF}(${vT}..'|'..${vH}..'|'..${vP})
local ${vN}=0
while true do
 local ${vZ}=${vF}(tostring(${vN})..'|'..${vT}..'|'..${vH}..'|'..${vP})
 if ${vZ}:sub(1,${powDiff})=='${zeros}' then break end
 ${vN}=${vN}+1
end
local ${vQ}=tostring(${vN})
local ${vU}=("https://"..'${ha}'..'${hb}'..${splitN("/api/", 2, '"')}..${splitN("payload", 2, '"')})..'?s='..${vS}..'&k='..${vT}..'&hwid='..${vH}:gsub('[^%w%-%.:]','')..'&place='..${vP}..'&p='..${vW}..'&n='..${vQ}${keyTail}
_G['load'..'string']((game)['Http'..'Get'](game,${vU}))()
`;
}

function handler(req, res) {
  P.secureApi(res);
  const q0 = req.query || {};
  if (P.isTrapReq(req, q0)) {
    P.logTrap(P.getIp(req), (req.headers && req.headers["user-agent"]) || "", "raw-trap", req.url);
    return P.sendBlack(req, res);
  }
  if (P.rateLimited(req)) return P.sendBlack(req, res);
  if (P.isBotUA(req)) return P.sendBlack(req, res);
  if (!P.isTrustedExecutor(req)) return P.sendBlack(req, res);

  const q = req.query || {};
  const ukey = (q.key || "").toString().replace(/[^0-9a-f.]/g, "").slice(0, 80);
  if (ukey === "trap") {
    P.logTrap(P.getIp(req), (req.headers && req.headers["user-agent"]) || "", "raw-key-trap", req.url);
    return P.sendBlack(req, res);
  }
  const hwidQ = P.sanitizeHwid(q.hwid || "");
  const ip = P.getIp(req);
  if (!P.getLoaderSecret()) { console.warn("[sodium] raw reject=no-secret"); return P.sendLuaError(res); }

  P.isDatacenterIP(ip).then((dc) => {
    if (dc) {
      P.logTrap(ip, (req.headers && req.headers["user-agent"]) || "", "raw-datacenter", "");
      return P.sendLuaError(res);
    }
    const t = P.makeTicket(ip, hwidQ);
    if (!t) return P.sendLuaError(res);
    res.setHeader("Content-Type", "text/plain; charset=utf-8");
    return res.status(200).send(buildLoader(P.getHost(req), t.ticket, t.sig, ukey, P.getPowDifficulty()));
  }).catch(() => P.sendLuaError(res));
}

module.exports = handler;
module.exports.default = handler;
