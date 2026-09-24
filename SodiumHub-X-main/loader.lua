-- SodiumHub loader v4 — no static KEY like v2.
-- Correct flow:
--   1. Free:  loadstring(game:HttpGet("https://YOUR-HOST/api/raw"))()
--   2. Personal (after verify): loadstring(game:HttpGet("https://YOUR-HOST/api/raw?key=EXP.SIG&hwid=YOUR_HWID"))()
-- Replace YOUR-HOST / EXP.SIG / YOUR_HWID with the values returned by /api/verify.
-- /api/raw only serves the PoW loader to genuine Roblox executors (Roblox UA, no
-- cookie/referer, no accept-language, no text/html), blocking curl/fetch/AI + datacenters.
-- The loader mines PoW (djb2 hashcash) then calls /api/payload?s=&k=&hwid=&place=&p=&n=
-- in strict order; tickets are IP+HWID bound, single-use, 120s; blobs are RC4-drop512 + watermarked.
-- The real source lives in the LUA_B64 env (see tools/encrypt-source.js); the repo holds no source.

local HOST = "https://YOUR-HOST/api/raw"
-- Personal example:
-- local HOST = "https://YOUR-HOST/api/raw?key=1740000000.abc123...&hwid=ABC123"

local src = game:HttpGet(HOST)
local f = loadstring(src)
if f then f() end
