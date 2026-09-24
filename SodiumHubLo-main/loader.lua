-- SodiumHub loader chong tool fetch raw
-- Share doan nay cho user, KHONG share link /api/raw truc tiep
-- Doi KEY + URL cho khop voi Env RAW_KEY tren Vercel

local KEY = "sodiumhub123"
local URL = "https://sodium-hub-lo.vercel.app/api/raw?key=" .. KEY .. "&enc=1"

-- base64 decode thu gon (tuong thich Roblox)
local b64chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
local b64map = {}
for i = 1, #b64chars do b64map[b64chars:sub(i, i)] = i - 1 end

local function b64decode(data)
  data = data:gsub("[^" .. b64chars .. "=]", "")
  local out = {}
  local i = 1
  while i <= #data do
    local c1 = b64map[data:sub(i, i)] or 0
    local c2 = b64map[data:sub(i + 1, i + 1)] or 0
    local c3 = b64map[data:sub(i + 2, i + 2)] or 0
    local c4 = b64map[data:sub(i + 3, i + 3)] or 0
    local n = c1 * 262144 + c2 * 4096 + c3 * 64 + c4
    local b1 = math.floor(n / 65536) % 256
    local b2 = math.floor(n / 256) % 256
    local b3 = n % 256
    table.insert(out, string.char(b1))
    if data:sub(i + 2, i + 2) ~= "=" then table.insert(out, string.char(b2)) end
    if data:sub(i + 3, i + 3) ~= "=" then table.insert(out, string.char(b3)) end
    i = i + 4
  end
  return table.concat(out)
end

local function xorDecrypt(blob, key)
  local res = {}
  for i = 1, #blob do
    local b = blob:byte(i)
    local k = key:byte(((i - 1) % #key) + 1)
    res[i] = string.char(bit32.bxor(b, k))
  end
  return table.concat(res)
end

local blob = game:HttpGet(URL)
local src = xorDecrypt(b64decode(blob), KEY)
loadstring(src)()
