// Offline tool: encode the real Lua source as LUA_B64 for the ENV (repo holds no source).
// Run: node tools/encrypt-source.js input.lua  -> prints LUA_B64 (copy into the Vercel ENV).
// Never commit the real Lua file or the output.
const fs = require("fs");
const path = process.argv[2];
if (!path) {
  console.error("Usage: node tools/encrypt-source.js <input.lua>");
  process.exit(1);
}
const src = fs.readFileSync(path, "utf8");
if (src.length < 5) { console.error("File too short."); process.exit(1); }
if (src.length > 400000) { console.error("File too large (>400KB)."); process.exit(1); }
console.log(Buffer.from(src, "utf8").toString("base64"));
