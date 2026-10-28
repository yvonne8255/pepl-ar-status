const crypto = require("crypto");
const COOKIE = "pepl_session";
const MAX_AGE = 60 * 60 * 12; // 12 hours

function secret() {
  const s = process.env.AUTH_SECRET;
  if (!s || s.length < 16) throw new Error("AUTH_SECRET missing or too short");
  return s;
}
const b64 = (b) => Buffer.from(b).toString("base64url");
function sign(payload) {
  const body = b64(JSON.stringify(payload));
  const mac = crypto.createHmac("sha256", secret()).update(body).digest("base64url");
  return body + "." + mac;
}
function verify(token) {
  if (!token || token.indexOf(".") < 0) return null;
  const [body, mac] = token.split(".");
  const exp = crypto.createHmac("sha256", secret()).update(body).digest("base64url");
  const a = Buffer.from(mac), b = Buffer.from(exp);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;
  try {
    const p = JSON.parse(Buffer.from(body, "base64url").toString());
    if (!p.exp || p.exp < Date.now() / 1000) return null;
    return p;
  } catch (e) { return null; }
}
function parseCookies(req) {
  const out = {};
  (req.headers.cookie || "").split(";").forEach((c) => {
    const i = c.indexOf("=");
    if (i > 0) out[c.slice(0, i).trim()] = decodeURIComponent(c.slice(i + 1).trim());
  });
  return out;
}
// Shared-password mode. Changing SITE_PASSWORD invalidates every existing session.
function pwTag() {
  return crypto.createHash("sha256").update("pepl|" + (process.env.SITE_PASSWORD || "")).digest("hex").slice(0, 12);
}
function checkPassword(input) {
  const pw = process.env.SITE_PASSWORD;
  if (!pw) return false;
  const a = crypto.createHash("sha256").update(String(input || "")).digest();
  const b = crypto.createHash("sha256").update(pw).digest();
  return crypto.timingSafeEqual(a, b);
}

function setSession(res) {
  const token = sign({ pv: pwTag(), exp: Math.floor(Date.now() / 1000) + MAX_AGE });
  res.setHeader("Set-Cookie", `${COOKIE}=${token}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${MAX_AGE}`);
}
function clearSession(res) {
  res.setHeader("Set-Cookie", `${COOKIE}=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0`);
}
function currentUser(req) {
  const p = verify(parseCookies(req)[COOKIE]);
  return p && process.env.SITE_PASSWORD && p.pv === pwTag() ? "viewer" : null;
}
module.exports = { sign, verify, parseCookies, checkPassword, setSession, clearSession, currentUser };
