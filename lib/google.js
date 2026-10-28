const crypto = require("crypto");
const SCOPE = "https://www.googleapis.com/auth/spreadsheets.readonly";
let cached = null; // {token, exp}

function creds() {
  const raw = process.env.GOOGLE_SERVICE_ACCOUNT_JSON;
  if (!raw) throw new Error("GOOGLE_SERVICE_ACCOUNT_JSON not set");
  let j;
  try { j = JSON.parse(raw); } catch (e) { j = JSON.parse(Buffer.from(raw, "base64").toString()); }
  return j;
}
async function accessToken() {
  const now = Math.floor(Date.now() / 1000);
  if (cached && cached.exp - 60 > now) return cached.token;
  const c = creds();
  const b64 = (o) => Buffer.from(JSON.stringify(o)).toString("base64url");
  const unsigned = b64({ alg: "RS256", typ: "JWT" }) + "." +
    b64({ iss: c.client_email, scope: SCOPE, aud: "https://oauth2.googleapis.com/token", iat: now, exp: now + 3600 });
  const sig = crypto.createSign("RSA-SHA256").update(unsigned).sign(c.private_key).toString("base64url");
  const r = await fetch("https://oauth2.googleapis.com/token", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer", assertion: unsigned + "." + sig }),
  });
  const j = await r.json();
  if (!r.ok) throw new Error("token_error " + (j.error || r.status));
  cached = { token: j.access_token, exp: now + (j.expires_in || 3600) };
  return cached.token;
}
async function getValues(spreadsheetId, range) {
  const t = await accessToken();
  const url = `https://sheets.googleapis.com/v4/spreadsheets/${encodeURIComponent(spreadsheetId)}/values/${encodeURIComponent(range)}?valueRenderOption=FORMATTED_VALUE`;
  const r = await fetch(url, { headers: { Authorization: "Bearer " + t } });
  const j = await r.json();
  if (!r.ok) { const e = new Error((j.error && j.error.message) || "sheets_error"); e.status = r.status; throw e; }
  return { range: j.range, values: j.values || [] };
}
module.exports = { getValues };
