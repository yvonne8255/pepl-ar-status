const { verify, parseCookies, isAllowed, setSession } = require("../lib/session");

const page = (title, msg) => `<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>PEPL AR Status</title><body style="font:14px Calibri,Carlito,Arial,sans-serif;background:#eef1f5;display:flex;min-height:100vh;align-items:center;justify-content:center;margin:0">
<div style="background:#fff;border:1px solid #cbd2db;border-radius:8px;padding:28px;max-width:420px;margin:16px"><h2 style="margin:0 0 10px;font-size:16px">${title}</h2><p style="margin:0 0 14px;line-height:1.5">${msg}</p><a href="/api/logout" style="color:#0b5a8c">Sign in with another account</a></div>`;

module.exports = async (req, res) => {
  res.setHeader("Cache-Control", "no-store");
  const { code, state } = req.query;
  const cookieState = parseCookies(req).pepl_state;
  if (!code || !state || state !== cookieState || !verify(state)) return res.status(400).send(page("Sign-in failed", "Please try again."));
  const host = req.headers["x-forwarded-host"] || req.headers.host;
  const r = await fetch("https://oauth2.googleapis.com/token", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      code, client_id: process.env.GOOGLE_OAUTH_CLIENT_ID, client_secret: process.env.GOOGLE_OAUTH_CLIENT_SECRET,
      redirect_uri: `https://${host}/api/callback`, grant_type: "authorization_code",
    }),
  });
  const j = await r.json();
  if (!r.ok || !j.id_token) return res.status(400).send(page("Sign-in failed", "Please try again."));
  // id_token came straight from Google over TLS in exchange for our own code.
  let claims;
  try { claims = JSON.parse(Buffer.from(j.id_token.split(".")[1], "base64url").toString()); } catch (e) { return res.status(400).send(page("Sign-in failed", "Please try again.")); }
  if (!claims.email || claims.email_verified !== true) return res.status(403).send(page("Email not verified", "Google could not verify this email address."));
  if (!isAllowed(claims.email)) {
    const esc = String(claims.email).replace(/[<>&"]/g, "");
    return res.status(403).send(page("No access", `${esc} is not on the access list. Please ask Yvonne (yvonne@pollisum.com) to add your email.`));
  }
  setSession(res, claims.email);
  res.writeHead(302, { Location: "/" });
  res.end();
};
