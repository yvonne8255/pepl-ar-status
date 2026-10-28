const crypto = require("crypto");
const { sign } = require("../lib/session");

module.exports = (req, res) => {
  const id = process.env.GOOGLE_OAUTH_CLIENT_ID;
  if (!id) return res.status(500).send("Login is not configured yet.");
  const host = req.headers["x-forwarded-host"] || req.headers.host;
  const redirect = `https://${host}/api/callback`;
  const state = sign({ n: crypto.randomBytes(8).toString("hex"), exp: Math.floor(Date.now() / 1000) + 600 });
  res.setHeader("Set-Cookie", `pepl_state=${state}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=600`);
  const q = new URLSearchParams({
    client_id: id, redirect_uri: redirect, response_type: "code",
    scope: "openid email", state, prompt: "select_account",
  });
  res.writeHead(302, { Location: "https://accounts.google.com/o/oauth2/v2/auth?" + q });
  res.end();
};
