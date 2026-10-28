const { checkPassword, setSession } = require("../lib/session");

const page = (err) => `<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>PEPL AR Status</title><body style="font:14px Calibri,Carlito,Arial,sans-serif;background:#eef1f5;display:flex;min-height:100vh;align-items:center;justify-content:center;margin:0">
<form method="POST" action="/api/login" style="background:#fff;border:1px solid #cbd2db;border-radius:8px;padding:28px;width:320px;margin:16px">
<h2 style="margin:0 0 14px;font-size:16px">PEPL AR Status</h2>
<input type="password" name="password" placeholder="Password" autofocus required style="width:100%;box-sizing:border-box;padding:9px;border:1px solid #cbd2db;border-radius:6px;font:inherit;margin-bottom:10px">
${err ? '<p style="color:#b42318;margin:0 0 10px">Wrong password.</p>' : ""}
<button style="width:100%;padding:9px;border:0;border-radius:6px;background:#0b5a8c;color:#fff;font:inherit;cursor:pointer">Sign in</button></form>`;

module.exports = async (req, res) => {
  res.setHeader("Cache-Control", "no-store");
  res.setHeader("Content-Type", "text/html; charset=utf-8");
  if (!process.env.SITE_PASSWORD || !process.env.AUTH_SECRET) return res.status(500).send("Login is not configured yet.");
  if (req.method === "POST") {
    const body = req.body && typeof req.body === "object" ? req.body : {};
    if (checkPassword(body.password)) {
      setSession(res);
      res.writeHead(302, { Location: "/" });
      return res.end();
    }
    await new Promise((r) => setTimeout(r, 1000)); // slow down guessing
    return res.status(401).send(page(true));
  }
  res.status(200).send(page(false));
};
