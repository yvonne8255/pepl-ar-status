const { currentUser } = require("../lib/session");
const { getValues } = require("../lib/google");

// Only these spreadsheets may be read through this endpoint.
const ALLOWED_IDS = new Set([
  "1ugrcdSuh5tPEQ0kgFBaqZh-BfI3dXCWvyvX4X3VULr4",
  "1benIfpQNEmBE_TRhneGUmyUkHfjEs_DS8afpVSbEG0w",
  "1qKdjS2GGt54lg6eM1A2VHtfVj6NgWLBG6Y_ZR6KocsY",
]);

module.exports = async (req, res) => {
  res.setHeader("Cache-Control", "no-store");
  let user;
  try { user = currentUser(req); } catch (e) { return res.status(500).json({ error: "server_not_configured" }); }
  if (!user) return res.status(401).json({ error: "unauthorized" });
  const { id, range } = req.query;
  if (!ALLOWED_IDS.has(id) || !range || String(range).length > 100) return res.status(400).json({ error: "bad_request" });
  try {
    const out = await getValues(id, range);
    res.status(200).json({ range: out.range, values: out.values, storedAt: Date.now(), user });
  } catch (e) {
    res.status(e.status === 403 || e.status === 404 ? 502 : 500).json({ error: "sheet_error", detail: e.message });
  }
};
