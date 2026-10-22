// Talks to the scanner API, caches verdicts, and wires up the context menu.
const DEFAULTS = { api: "http://127.0.0.1:8006", apiKey: "" };
const CACHE_MS = 10 * 60 * 1000;
const cache = new Map();

async function settings() {
  return { ...DEFAULTS, ...(await chrome.storage.sync.get(["api", "apiKey"])) };
}

async function scan(path, body) {
  const key = path + JSON.stringify(body).slice(0, 2000);
  const hit = cache.get(key);
  if (hit && Date.now() - hit.at < CACHE_MS) return hit.verdict;
  const { api, apiKey } = await settings();
  const r = await fetch(api + path, {
    method: "POST",
    headers: { "Content-Type": "application/json", ...(apiKey ? { "X-API-Key": apiKey } : {}) },
    body: JSON.stringify(body),
  });
  if (!r.ok) throw new Error(`scanner error ${r.status}`);
  const verdict = await r.json();
  cache.set(key, { at: Date.now(), verdict });
  if (cache.size > 500) cache.delete(cache.keys().next().value);
  return verdict;
}

chrome.runtime.onMessage.addListener((msg, _sender, reply) => {
  const run = async () => {
    if (msg.type === "scan-link") return scan(msg.url.startsWith("upi:") ? "/v1/scan/upi" : "/v1/scan/url", { input: msg.url });
    if (msg.type === "scan-page") return scan("/v1/scan/page", { url: msg.url, html: msg.html });
    if (msg.type === "scan-text") return scan("/v1/scan", { input: msg.text });
    throw new Error("unknown request");
  };
  run().then((v) => reply({ ok: true, verdict: v }), (e) => reply({ ok: false, error: String(e.message || e) }));
  return true; // async reply
});

chrome.runtime.onInstalled.addListener(() => {
  chrome.contextMenus.create({ id: "check-link", title: "Check this link for scams", contexts: ["link"] });
  chrome.contextMenus.create({ id: "check-text", title: "Check selected text for scams", contexts: ["selection"] });
});

chrome.contextMenus.onClicked.addListener(async (info, tab) => {
  const input = info.menuItemId === "check-link" ? info.linkUrl : info.selectionText;
  try {
    const v = await scan(info.menuItemId === "check-link" ? "/v1/scan/url" : "/v1/scan", { input });
    chrome.tabs.sendMessage(tab.id, { type: "show-verdict", verdict: v, subject: input });
  } catch (e) {
    chrome.tabs.sendMessage(tab.id, { type: "show-error", error: String(e.message || e) });
  }
});
