// Checks links before they open, and the page itself when it asks for credentials.
(() => {
  const host = location.hostname;
  const ask = (msg) => new Promise((res) => chrome.runtime.sendMessage(msg, res));
  const esc = (v) => String(v ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

  function overlay(verdict, subject, onProceed) {
    document.getElementById("scamcheck-overlay")?.remove();
    const wrap = document.createElement("div");
    wrap.id = "scamcheck-overlay";
    const root = wrap.attachShadow({ mode: "closed" });
    const danger = verdict.level === "dangerous";
    const reasons = verdict.findings.filter((f) => f.weight > 0).slice(0, 5)
      .map((f) => `<li>${esc(f.message)}</li>`).join("");
    root.innerHTML = `
      <style>
        .bg{position:fixed;inset:0;background:rgba(10,12,16,.6);z-index:2147483647;display:grid;place-items:center;font:15px/1.5 system-ui,sans-serif}
        .box{background:#fff;color:#14181d;max-width:520px;width:calc(100% - 32px);border-radius:14px;padding:22px;box-shadow:0 20px 60px rgba(0,0,0,.35)}
        h2{margin:0 0 6px;font-size:20px;color:${danger ? "#c62828" : "#b36b00"}}
        .s{color:#5d6774;word-break:break-all;font-size:13px;margin-bottom:10px}
        ul{padding-left:18px;margin:8px 0 12px} .a{background:#f2f4f7;border-radius:8px;padding:10px;font-size:14px}
        .row{display:flex;gap:10px;justify-content:flex-end;margin-top:16px}
        button{font:inherit;font-weight:600;border:0;border-radius:8px;padding:9px 14px;cursor:pointer}
        .back{background:#0f6fde;color:#fff} .go{background:transparent;color:#5d6774;text-decoration:underline}
      </style>
      <div class="bg"><div class="box" role="alertdialog" aria-modal="true">
        <h2>${danger ? "This looks like a scam" : "Be careful with this"} (risk ${esc(verdict.risk)}/100)</h2>
        <div class="s">${esc(String(subject).slice(0, 200))}</div>
        <ul>${reasons}</ul>
        <div class="a">${esc(verdict.advice)}</div>
        <div class="row">${onProceed ? '<button class="go">Open anyway</button>' : ""}<button class="back">${onProceed ? "Go back to safety" : "Close"}</button></div>
      </div></div>`;
    root.querySelector(".back").onclick = () => wrap.remove();
    const go = root.querySelector(".go");
    if (go) go.onclick = () => { wrap.remove(); onProceed(); };
    document.documentElement.appendChild(wrap);
  }

  // 1. links: check external and UPI links on click; open normally when safe
  document.addEventListener("click", async (ev) => {
    if (ev.defaultPrevented || ev.button !== 0) return;
    const a = ev.target.closest && ev.target.closest("a[href]");
    if (!a || a.dataset.scamcheckOk) return;
    const href = a.href;
    const upi = href.startsWith("upi:");
    let external = false;
    try { external = /^https?:/.test(href) && new URL(href).hostname !== host; } catch { return; }
    if (!upi && !external) return;
    ev.preventDefault();
    ev.stopPropagation();
    const res = await ask({ type: "scan-link", url: href });
    const open = () => { a.dataset.scamcheckOk = "1"; a.click(); delete a.dataset.scamcheckOk; };
    if (!res || !res.ok || res.verdict.level === "safe") return open(); // fail open: never break browsing
    overlay(res.verdict, href, open);
  }, true);

  // 2. this page: only when it asks for passwords, OTPs, card or UPI details
  const sensitive = () => document.querySelector('input[type=password], input[name*=otp i], input[placeholder*=otp i], ' +
    'input[name*=card i], input[placeholder*="upi pin" i], input[autocomplete=cc-number]');
  let checked = false;
  async function checkPage() {
    if (checked || !sensitive()) return;
    checked = true;
    const res = await ask({ type: "scan-page", url: location.href, html: document.documentElement.outerHTML.slice(0, 1_500_000) });
    if (res && res.ok && res.verdict.level !== "safe") overlay(res.verdict, location.href, null);
  }
  checkPage();
  new MutationObserver(() => checkPage()).observe(document.documentElement, { childList: true, subtree: true });

  // 3. results from the context menu
  chrome.runtime.onMessage.addListener((msg) => {
    if (msg.type === "show-verdict") overlay(msg.verdict, msg.subject, null);
    if (msg.type === "show-error") alert("Scam Check: " + msg.error);
  });
})();
