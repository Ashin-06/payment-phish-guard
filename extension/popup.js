const esc = (s) => String(s ?? "").replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));
const ask = (msg) => new Promise((res) => chrome.runtime.sendMessage(msg, res));

function render(v) {
  const reasons = v.findings.filter((f) => f.weight > 0).slice(0, 4).map((f) => `<li>${esc(f.message)}</li>`).join("");
  return `<strong class="${v.level}">${v.level.toUpperCase()}</strong> · risk ${v.risk}/100${reasons ? `<ul>${reasons}</ul>` : ""}`;
}

chrome.tabs.query({ active: true, currentWindow: true }, async ([tab]) => {
  if (!tab || !/^https?:/.test(tab.url || "")) {
    document.getElementById("page").textContent = "Open a web page to check it.";
    return;
  }
  const res = await ask({ type: "scan-link", url: tab.url });
  document.getElementById("page").innerHTML = res && res.ok
    ? `This site: ${render(res.verdict)}`
    : `Scanner unreachable: ${esc(res && res.error)}. Is the API running?`;
});

document.getElementById("go").addEventListener("click", async () => {
  const text = document.getElementById("text").value.trim();
  if (!text) return;
  document.getElementById("out").textContent = "Checking…";
  const res = await ask({ type: "scan-text", text });
  document.getElementById("out").innerHTML = res && res.ok ? render(res.verdict) + `<p>${esc(res.verdict.advice)}</p>` : esc(res && res.error);
});
