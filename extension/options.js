chrome.storage.sync.get(["api", "apiKey"], (s) => {
  document.getElementById("api").value = s.api || "http://127.0.0.1:8006";
  document.getElementById("key").value = s.apiKey || "";
});
document.getElementById("save").addEventListener("click", () => {
  const api = document.getElementById("api").value.trim().replace(/\/$/, "") || "http://127.0.0.1:8006";
  chrome.storage.sync.set({ api, apiKey: document.getElementById("key").value.trim() }, () => {
    document.getElementById("saved").textContent = "Saved";
    setTimeout(() => (document.getElementById("saved").textContent = ""), 1500);
  });
});
