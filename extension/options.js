const fields = ["gemini", "groq", "safeBrowsing", "virustotal", "urlscan", "tavily"];

document.addEventListener("DOMContentLoaded", async () => {
  const stored = await new Promise((resolve) => chrome.storage.local.get(["byokKeys"], (d) => resolve(d.byokKeys || {})));
  for (const field of fields) {
    if (stored[field]) document.getElementById(field).value = stored[field];
  }
});

document.getElementById("saveBtn").addEventListener("click", () => {
  const keys = {};
  for (const field of fields) keys[field] = document.getElementById(field).value.trim();

  chrome.storage.local.set({ byokKeys: keys }, () => {
    const saved = document.getElementById("saved");
    saved.style.display = "inline";
    setTimeout(() => (saved.style.display = "none"), 1500);
  });

document.getElementById("closeLink").addEventListener("click", (e) => {
  e.preventDefault();
  window.close();
});
});