function extractFormData() {
  const titleMeta = document.querySelector('meta[itemprop="name"]');
  const descMeta = document.querySelector('meta[itemprop="description"]');

  const title = titleMeta ? titleMeta.content : document.title;
  let description = descMeta ? descMeta.content : "";
  // Google prefixes this field with a literal "Description\n" label - strip it.
  description = description.replace(/^Description\n/, "").trim();

  let questions = [];
  const scripts = document.querySelectorAll("script");
  for (const script of scripts) {
    const text = script.textContent || "";
    if (text.includes("FB_PUBLIC_LOAD_DATA_")) {
      try {
        const jsonText = text
          .trim()
          .replace(/^var FB_PUBLIC_LOAD_DATA_ = /, "")
          .replace(/;$/, "");
        const data = JSON.parse(jsonText);
        const rawQuestions = data?.[1]?.[1] || [];
        questions = rawQuestions
          .map((q) => q[1])
          .filter((text) => typeof text === "string" && text.trim().length > 0);
      } catch (e) {
        console.warn("Scam Analyzer: failed to parse form data", e);
      }
      break;
    }
  }

  return {
    form_url: window.location.href,
    title,
    description,
    questions,
  };
}

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === "GET_FORM_DATA") {
    sendResponse(extractFormData());
  }
  return true;
});