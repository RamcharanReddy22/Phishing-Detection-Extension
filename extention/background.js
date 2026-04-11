// ── Schemes to skip entirely ──────────────────────────────────────────────────
const SKIP_SCHEMES = ["chrome://", "chrome-extension://", "edge://", "about:", "moz-extension://", "file://"];

// ── In-memory result cache ────────────────────────────────────────────────────
const resultCache = {};

function shouldSkip(url) {
    if (!url) return true;
    return SKIP_SCHEMES.some(s => url.startsWith(s));
}

async function analyzeUrl(tabId, url) {
    if (shouldSkip(url)) return;

    // Use cache if available
    if (resultCache[url]) {
        applyResult(tabId, resultCache[url]);
        return;
    }

    try {
        const response = await fetch(
            `http://127.0.0.1:5000/analyze?url=${encodeURIComponent(url)}`,
            { signal: AbortSignal.timeout(8000) }   // 8s hard timeout
        );

        if (!response.ok) return;

        const data = await response.json();

        if (data.error) {
            console.warn("[PhishDetect] API error:", data.error);
            return;
        }

        // Cache result
        resultCache[url] = data;

        applyResult(tabId, data);

    } catch (err) {
        console.warn("[PhishDetect] Backend unreachable:", err.message);
    }
}

function applyResult(tabId, data) {
    const { score, status } = data;

    // Set badge color and text
    let color = "#4CAF50";   // green = safe
    let badgeText = "✓";

    if (status === "Suspicious") {
        color = "#FF9800";
        badgeText = "?";
    } else if (status === "Phishing") {
        color = "#F44336";
        badgeText = "!";
    }

    chrome.action.setBadgeText({ text: badgeText, tabId });
    chrome.action.setBadgeBackgroundColor({ color, tabId });

    // Only show blocking alert for confirmed phishing
    if (status === "Phishing") {
        chrome.scripting.executeScript({
            target: { tabId },
            func: (score, url) => {
                const proceed = confirm(
                    `⚠️ PHISHING WARNING\n\n` +
                    `Safety Score: ${score}/10\n` +
                    `URL: ${url}\n\n` +
                    `This site has been flagged as likely phishing.\n` +
                    `Click CANCEL to go back, or OK to proceed at your own risk.`
                );
                if (!proceed) {
                    history.back();
                }
            },
            args: [score, data.url]
        }).catch(() => {});
    }
}

// ── Listen for tab navigation ─────────────────────────────────────────────────
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
    if (changeInfo.status === "complete" && tab.url) {
        analyzeUrl(tabId, tab.url);
    }
});

// ── Clear cache periodically (every 10 minutes) ───────────────────────────────
setInterval(() => {
    const keys = Object.keys(resultCache);
    if (keys.length > 200) {
        // Remove oldest 100 entries
        keys.slice(0, 100).forEach(k => delete resultCache[k]);
    }
}, 10 * 60 * 1000);
