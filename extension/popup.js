const SKIP_SCHEMES = ["chrome://", "chrome-extension://", "edge://", "about:", "moz-extension://", "file://"];

function shouldSkip(url) {
    return !url || SKIP_SCHEMES.some(s => url.startsWith(s));
}

chrome.tabs.query({ active: true, currentWindow: true }, function (tabs) {
    const currentUrl = tabs[0]?.url;

    // Show URL truncated
    const urlEl = document.getElementById("url-text");
    urlEl.textContent = currentUrl?.length > 60
        ? currentUrl.slice(0, 60) + "…"
        : currentUrl || "(no URL)";

    if (shouldSkip(currentUrl)) {
        showResult({
            score: 10,
            status: "Safe",
            note: "Internal browser page"
        });
        return;
    }

    fetch(`http://127.0.0.1:5000/analyze?url=${encodeURIComponent(currentUrl)}`, {
        signal: AbortSignal.timeout(8000)
    })
        .then(res => res.json())
        .then(data => {
            if (data.error) {
                showError();
            } else {
                showResult(data);
            }
        })
        .catch(() => showError());
});


function showResult(data) {
    document.getElementById("loading").style.display = "none";
    document.getElementById("result").style.display = "block";

    const score = data.score ?? 0;
    const status = data.status ?? "Unknown";

    // Apply color class
    const scoreSection = document.getElementById("score-section");
    scoreSection.className = "score-ring " + status.toLowerCase();

    document.getElementById("score-num").textContent = score;

    const badge = document.getElementById("status-badge");
    badge.textContent = status === "Safe" ? "✅  Safe" :
                        status === "Suspicious" ? "⚠️  Suspicious" :
                        "🚨  Phishing Detected";
    badge.className = "status-badge";

    // Details row
    const detailsEl = document.getElementById("details");
    const items = [];

    if (data.ml_confidence !== undefined) {
        items.push({ key: "Phish Probability", value: data.ml_confidence + "%" });
    }

    if (data.domain_age_days !== undefined && data.domain_age_days !== null) {
        const age = data.domain_age_days;
        const ageStr = age === 0 ? "Unknown" :
                       age < 30 ? age + "d 🔴" :
                       age < 365 ? Math.floor(age / 30) + "mo" :
                       Math.floor(age / 365) + "yr";
        items.push({ key: "Domain Age", value: ageStr });
    }

    detailsEl.innerHTML = items.map(i => `
        <div class="detail-item">
            <div class="detail-value">${i.value}</div>
            <div class="detail-key">${i.key}</div>
        </div>
    `).join("");
}

function showError() {
    document.getElementById("loading").style.display = "none";
    document.getElementById("error-box").style.display = "block";
}
