const SKIP_SCHEMES = ["chrome://", "chrome-extension://", "edge://", "about:", "moz-extension://", "file://"];

function shouldSkip(url) {
    return !url || SKIP_SCHEMES.some(s => url.startsWith(s));
}

chrome.tabs.query({ active: true, currentWindow: true }, function (tabs) {
    const currentUrl = tabs[0]?.url;

    const urlEl = document.getElementById("url-text");
    urlEl.textContent = currentUrl?.length > 60
        ? currentUrl.slice(0, 60) + "…"
        : currentUrl || "(no URL)";

    if (shouldSkip(currentUrl)) {
        showResult({ score: 10, status: "Safe", note: "Internal browser page" });
        return;
    }

    fetch(`https://phishdect.ddns.net/analyze?url=${encodeURIComponent(currentUrl)}`, {
        signal: AbortSignal.timeout(8000)
    })
        .then(res => res.json())
        .then(data => {
            if (data.error) showError();
            else showResult(data);
        })
        .catch(() => showError());
});

function showResult(data) {
    document.getElementById("loading").style.display = "none";
    document.getElementById("result").style.display = "block";

    const score = data.score ?? 0;
    const status = data.status ?? "Unknown";

    const scoreSection = document.getElementById("score-section");
    scoreSection.className = "score-ring " + status.toLowerCase();
    document.getElementById("score-num").textContent = score;

    const badge = document.getElementById("status-badge");
    badge.textContent = status === "Safe" ? "✅  Safe" :
                        status === "Suspicious" ? "⚠️  Suspicious" :
                        "🚨  Phishing Detected";
    badge.className = "status-badge";

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

    // ✅ SHOW REPORT BUTTON
    showReportButton();
}

function showError() {
    document.getElementById("loading").style.display = "none";
    document.getElementById("error-box").style.display = "block";
}

/* =========================
   🔥 COMMUNITY REPORT FEATURE
========================= */

function showReportButton() {
    const section = document.getElementById("report-section");
    if (section) section.style.display = "block";
}

document.addEventListener("DOMContentLoaded", () => {
    const btn = document.getElementById("report-btn");
    if (!btn) return;

    btn.addEventListener("click", async () => {
        chrome.tabs.query({ active: true, currentWindow: true }, async (tabs) => {
            const url = tabs[0]?.url;
            if (!url) return;

            btn.disabled = true;
            btn.textContent = "Reporting...";

            try {
                const res = await fetch("https://phishdect.ddns.net/report", {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({ url, note: "User reported via extension" })
                });

                const data = await res.json();

                if (data.status === "reported") {
                    btn.style.display = "none";
                    document.getElementById("report-msg").style.display = "block";
                }
            } catch (e) {
                btn.textContent = "👎 Report as Phishing";
                btn.disabled = false;
            }
        });
    });
});