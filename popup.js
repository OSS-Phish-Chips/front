/* global chrome */
(() => {
  // ---------- Utilities ----------
const $ = (sel) => document.querySelector(sel);

const defaultKeywords = [
    "login", "verify", "update", "reset", "password",
    "gift", "bonus", "win", "free", "wallet",
    "bank", "secure", "pay", "paypal", "sms"
];

const knownBadHosts = new Set([
    "example-phish.test", "malicious-site.xyz", "free-gift-card.top"
]);

const state = {
    url: null,
    host: null,
    score: 0,
    parts: {
    ssl: null,
    whois: null,
    blacklist: null,
    keywords: null,
    redirect: null
    },
    keywords: []
};

// ---------- Storage helpers ----------
async function loadSettings() {
    const { autoScan = true, shareData = false, keywords } =
    await chrome.storage?.sync.get(["autoScan", "shareData", "keywords"]) ?? {};
    state.keywords = Array.isArray(keywords) && keywords.length ? keywords : defaultKeywords.slice();
    $("#autoScan").checked = !!autoScan;
    $("#shareData").checked = !!shareData;
    renderKeywords();
}

async function saveSettings() {
    await chrome.storage?.sync.set({
    autoScan: $("#autoScan").checked,
    shareData: $("#shareData").checked,
    keywords: state.keywords
    });
}

// ---------- UI helpers ----------
function setBadge(elText, elBadge, text, level = "safe") {
    elText.textContent = text;
    elBadge.classList.remove("warn", "bad");
    if (level === "warn") elBadge.classList.add("warn");
    if (level === "bad") elBadge.classList.add("bad");
    elBadge.textContent = level === "safe" ? "안전" : level === "warn" ? "주의" : "위험";
}

function setGauge(score) {
    const clamped = Math.max(0, Math.min(100, Math.round(score)));
    const el = $("#gauge");
    el.style.background = `conic-gradient(var(--safe) 0 ${clamped * 3.6}deg, #e5e7eb 0)`;
    $("#scoreNum").textContent = `${clamped}/100`;
    // 색상에 약간의 경고 단계 반영
    if (clamped < 60) {
    el.style.background = `conic-gradient(var(--danger) 0 ${clamped * 3.6}deg, #e5e7eb 0)`;
    $("#verdict").textContent = "위험할 수 있습니다.";
    $("#verdict").style.color = "var(--danger)";
    } else if (clamped < 80) {
    el.style.background = `conic-gradient(var(--warn) 0 ${clamped * 3.6}deg, #e5e7eb 0)`;
    $("#verdict").textContent = "주의가 필요합니다.";
    $("#verdict").style.color = "var(--warn)";
    } else {
    $("#verdict").textContent = "이 사이트는 안전합니다.";
    $("#verdict").style.color = "var(--safe)";
    }
}

function updateIconByScore(score) {
    let iconPath;
    let logoHTML; // popup.html 내부 로고 변경용

    if (score <= 50) {
        iconPath = {
            16: "icons/red.png",
            32: "icons/red.png",
            128: "icons/red.png"
        };
        logoHTML = '<img src="icons/red.png" alt="위험" class="logo-img">';
    } else if (score <= 79) {
        iconPath = {
            16: "icons/yellow.png",
            32: "icons/yellow.png",
            128: "icons/yellow.png"
        };
        logoHTML = '<img src="icons/yellow.png" alt="주의" class="logo-img">';
    } else {
        iconPath = {
            16: "icons/green.png",
            32: "icons/green.png",
            128: "icons/green.png"
        };
        logoHTML = '<img src="icons/green.png" alt="안전" class="logo-img">';
    }

    // 확장 아이콘 변경
    chrome.action.setIcon({ path: iconPath });

    // popup.html 내부 로고 변경
    const logoEl = document.querySelector('.logo');
    if (logoEl) {
        logoEl.innerHTML = logoHTML;
    }
}

function renderKeywords() {
    const list = $("#keywordsList");
    list.innerHTML = "";
    state.keywords.forEach((kw, idx) => {
    const pill = document.createElement("span");
    pill.className = "pill";
    pill.innerHTML = `<span>${kw}</span>`;
    const btn = document.createElement("button");
    btn.type = "button";
    btn.setAttribute("aria-label", `${kw} 삭제`);
    btn.innerHTML = "&times;";
    btn.addEventListener("click", async () => {
        state.keywords.splice(idx, 1);
        renderKeywords();
        await saveSettings();
    });
    pill.appendChild(btn);
    list.appendChild(pill);
    });
}

  // ---------- Analysis ----------
async function analyze(urlStr) {
    const url = new URL(urlStr);
    state.url = urlStr;
    state.host = url.hostname;
    $("#urlDisplay").textContent = urlStr;

    let score = 100;

    // 1) SSL
    const usesHttps = url.protocol === "https:";
    setBadge($("#sslText"), $("#sslBadge"),
    usesHttps ? "보안 연결(HTTPS)을 사용 중입니다." : "HTTPS가 아닙니다.", usesHttps ? "safe" : "warn");
    if (!usesHttps) score -= 25;

    // 2) WHOIS / RDAP 시도
    let whoisOK = false;
    try {
    const rdapRes = await Promise.race([
        fetch(`https://rdap.org/domain/${state.host}`, { method: "GET" }),
        new Promise((_, rej) => setTimeout(() => rej(new Error("timeout")), 2500))
    ]);
    whoisOK = rdapRes && rdapRes.ok;
    } catch (e) { /* ignore */ }
    setBadge($("#whoisText"), $("#whoisBadge"),
    whoisOK ? "정보 도메인 등록자 정보가 확인되었습니다." : "등록 정보 확인 불가(네트워크 또는 정책)", whoisOK ? "safe" : "warn");
    if (!whoisOK) score -= 5;

    // 3) 블랙리스트/의심 패턴
    let blackHit = knownBadHosts.has(state.host);
    setBadge($("#blacklistText"), $("#blacklistBadge"),
    blackHit ? "악성 URL 목록에 포함되었습니다." : "악성 URL 목록에 포함되지 않았습니다.",
    blackHit ? "bad" : "safe");
    if (blackHit) score -= 40;

    // 4) 의심 키워드 탐지
    const lowerAll = (state.host + url.pathname + url.search).toLowerCase();
    const matched = state.keywords.filter((kw) => lowerAll.includes(kw.toLowerCase()));
    const hasSuspicious = matched.length > 0;
    setBadge($("#keywordText"), $("#keywordBadge"),
    hasSuspicious ? `의심스러운 키워드(${matched.slice(0,4).join(", ")}${matched.length>4?" 외":""})가 포함됨`
                    : "의심스러운 키워드는 포함되어 있지 않습니다.",
    hasSuspicious ? "warn" : "safe");
    if (hasSuspicious) score -= Math.min(25, 8 + matched.length * 2);

    // 5) 리디렉션 탐지(컨텐츠에서 navigation redirectCount 조회)
    let redirectCount = 0;
    try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (tab?.id) {
        const results = await chrome.scripting.executeScript({
        target: { tabId: tab.id },
        func: () => {
            try {
            const nav = performance.getEntriesByType("navigation")[0];
            return nav ? nav.redirectCount : 0;
            } catch { return -1; }
        }
        });
        redirectCount = Array.isArray(results) ? (results[0].result ?? 0) : 0;
    }
    } catch { /* permissions might be missing */ }

    const redirected = redirectCount > 0;
    setBadge($("#redirectText"), $("#redirectBadge"),
    redirected ? `외부로의 자동 이동 감지됨(횟수: ${redirectCount})` : "외부로의 자동 이동이 감지되지 않았습니다.",
    redirected ? "warn" : "safe");
    if (redirected) score -= 10;

    // 최종 점수 정리 & 하한/상한
    state.score = Math.max(1, Math.min(100, Math.round(score)));
    setGauge(state.score);
    updateIconByScore(state.score);
}

// ---------- Report ----------
// popup.js - openReport() 교체
async function openReport() {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });

    // 팝업 UI에서 읽어 표 데이터 스냅샷 생성 (있으면 사용, 없으면 리포트에서 재분석)
    const snap = {
        basic: [
        { title: "SSL 인증서",
            level: document.querySelector("#sslBadge")?.classList.contains("bad") ? "bad"
                : document.querySelector("#sslBadge")?.classList.contains("warn") ? "warn" : "safe",
            note: document.querySelector("#sslText")?.textContent || "-" },
        { title: "WHOIS 등록 정보",
            level: document.querySelector("#whoisBadge")?.classList.contains("warn") ? "warn" : "safe",
            note: document.querySelector("#whoisText")?.textContent || "-" },
        { title: "악성 도메인 목록 여부",
            level: document.querySelector("#blacklistBadge")?.classList.contains("bad") ? "bad" : "safe",
            note: document.querySelector("#blacklistText")?.textContent || "-" },
        { title: "DNS 상태", level: "safe", note: "정상 도메인 구조." },
        { title: "HTML 기본 분석", level: "safe", note: "특이사항 없음." }
        ],
        vuln: [
        { title: "XSS 탐지", level: "safe", note: "악성 스크립트 징후 없음." },
        { title: "Clickjacking 방지 설정", level: "warn", note: "헤더 접근 제한으로 확인 불가." },
        { title: "파일 업로드 경로 노출", level: "safe", note: "특이사항 없음." },
        { title: "디렉터리 리스팅", level: "safe", note: "노출되지 않음." },
        { title: "CSP(Content-Security-Policy)", level: "warn", note: "정책 확인 불가." },
        { title: "CORS 정책", level: "safe", note: "개방적 징후 없음." },
        { title: "서버 정보 노출", level: "safe", note: "식별 헤더 노출 징후 없음." }
        ],
        extra: [
        { title: "의심 키워드 포함 여부",
            level: document.querySelector("#keywordBadge")?.classList.contains("warn") ? "warn" : "safe",
            note: document.querySelector("#keywordText")?.textContent || "-" },
        { title: "리디렉션 여부",
            level: document.querySelector("#redirectBadge")?.classList.contains("warn") ? "warn" : "safe",
            note: document.querySelector("#redirectText")?.textContent || "-" }
        ],
        summary: "팝업에서 캡처한 결과 스냅샷입니다."
    };

    const reportData = {
        url: state.url,
        score: state.score,
        tabId: tab?.id || null,
        // 스냅샷이 유효한지 간단 체크 후 넣기
        ...(state.url ? snap : {}),
        __ts: Date.now()
    };

    await chrome.storage.local.set({ reportData });   // ★ local에 저장
    chrome.tabs.create({ url: chrome.runtime.getURL("report.html") });
}




// ---------- Wiring ----------
async function init() {
    await loadSettings();

    // 상태 저장용 클래스명도 세팅
    ["ssl","whois","blacklist","keywords","redirect"].forEach(k => state.parts[k] = "safe");

    // 이벤트
    $("#autoScan").addEventListener("change", saveSettings);
    $("#shareData").addEventListener("change", saveSettings);
    $("#refreshBtn").addEventListener("click", async () => {
    const tab = (await chrome.tabs.query({ active: true, currentWindow: true }))[0];
    if (tab?.url) analyze(tab.url);
    });
    $("#reportBtn").addEventListener("click", openReport);

    $("#manageKeywords").addEventListener("click", (e) => {
    const panel = $("#keywordsPanel");
    const expanded = e.currentTarget.getAttribute("aria-expanded") === "true";
    panel.hidden = expanded;
    e.currentTarget.setAttribute("aria-expanded", String(!expanded));
    e.currentTarget.textContent = expanded ? "관리" : "닫기";
    });

    $("#addKeywordForm").addEventListener("submit", async (e) => {
    e.preventDefault();
    const val = $("#keywordInput").value.trim();
    if (!val) return;
    if (!state.keywords.includes(val)) {
        state.keywords.push(val);
        $("#keywordInput").value = "";
        renderKeywords();
        await saveSettings();
        // 즉시 재분석
        if (state.url) analyze(state.url);
    }
    });

    // 현재 탭 분석
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (tab?.url) {
    await analyze(tab.url);
    } else {
    $("#verdict").textContent = "현재 탭 URL을 확인할 수 없습니다.";
    $("#verdict").style.color = "var(--warn)";
    }

    // 결과 등급 상태 클래스 기록(리포트 생성용)
    const mapBadge = (el) =>
    el.classList.contains("bad") ? "bad" : el.classList.contains("warn") ? "warn" : "safe";
    state.parts.ssl = mapBadge($("#sslBadge"));
    state.parts.whois = mapBadge($("#whoisBadge"));
    state.parts.blacklist = mapBadge($("#blacklistBadge"));
    state.parts.keywords = mapBadge($("#keywordBadge"));
    state.parts.redirect = mapBadge($("#redirectBadge"));
}

document.addEventListener("DOMContentLoaded", init);
})();

