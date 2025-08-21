/* global chrome */
(() => {
  const DEMO_URL = "https://www.sookmyung.ac.kr/kr/index.do";
  const $ = (sel) => document.querySelector(sel);


  // url Display
  const setUrlDisplay = (val) => {
    const el = document.querySelector("#urlDisplay");
    if (el) el.textContent = val;
  };

  /// Machine learning
  const ML_API = "http://127.0.0.1:8000";

  async function runMlDetect(targetUrl) {
    const ctrl = new AbortController();
    const t = setTimeout(() => ctrl.abort(), 8000);
    try {
      const r = await fetch(`${ML_API}/predict?url=${encodeURIComponent(targetUrl)}`, { signal: ctrl.signal });
      clearTimeout(t);
      if (!r.ok) throw new Error(`ML ${r.status}`);
      return await r.json(); // { label, proba, features }
    } catch (e) {
      clearTimeout(t);
      throw e;
    }
  }

  async function applyMlBadge(targetUrl, mlResOptional) {
    try {
      const res = mlResOptional ?? await runMlDetect(targetUrl);
      const isPhish = Number(res.label) === 1;       // 1=악성
      const p = Math.round((res.proba || 0) * 100);  // 악성 확률(%)
      setBadge(
        document.querySelector("#blacklistText"),
        document.querySelector("#blacklistBadge"),
        isPhish ? `머신러닝 탐지: 악성(${p}%)` : `머신러닝 탐지: 정상(${100 - p}%)`,
        isPhish ? "bad" : "safe"
      );
      return res; // 호출자가 점수 합산에 재사용 가능
    } catch (e) {
      console.warn("ML detect failed:", e);
      setBadge(
        document.querySelector("#blacklistText"),
        document.querySelector("#blacklistBadge"),
        "머신러닝 탐지 실패(오프라인)", "warn"
      );
      return null;
    }
  }


  function clamp01(v){ return Math.max(0, Math.min(1, v)); }

  // ML에서 오는 proba가 "악성(1)일 확률"이라고 가정 → 안전 점수 = (1 - p_malicious) * 100
  function mlToScore(res){
    // res.proba가 숫자(악성확률)인 케이스
    if (typeof res?.proba === "number") {
      const pMal = clamp01(res.proba);
      return Math.round((1 - pMal) * 100);
    }
    // 혹시 확률 벡터/다른 키로 올 수 있는 케이스 대비(없으면 0으로)
    const pMal = clamp01(res?.p_phishing ?? res?.prob_phish ?? 0);
    return Math.round((1 - pMal) * 100);
  }

  // 백엔드/ML 점수를 0~100으로 통일해서 "최종 점수" 산출
  function unifyScoreFromBackendAndML(backendData, mlRes) {
    const backendScore = Math.max(0, Math.min(100, Number(backendData?.totalScore ?? backendData?.score) || 0));
    const mlScore = mlRes ? mlToScore(mlRes) : null; // mlToScore는 이미 있음
    return mlScore == null ? backendScore : Math.round((backendScore + mlScore) / 2);
  }


  // Security
  const API_BASE = 'http://127.0.0.1:3000';
  async function runBackendAnalyze(targetUrl) {
    const r = await fetch(`${API_BASE}/analyze?url=${encodeURIComponent(targetUrl)}`);
    if (!r.ok) throw new Error(`API ${r.status}`);
    return r.json(); // { totalScore, overallGrade, details: {...} }
  }

    // 중복 호출 방지용 in-flight 맵
  const analyzingByUrl = new Map();

  async function runBackendAnalyzeDedup(targetUrl) {
    if (analyzingByUrl.has(targetUrl)) return analyzingByUrl.get(targetUrl);
    const p = (async () => {
      try { return await runBackendAnalyze(targetUrl); }
      finally { analyzingByUrl.delete(targetUrl); }
    })();
    analyzingByUrl.set(targetUrl, p);
    return p;
  }

  function gradeToLevel(grade) {
    // 백엔드 등급 문자열 → 뱃지 레벨
    if (!grade) return "warn";
    if (grade.includes("위험")) return "bad";
    if (grade.includes("주의")) return "warn";
    return "safe"; // 양호 등
  }

  // 현재 탭의 redirectCount를 읽어서 리디렉션 여부 배지 갱신
  async function fillRedirectBadge() {
    try {
      const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
      if (!tab?.id) return;

      const results = await chrome.scripting.executeScript({
        target: { tabId: tab.id },
        func: () => {
          try {
            const nav = performance.getEntriesByType("navigation")[0];
            return nav ? nav.redirectCount : 0;
          } catch {
            return 0;
          }
        }
      });

      const redirectCount = Array.isArray(results) ? (results[0].result ?? 0) : 0;
      const redirected = redirectCount > 0;

      setBadge(
        document.querySelector("#redirectText"),
        document.querySelector("#redirectBadge"),
        redirected
          ? `외부로의 자동 이동 감지됨 (횟수: ${redirectCount})`
          : "외부로의 자동 이동이 감지되지 않았습니다.",
        redirected ? "warn" : "safe"
      );
    } catch (err) {
      console.error("리디렉션 검사 실패:", err);
      setBadge(
        document.querySelector("#redirectText"),
        document.querySelector("#redirectBadge"),
        "리디렉션 여부를 확인할 수 없습니다.",
        "warn"
      );
    }
  }


  function pickMessage(section) {
    // messages 타입이 배열(문자/객체 섞임)일 때 요약 문구 1줄 생성
    const msgs = section?.messages || [];
    if (!Array.isArray(msgs) || msgs.length === 0) return `${section?.grade || "정보"} 상태입니다.`;
    const first = msgs[0];
    if (typeof first === "string") return first;
    if (first?.issue) return first.issue;
    if (first?.note) return first.note;
    return `${section?.grade || "정보"} 상태입니다.`;
  }

  function convertBackendToReport(data, targetUrl) {
    // data: { totalScore, overallGrade, details: { ssl, whois, dns, header, vulnerability, url } }
    const d = data?.details || {};
    const toNote = (sec) => {
      const msgs = sec?.messages || [];
      if (!msgs.length) return sec?.grade || "-";
      const first = msgs[0];
      return typeof first === "string" ? first : (first.note || first.issue || JSON.stringify(first));
    };
    const toLevel = (sec) => gradeToLevel(sec?.grade || "");

    // 기본 보안 구성
    const basic = []
    if (d.ssl)     basic.push({ title: "SSL 인증서",     level: toLevel(d.ssl),     note: toNote(d.ssl) });
    if (d.whois)   basic.push({ title: "WHOIS 등록 정보", level: toLevel(d.whois),   note: toNote(d.whois) });
    if (d.dns)     basic.push({ title: "DNS 상태",        level: toLevel(d.dns),     note: toNote(d.dns) });
    if (d.header)  basic.push({ title: "HTTP 보안 헤더",  level: toLevel(d.header),  note: toNote(d.header) });

    // 취약점
    const vuln = [];
    if (d.vulnerability?.messages?.length) {
      for (const m of d.vulnerability.messages) {
        const note = typeof m === "string" ? m : (m.note || m.issue || JSON.stringify(m));
        vuln.push({
          title: m.title || "취약점 점검",
          level: toLevel(d.vulnerability),
          note
        });
      }
    } else if (d.vulnerability) {
      vuln.push({ title: "취약점 점검", level: toLevel(d.vulnerability), note: toNote(d.vulnerability) });
    }

    // 추가 분석(URL 규칙 등)
    const extra = [];
    if (d.url) {
      const first = d.url.messages?.[0];
      extra.push({
        title: "URL 규칙 기반 점검",
        level: toLevel(d.url),
        note: typeof first === "string" ? first : (first?.note || first?.issue || toNote(d.url))
      });
    }

    return {
      url: targetUrl,
      score: Math.max(1, Math.min(100, Number(data.totalScore) || 0)),
      basic,
      vuln,
      extra,
      // 아래 메타는 report 페이지의 “분석 기준 및 기술” 섹션에 그대로 사용됨
      tools: ["axios", "cheerio", "ssl-certificate", "whois-json", "Google Safe Browsing API"],
      analysisTypes: ["비접속 기반 정적 분석", "응답 기반 동적 분석"],
    };
  }

  function renderBackendBadges(details) {
    // 존재하는 UI 요소에 한해 백엔드 값을 우선 반영
    // 1) SSL
    if (details?.ssl) {
      const lvl = gradeToLevel(details.ssl.grade);
      setBadge($("#sslText"), $("#sslBadge"), pickMessage(details.ssl), lvl);
    }
    // 2) WHOIS
    if (details?.whois) {
      const lvl = gradeToLevel(details.whois.grade);
      setBadge($("#whoisText"), $("#whoisBadge"), pickMessage(details.whois), lvl);
    }
    // 2.5) 의심 키워드(= URL 규칙 결과를 매핑)
    if (details?.url) {
      const lvl = gradeToLevel(details.url.grade);
      setBadge($("#keywordText"), $("#keywordBadge"), pickMessage(details.url), lvl);
    }
    // 3) DNS (팝업에 #dnsBadge / #dnsText가 있다면 적용됨. 없으면 자동 무시)
    if (details?.dns && $("#dnsBadge")) {
      const lvl = gradeToLevel(details.dns.grade);
      setBadge($("#dnsText"), $("#dnsBadge"), pickMessage(details.dns), lvl);
    }
    // 4) 헤더/취약점 등도 동일 패턴(해당 요소가 있으면 반영)
    if (details?.header && $("#headerBadge")) {
      const lvl = gradeToLevel(details.header.grade);
      setBadge($("#headerText"), $("#headerBadge"), pickMessage(details.header), lvl);
    }
    if (details?.vulnerability && $("#vulnBadge")) {
      const lvl = gradeToLevel(details.vulnerability.grade);
      setBadge($("#vulnText"), $("#vulnBadge"), pickMessage(details.vulnerability), lvl);
    }
    // 참고: blacklist/keywords/redirect는 현재 로컬 전용이므로 그대로 두셔도 됩니다.
  }


  const defaultKeywords = [
    "login","verify","update","reset","password",
    "gift","bonus","win","free","wallet",
    "bank","secure","pay","paypal","sms"
  ];
  const knownBadHosts = new Set(["example-phish.test","malicious-site.xyz","free-gift-card.top"]);

  const state = {
    url: null, host: null, score: 0, isDemo: false,
    parts: { ssl:null, whois:null, blacklist:null, keywords:null, redirect:null },
    keywords: []
  };

  // ---- storage ----
  async function loadSettings() {
    const { autoScan = true, shareData = false, keywords } =
      (await chrome.storage?.sync.get(["autoScan","shareData","keywords"])) ?? {};
    state.keywords = Array.isArray(keywords) && keywords.length ? keywords : defaultKeywords.slice();
    $("#autoScan") && ($("#autoScan").checked = !!autoScan);
    $("#shareData") && ($("#shareData").checked = !!shareData);
    renderKeywords();
  }
  async function saveSettings() {
    await chrome.storage?.sync.set({
      autoScan: $("#autoScan")?.checked ?? true,
      shareData: $("#shareData")?.checked ?? false,
      keywords: state.keywords
    });
  }

  // ---- UI helpers ----
  function setBadge(elText, elBadge, text, level = "safe") {
    if (elText) elText.textContent = text;
    if (!elBadge) return;
    elBadge.classList.remove("warn","bad");
    if (level === "warn") elBadge.classList.add("warn");
    if (level === "bad")  elBadge.classList.add("bad");
    elBadge.textContent = level === "safe" ? "안전" : level === "warn" ? "주의" : "위험";
  }

  function setGauge(score) {
    const clamped = Math.max(0, Math.min(100, Math.round(score)));
    const el = $("#gauge");
    const angle = clamped * 3.6;
    let color = "var(--safe)", verdictText = "이 사이트는 안전합니다.";
    if (clamped < 60) { color = "var(--danger)"; verdictText = "위험할 수 있습니다."; }
    else if (clamped < 80) { color = "var(--warn)"; verdictText = "주의가 필요합니다."; }

    if (el) {
      el.style.background = `conic-gradient(${color} 0 ${angle}deg, #e5e7eb 0)`;
      el.innerHTML = `
        <div class="gauge-center">
          <span class="gauge-score">${clamped}</span>
          <span class="gauge-unit">/100</span>
        </div>`;
    }
    const scoreNum = $("#scoreNum"); if (scoreNum) scoreNum.textContent = `${clamped}/100`;
    const verdict = $("#verdict");  if (verdict) { verdict.textContent = verdictText; verdict.style.color = color; }
  }

  function updateIconByScore(score) {
    let iconPath, logoHTML;
    if (score <= 50) {
      iconPath = {16:"icons/red.png",32:"icons/red.png",128:"icons/red.png"};
      logoHTML = '<img src="icons/red.png" alt="위험" class="logo-img">';
    } else if (score <= 79) {
      iconPath = {16:"icons/yellow.png",32:"icons/yellow.png",128:"icons/yellow.png"};
      logoHTML = '<img src="icons/yellow.png" alt="주의" class="logo-img">';
    } else {
      iconPath = {16:"icons/green.png",32:"icons/green.png",128:"icons/green.png"};
      logoHTML = '<img src="icons/green.png" alt="안전" class="logo-img">';
    }
    try { chrome.action.setIcon({ path: iconPath }); } catch {}
    const logoEl = document.querySelector(".logo");
    if (logoEl) logoEl.innerHTML = logoHTML;
  }

  function renderKeywords() {
    const list = $("#keywordsList"); if (!list) return;
    list.innerHTML = "";
    state.keywords.forEach((kw, idx) => {
      const pill = document.createElement("span");
      pill.className = "pill";
      pill.innerHTML = `<span>${kw}</span>`;
      const btn = document.createElement("button");
      btn.type = "button"; btn.setAttribute("aria-label", `${kw} 삭제`); btn.innerHTML = "&times;";
      btn.addEventListener("click", async () => {
        state.keywords.splice(idx, 1);
        renderKeywords(); await saveSettings();
        if (state.url) analyze(state.url);
      });
      pill.appendChild(btn); list.appendChild(pill);
    });
  }

  // ---- analysis ----
  async function analyze(urlStr, { markDemo = false } = {}) {
    const url = new URL(urlStr);
    state.url = urlStr; state.host = url.hostname; state.isDemo = !!markDemo;

    const urlDisplay = $("#urlDisplay"); if (urlDisplay) urlDisplay.textContent = urlStr;
    const helper = document.querySelector(".helper");
    if (helper) helper.innerHTML = '사이트에 대한 상세 보안 리포트를 확인합니다.' + (state.isDemo ? ' <span class="demo-badge">예시 URL 미리보기</span>' : '');

    let score = 100;

    // 1) SSL
    const usesHttps = url.protocol === "https:";
    setBadge($("#sslText"), $("#sslBadge"),
      usesHttps ? "보안 연결(HTTPS)을 사용 중입니다." : "HTTPS가 아닙니다.",
      usesHttps ? "safe" : "warn");
    if (!usesHttps) score -= 25;

    // 2) WHOIS/RDAP
    let whoisOK = false;
    try {
      const rdapRes = await Promise.race([
        fetch(`https://rdap.org/domain/${state.host}`, { method: "GET" }),
        new Promise((_, rej) => setTimeout(() => rej(new Error("timeout")), 2500))
      ]);
      whoisOK = rdapRes && rdapRes.ok;
    } catch {}
    setBadge($("#whoisText"), $("#whoisBadge"),
      whoisOK ? "정보 도메인 등록자 정보가 확인되었습니다." : "등록 정보 확인 불가(네트워크 또는 정책)",
      whoisOK ? "safe" : "warn");
    if (!whoisOK) score -= 5;

    // 3) 블랙리스트
    const blackHit = knownBadHosts.has(state.host);
    setBadge($("#blacklistText"), $("#blacklistBadge"),
      blackHit ? "악성 URL 목록에 포함되었습니다." : "악성 URL 목록에 포함되지 않았습니다.",
      blackHit ? "bad" : "safe");
    if (blackHit) score -= 40;

    // 4) 의심 키워드
    const lowerAll = (state.host + url.pathname + url.search).toLowerCase();
    const matched = state.keywords.filter((kw) => lowerAll.includes(kw.toLowerCase()));
    const hasSuspicious = matched.length > 0;
    setBadge($("#keywordText"), $("#keywordBadge"),
      hasSuspicious ? `의심스러운 키워드(${matched.slice(0,4).join(", ")}${matched.length>4?" 외":""})가 포함됨`
                    : "의심스러운 키워드는 포함되어 있지 않습니다.",
      hasSuspicious ? "warn" : "safe");
    if (hasSuspicious) score -= Math.min(25, 8 + matched.length * 2);

    // 5) 리디렉션
    let redirectCount = 0;
    try {
      const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
      if (tab?.id) {
        const results = await chrome.scripting.executeScript({
          target: { tabId: tab.id },
          func: () => {
            try { const nav = performance.getEntriesByType("navigation")[0]; return nav ? nav.redirectCount : 0; }
            catch { return -1; }
          }
        });
        redirectCount = Array.isArray(results) ? (results[0].result ?? 0) : 0;
      }
    } catch {}
    const redirected = redirectCount > 0;
    setBadge($("#redirectText"), $("#redirectBadge"),
      redirected ? `외부로의 자동 이동 감지됨(횟수: ${redirectCount})` : "외부로의 자동 이동이 감지되지 않았습니다.",
      redirected ? "warn" : "safe");
    if (redirected) score -= 10;

    state.score = Math.max(1, Math.min(100, Math.round(score)));
    setGauge(state.score);
    updateIconByScore(state.score);

    const mapBadge = (el) =>
      el.classList.contains("bad") ? "bad" : el.classList.contains("warn") ? "warn" : "safe";
    state.parts.ssl = mapBadge($("#sslBadge"));
    state.parts.whois = mapBadge($("#whoisBadge"));
    state.parts.blacklist = mapBadge($("#blacklistBadge"));
    state.parts.keywords = mapBadge($("#keywordBadge"));
    state.parts.redirect = mapBadge($("#redirectBadge"));
  }

  // ---- report open (저장 먼저 → 탭 열기) ----
  async function getActiveHttpUrlOrDemo() {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    const url = tab?.url || "";
    // http/https만 허용. (chrome://, file://, chrome web store 등은 접근 불가)
    const isHttp = /^https?:\/\//i.test(url);
    return isHttp ? url : DEMO_URL;
  }

  async function openReport() {
    try {
      // 1) 현재 탭 URL 확보 (안 되면 DEMO_URL)
      const target = await getActiveHttpUrlOrDemo();

      // 2) 먼저 새 탭으로 이동 (쿼리로 URL을 반드시 전달) ★핵심
      const urlWithQuery = chrome.runtime.getURL(`report.html?url=${encodeURIComponent(target)}`);
      await chrome.tabs.create({ url: urlWithQuery });

      // 3) (비차단) 백엔드/ML 프리패치해서 저장만 — 실패해도 상관 없음
      Promise.all([
        runBackendAnalyzeDedup(target),
        runMlDetect(target).catch(() => null),
      ])
      .then(async ([data, mlRes]) => {
        const report = convertBackendToReport(data, target);
        // (선택) 백엔드 점수와 ML 점수 평균으로 교체
        report.score = unifyScoreFromBackendAndML(data, mlRes);
        await chrome.storage.local.set({ reportData: report, reportUrl: target, schemaVersion: 2 });
      })
      .catch(err => {
        console.warn("[SiteGuard] prefetch failed (non-blocking):", err);
        // 프리패치 실패 시에도 이미 report는 쿼리로 백엔드 호출하므로 신경X
      });

    } catch (e) {
      console.error("[SiteGuard] openReport failed:", e, chrome.runtime?.lastError);
      // 마지막 폴백: 어찌됐든 report는 열어줌
      try { window.open(chrome.runtime.getURL("report.html"), "_blank"); } catch {}
    }
  }

  // ---- init ----
  async function init() {
    await loadSettings();

    $("#manageKeywords")?.addEventListener("click", (e) => {
      const panel = $("#keywordsPanel");
      const expanded = e.currentTarget.getAttribute("aria-expanded") === "true";
      panel.hidden = expanded;
      e.currentTarget.setAttribute("aria-expanded", String(!expanded));
      e.currentTarget.textContent = "관리";
    });

    $("#autoScan")?.addEventListener("change", saveSettings);
    $("#shareData")?.addEventListener("change", saveSettings);

    $("#refreshBtn")?.addEventListener("click", async () => {
      const [tab] = await chrome.tabs.query({ active:true, currentWindow:true });
      const useDemo = !(tab?.url && /^https?:\/\//i.test(tab.url));
      const target = useDemo ? DEMO_URL : tab.url;
      setUrlDisplay(target);

      try {
        // 1) 백엔드 분석 호출
        const [data, mlRes] = await Promise.all([
          runBackendAnalyzeDedup(target),
          runMlDetect(target).catch(() => null)
        ]);

        // 2) 점수 계산
        const backendScore = Math.max(0, Math.min(100, Number(data?.totalScore) || 0));
        const mlScore = mlRes ? mlToScore(mlRes) : null;
        const finalScore = mlScore == null
          ? backendScore
          : Math.round((backendScore + mlScore) / 2);

        // 3) UI 반영
        setGauge(finalScore);
        updateIconByScore(finalScore);
        renderBackendBadges(data.details);

        // ML 뱃지는 이미 받은 결과 재사용(실패시 내부에서 경고 뱃지)
        if (mlRes) await applyMlBadge(target, mlRes); else await applyMlBadge(target);

        await fillRedirectBadge();

        // 4) report 저장 시도(리포트 카드의 score도 “합산 점수”로 저장)
        const reportData = convertBackendToReport(data, target);
        reportData.score = finalScore; // ★ 합산된 최종 점수로 덮어쓰기
        await chrome.storage.local.set({ reportData, reportUrl: target });

      } catch (e) {
        // 백엔드 실패 시 기존 로컬 분석으로 폴백
        await analyze(target, { markDemo: useDemo });
      }
    });

    // 여기서만 바인딩 (DOM 생성 이후)
    $("#reportBtn")?.addEventListener("click", openReport);
    // init() 맨 끝에 추가 (선택)
    try {
      const [tab] = await chrome.tabs.query({ active:true, currentWindow:true });
      const useDemo = !(tab?.url && /^https?:\/\//i.test(tab.url));
      const target = useDemo ? DEMO_URL : tab.url;
      setUrlDisplay(target);

      // 백엔드 바로 호출 시도 (실패하면 아래 catch에서 로컬로 폴백)
      const [data, mlRes] = await Promise.all([
        runBackendAnalyzeDedup(target),
        runMlDetect(target).catch(() => null)
      ]);

      const backendScore = Math.max(0, Math.min(100, Number(data?.totalScore) || 0));
      const mlScore = mlRes ? mlToScore(mlRes) : null;
      const finalScore = mlScore == null
        ? backendScore
        : Math.round((backendScore + mlScore) / 2);

      setGauge(finalScore);
      updateIconByScore(finalScore);
      renderBackendBadges(data.details);
      if (mlRes) await applyMlBadge(target, mlRes); else await applyMlBadge(target);
      await fillRedirectBadge();

      const reportData = convertBackendToReport(data, target);
      reportData.score = finalScore; // ★ 합산 결과 저장
      await chrome.storage.local.set({ reportData, reportUrl: target });

    } catch (e) {
      // 실패하면 기존 로컬 간이 분석
      const [tab] = await chrome.tabs.query({ active:true, currentWindow:true });
      const useDemo = !(tab?.url && /^https?:\/\//i.test(tab.url));
      const target = useDemo ? DEMO_URL : tab.url;
      await analyze(target, { markDemo: useDemo });
    }
  }

  if (chrome?.storage?.onChanged) {
    chrome.storage.onChanged.addListener((changes, area) => {
      if (area === "local" && changes.reportData?.newValue) {
        renderAll(changes.reportData.newValue);
      }
    });
  }

  document.addEventListener("DOMContentLoaded", init);
})();
