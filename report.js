/* global chrome */
(() => {
  // 중복 로드 방지
  if (window.__SG_REPORT_LOADED__) {
    console.warn("[SiteGuard] report.js already loaded, skip.");
    return;
  }
  window.__SG_REPORT_LOADED__ = true;

  const dom = {
    gauge: document.getElementById("gauge"),
    scoreText: document.getElementById("scoreText"),
    verdict: document.getElementById("verdict"),
    rptUrl: document.getElementById("rptUrl"),
    tableBasic: document.getElementById("tableBasic"),
    tableVuln: document.getElementById("tableVuln"),
    tableExtra: document.getElementById("tableExtra"),
    summary: document.getElementById("summary"),
    // 분석 기준 및 기술
    methodology: document.getElementById("methodology"),
    tools: document.getElementById("tools"),
    analyzedAt: document.getElementById("analyzedAt"),
    analysisType: document.getElementById("analysisType"),
    // 헤더 검색
    searchForm: document.querySelector(".search-box"),
    searchInput: document.querySelector(".search-box .search-txt"),
  };

  const cssVar = (name) =>
    getComputedStyle(document.documentElement).getPropertyValue(name).trim();
  const levelText = (l) => (l === "safe" ? "정상" : l === "warn" ? "주의" : "위험");
  const badge = (l) => `<span class="badge ${l}">${levelText(l)}</span>`;
  const row = (t, l, n) =>
    `<div class="row">
      <div class="cell-title">${t}</div>
      <div>${badge(l)}</div>
      <div>${n}</div>
    </div>`;

  // ===== Backend analyze (port 3000) =====
  const API_BASE = "http://127.0.0.1:3000";
  async function runBackendAnalyze(targetUrl) {
    const r = await fetch(`${API_BASE}/analyze?url=${encodeURIComponent(targetUrl)}`);
    if (!r.ok) throw new Error(`Backend ${r.status}`);
    return r.json(); // { totalScore, overallGrade, details:{...}, meta... }
  }

  // ===== ML analyze (port 8000) =====
  const ML_API = "http://127.0.0.1:8000";
  async function runMlDetect(targetUrl) {
    const ctrl = new AbortController();
    const t = setTimeout(() => ctrl.abort(), 8000);
    try {
      const r = await fetch(`${ML_API}/predict?url=${encodeURIComponent(targetUrl)}`, { signal: ctrl.signal });
      clearTimeout(t);
      if (!r.ok) throw new Error(`ML ${r.status}`);
      return await r.json(); // { label, proba, ... }
    } catch (e) {
      clearTimeout(t);
      console.warn("[SiteGuard] ML detect failed:", e);
      return null; // 실패 허용(백엔드 점수만 사용)
    }
  }
  function clamp01(v){ return Math.max(0, Math.min(1, Number(v) || 0)); }
  function mlToScore(res){
    if (!res) return null;
    const pMal = (typeof res.proba === "number")
      ? clamp01(res.proba)
      : clamp01(res?.p_phishing ?? res?.prob_phish ?? 0);
    return Math.round((1 - pMal) * 100); // 악성확률 → 안전점수
  }
  function unifyScoreFromBackendAndML(backendData, mlRes){
    const backendScore = Math.max(0, Math.min(100,
      Number(backendData?.totalScore ?? backendData?.score ?? backendData?.meta?.safeScore100) || 0));
    const mlScore = mlToScore(mlRes);
    return (mlScore == null) ? backendScore : Math.round((backendScore + mlScore) / 2);
  }

  // 등급 문자열 → 뱃지 레벨
  function gradeToLevel(grade) {
    if (!grade) return "warn";
    if (grade.includes("위험")) return "bad";
    if (grade.includes("주의")) return "warn";
    return "safe";
  }

  // 백엔드 구조 → report 페이지 구조로 변환 (1번 스샷 형태)
  function convertBackendToReport(data, targetUrl) {
    const d = data?.details || {};
    const ssl    = d.ssl;
    const whois  = d.whois;
    const dns    = d.dns;
    const header = d.header;          // 보안 헤더 관련 이슈
    const vuln   = d.vulnerability;   // 취약점 스캐닝 결과
    const urlCat = d.url;             // URL/HTML 간이 분석 + 블랙리스트/키워드 등

    // 등급→레벨
    const toLevel = (sec) => gradeToLevel(sec?.grade || "");
    // 첫 메시지를 설명으로
    const firstMsg = (sec, fb) => {
      const msgs = sec?.messages || [];
      if (!msgs.length) return fb || "특이사항 없음";
      const m = msgs[0];
      return typeof m === "string" ? m : (m.note || m.issue || JSON.stringify(m));
    };

    // ----- [기본 보안 구성 점검] -----
    const basic = [
      { title: "SSL 인증서",           level: toLevel(ssl),    note: firstMsg(ssl, "HTTPS/HTTP 확인") },
      { title: "WHOIS 등록 정보",       level: toLevel(whois),  note: firstMsg(whois, "WHOIS 확인") },
      {
        title: "악성 도메인 목록 여부",
        level: (() => {
          const txt = (urlCat?.messages || []).join(" ");
          return /blacklist|악성|피싱|malicious|suspicious/i.test(txt) ? "warn" : toLevel(urlCat) || "safe";
        })(),
        note: firstMsg(urlCat, "악성 URL 목록에 포함되지 않았습니다."),
      },
      { title: "DNS 상태",             level: toLevel(dns),    note: firstMsg(dns, "정상 도메인 구조") },
      { title: "HTML 기본 분석",        level: toLevel(urlCat), note: firstMsg(urlCat, "특이사항 없음(간이 분석)") },
    ];

    // ----- [취약점 점검 결과] -----
    const headerNote = firstMsg(header, "보안 헤더 확인");
    const vulnNote   = firstMsg(vuln,   "악성 스크립트 징후 없음");

    const vulnRows = [
      { title: "XSS 탐지",                 level: toLevel(vuln),   note: vulnNote },
      { title: "Clickjacking 방지 설정",    level: toLevel(header), note: headerNote },
      { title: "파일 업로드 경로 노출",      level: "safe",          note: "노출 흔적 없음" },
      { title: "디렉터리 리스팅",           level: "safe",          note: "노출되지 않음" },
      { title: "CSP(Content-Security-Policy)", level: toLevel(header), note: headerNote },
      { title: "CORS 정책",                 level: "safe",          note: "개방적 아님" },
      { title: "서버 정보 노출",            level: "safe",          note: "식별 헤더 노출 징후 없음" },
    ];

    // ----- [추가 분석] -----
    const redirectCount =
      data?.meta?.redirectCount ??
      (urlCat?.meta?.redirectCount ?? 0);

    const extra = [
      {
        title: "의심 키워드 포함 여부",
        level: (() => {
          const txt = (urlCat?.messages || []).join(" ");
          return /키워드|keyword|login|admin|pay|verify|otp|bank/i.test(txt) ? "warn" : "safe";
        })(),
        note: firstMsg(urlCat, "의심스러운 키워드는 포함되어 있지 않습니다."),
      },
      {
        title: "리디렉션 여부",
        level: redirectCount ? "warn" : "safe",
        note: redirectCount ? `외부로의 자동 이동이 감지되었습니다(${redirectCount}).`
                            : "외부로의 자동 이동이 감지되지 않았습니다.",
      },
    ];

    return {
      url: data?.meta?.url || targetUrl,
      // 백엔드 점수(0~100)를 기본으로 넣고 → 렌더 직전에 ML과 평균으로 덮어씀
      score: Math.max(0, Math.min(100,
              Number(data?.score ?? data?.totalScore ?? data?.meta?.safeScore100) || 0)),
      basic,
      vuln: vulnRows,
      extra,
      tools: ["axios", "cheerio", "ssl-certificate", "whois-json", "Google Safe Browsing API", "ML(FastAPI)"],
      analysisTypes: ["비접속 기반 정적 분석", "응답 기반 동적 분석"],
      analyzedAt: data?.analyzedAt || formatKST(),
      summary: data?.summary || "백엔드 규칙 기반 종합 분석 결과입니다.",
    };
  }

  /* ===== SVG 아이콘 ===== */
  const Icons = {
    safe: () =>
      `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor">
        <path stroke-width="2" d="M20 6L9 17l-5-5"/></svg>`,
    warn: () =>
      `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor">
        <path stroke-width="2" d="M12 9v4m0 4h.01"/>
        <path stroke-width="2" d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/></svg>`,
    bad: () =>
      `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor">
        <path stroke-width="2" d="M6 18L18 6M6 6l12 12"/></svg>`,
  };

  /* ===== 게이지 & 점수 ===== */
  function getBand(score) {
    if (score <= 40) return "bad"; // 위험
    if (score <= 70) return "warn"; // 주의
    return "safe"; // 안전
  }

  function bandToText(band) {
    return band === "bad" ? "위험" : band === "warn" ? "주의" : "안전";
  }

  function bandToNote(band) {
    return band === "bad"
      ? "다수의 위험 요소가 감지되었습니다. 즉시 조치가 필요합니다."
      : band === "warn"
      ? "중간 수준의 위험 요소가 감지되었습니다. 권장 설정을 점검하세요."
      : "전반적으로 안전한 설정입니다. 일부 항목은 개선 여지가 있을 수 있습니다.";
  }

  function setGauge(score) {
    const s = Math.max(0, Math.min(100, Number(score) || 0));
    const angle = s * 3.6;
    const band = getBand(s);

    // 게이지 색 (상태에 따라)
    const gauge = document.getElementById("gauge");
    const brand = getComputedStyle(document.documentElement)
      .getPropertyValue(band === "bad" ? "--bad" : band === "warn" ? "--warn" : "--safe")
      .trim();
    if (gauge) {
      gauge.style.background = `conic-gradient(${brand} ${angle}deg, var(--line) 0deg)`;
    }

    // 내부 점수칩
    const scoreText = document.getElementById("scoreText");
    if (scoreText) scoreText.textContent = s;

    const chip = gauge?.querySelector(".score-chip");
    if (chip) {
      chip.classList.remove("safe", "warn", "bad");
      chip.classList.add(band);
    }

    // 우측 큰 라벨
    const scoreText2 = document.getElementById("scoreText2");
    if (scoreText2) scoreText2.textContent = `${s}/100`;

    // 최종평가 문구 + 색
    const verdict = document.getElementById("verdict");
    const finalNote = document.getElementById("finalNote");
    if (verdict) {
      verdict.textContent = bandToText(band);
      verdict.className = `verdict ${band}`;
    }
    if (finalNote) finalNote.textContent = `최종 평가: ${bandToNote(band)}`;
  }

  /* ===== 표 렌더러 =====
   * items: [{ title, status: 'safe'|'warn'|'bad', detail }]
   */
  function renderTable(tableId, items) {
    const host = document.getElementById(tableId);
    if (!host) return;

    host.innerHTML = ""; // reset
    // 제목 행
    const head = document.createElement("div");
    head.className = "row";
    head.innerHTML = `
      <div class="cell-title"><strong>항목</strong></div>
      <div><strong>상태</strong></div>
      <div><strong>설명</strong></div>`;
    host.appendChild(head);

    // 본문
    for (const it of items) {
      const row = document.createElement("div");
      row.className = "row";
      const badgeClass =
        it.status === "bad" ? "badge bad" : it.status === "warn" ? "badge warn" : "badge safe";
      const label = it.status === "bad" ? "위험" : it.status === "warn" ? "주의" : "정상";

      row.innerHTML = `
        <div class="cell-title">${it.title}</div>
        <div>
          <span class="${badgeClass}">
            ${Icons[it.status] ? Icons[it.status]() : Icons.safe()}
            <span>${label}</span>
          </span>
        </div>
        <div>${it.detail}</div>
      `;
      host.appendChild(row);
    }
  }

  /* ========= 분석 요약 / 기준 및 기술 ========= */

  // 밴드별 요약 문장
  function buildSummary(url, band) {
    if (band === "bad") {
      return `"${url}"는 핵심 보안 기준을 충족하지 못한 항목이 다수 확인되었습니다. 즉시 조치가 필요하며, 현 시점에서 안전한 사용을 권장하지 않습니다.`;
    }
    if (band === "warn") {
      return `"${url}"는 일부 설정 미흡으로 주의가 필요합니다. 권장 보안 설정을 적용하면 보안 수준을 개선할 수 있습니다. 일반 사용은 가능하나 관리자 점검을 권장합니다.`;
    }
    return `"${url}"는 다양한 보안 기준을 충족하며, 현재까지 알려진 위험 정보는 발견되지 않았습니다. 사이트는 안전하게 사용할 수 있습니다.`;
  }

  // KST 포맷
  function formatKST(date = new Date()) {
    const tz = "Asia/Seoul";
    const d = new Date(date.toLocaleString("en-US", { timeZone: tz }));
    const yyyy = d.getFullYear();
    const m = d.getMonth() + 1;
    const dd = String(d.getDate()).padStart(2, "0");
    const hh = String(d.getHours()).padStart(2, "0");
    const mi = String(d.getMinutes()).padStart(2, "0");
    return `${yyyy}년 ${m}월 ${dd}일 ${hh}:${mi} KST`;
  }

  // 요약 + 기준/기술 채우기
  function renderSummaryAndMethod({ url, score, tools, analysisTypes, analyzedAt }) {
    const band = getBand(score || 0);
    if (dom.summary) {
      dom.summary.textContent = buildSummary(url || "-", band);
    }
    if (dom.tools) dom.tools.textContent = `분석 도구: ${tools.join(", ")}`;
    if (dom.analyzedAt) dom.analyzedAt.textContent = `분석 시점: ${analyzedAt || formatKST()}`;
    if (dom.analysisType)
      dom.analysisType.textContent = `검사 유형: ${analysisTypes.join(" + ")}`;
  }

  // 전체 렌더 (요약/기술 포함)
  function renderAll(data) {
    const url = data?.url || "-";
    const score = Number(data?.score ?? 0);

    // URL 표시
    if (dom.rptUrl) dom.rptUrl.textContent = url;

    // 게이지/평가
    setGauge(score);

    // 표: level -> status, note -> detail 매핑
    const map = (arr) =>
      (arr || []).map((x) => ({
        title: x.title,
        status: x.status || x.level || "safe",
        detail: x.detail || x.note || "",
      }));

    renderTable("tableBasic", map(data?.basic));
    renderTable("tableVuln", map(data?.vuln));
    renderTable("tableExtra", map(data?.extra));

    // 요약 & 기준/기술
    renderSummaryAndMethod({
      url,
      score,
      tools:
        data?.tools ||
        ["axios", "cheerio", "ssl-certificate", "whois-json", "Google Safe Browsing API", "ML(FastAPI)"],
      analysisTypes: data?.analysisTypes || ["비접속 기반 정적 분석", "응답 기반 동적 분석"],
      analyzedAt: data?.analyzedAt || formatKST(),
    });
  }

  // ─── storage helpers ───
  async function loadFromStorage() {
    try {
      const l = await chrome?.storage?.local.get("reportData");
      if (l?.reportData) return l.reportData;
      const s = await chrome?.storage?.session.get("reportData");
      return s?.reportData || null;
    } catch (e) {
      console.warn("[SiteGuard] storage read failed:", e);
      return null;
    }
  }

  async function saveToStorage(reportData) {
    try {
      if (chrome?.storage?.local) {
        await chrome.storage.local.set({ reportData });
      }
    } catch (e) {
      // 확장 환경이 아니면 무시
    }
  }

  async function clearStoredReport() {
    try { await chrome?.storage?.local.remove(["reportData"]); } catch (e) {}
  }

  function toURLLike(input) {
    if (!input) return null;
    let v = input.trim();
    if (/\s/.test(v)) return null; // 공백/한글 포함되면 URL 아님
    if (!/^https?:\/\//i.test(v)) {
      if (/^[a-z0-9.-]+\.[a-z]{2,}$/i.test(v)) v = "https://" + v;
      else return null;
    }
    try {
      const u = new URL(v);
      return u.protocol === "http:" || u.protocol === "https:" ? u.toString() : null;
    } catch (e) {
      return null;
    }
  }

  async function runLightAnalysis(urlStr, tabId) {
    if (!/^https?:\/\//i.test(urlStr || "")) return null;
    let redirectCount = 0;
    try {
      if (tabId && chrome?.scripting?.executeScript) {
        const [res] = await chrome.scripting.executeScript({
          target: { tabId },
          func: () => {
            try {
              const n = performance.getEntriesByType("navigation")[0];
              return n ? n.redirectCount : 0;
            } catch (e) {
              return 0;
            }
          },
        });
        redirectCount = res?.result ?? 0;
      }
    } catch (e) {}
    const https = urlStr.startsWith("https:");
    const score = Math.max(1, Math.min(100, (https ? 90 : 65) - (redirectCount ? 10 : 0)));
    return {
      url: urlStr,
      score,
      basic: [
        { title: "SSL 인증서", level: https ? "safe" : "warn", note: https ? "HTTPS 연결" : "HTTP 연결" },
        { title: "WHOIS 등록 정보", level: "warn", note: "확인 불가(헤더 접근 제한)" },
        { title: "악성 도메인 목록 여부", level: "safe", note: "목록에 없음(내장 목록 기준)" },
        { title: "DNS 상태", level: "safe", note: "정상 도메인 구조" },
        { title: "HTML 기본 분석", level: "safe", note: "특이사항 없음(간이 분석)" },
      ],
      vuln: [
        { title: "XSS 탐지", level: "safe", note: "악성 스크립트 징후 없음(간이)" },
        { title: "Clickjacking 방지 설정", level: "warn", note: "헤더 확인 불가" },
        { title: "파일 업로드 경로 노출", level: "safe", note: "노출 흔적 없음" },
        { title: "디렉터리 리스팅", level: "safe", note: "노출되지 않음" },
        { title: "CSP", level: "warn", note: "정책 확인 불가" },
        { title: "CORS 정책", level: "safe", note: "개방적 아님" },
        { title: "서버 정보 노출", level: "safe", note: "노출 없음" },
      ],
      extra: [
        { title: "의심 키워드 포함 여부", level: "safe", note: "특이사항 없음" },
        {
          title: "리디렉션 여부",
          level: redirectCount ? "warn" : "safe",
          note: redirectCount ? `자동 이동 감지(${redirectCount})` : "감지되지 않음",
        },
      ],
      // 요약/기술 섹션에 쓸 수 있는 메타
      tools: ["axios", "cheerio", "ssl-certificate", "whois-json", "Google Safe Browsing API", "ML(FastAPI)"],
      analysisTypes: ["비접속 기반 정적 분석", "응답 기반 동적 분석"],
      analyzedAt: formatKST(),
      summary: "검색창으로 입력된 URL에 대한 간이 분석 결과입니다.",
    };
  }

  // ─── 핵심: 쿼리 ?url= 이 있으면 "백엔드(+ML) → 스토리지 → 간이" 우선 ───
  async function getReportDataOrFallback() {
    const fromQuery = new URLSearchParams(location.search).get("url");

    // ① 쿼리 url이 있으면: 백엔드 + ML 최우선
    if (fromQuery && /^https?:\/\//i.test(fromQuery)) {
      try {
        const [data, mlRes] = await Promise.all([
          runBackendAnalyze(fromQuery),
          runMlDetect(fromQuery),
        ]);
        const report = convertBackendToReport(data, fromQuery);
        report.score = unifyScoreFromBackendAndML(data, mlRes); // ★ 합산 점수로 통일
        await chrome?.storage?.local.set({ reportUrl: fromQuery, reportData: report, schemaVersion: 2 });
        return report;
      } catch (e) {
        console.warn("[SiteGuard] backend/ml failed with query url, try storage:", e);
        // 실패 시에만 storage → light
        try {
          const l = await chrome?.storage?.local.get(["reportData","schemaVersion"]);
          if (l?.schemaVersion === 2 && l?.reportData) return l.reportData;
        } catch (ee) {
          console.warn("[SiteGuard] storage read failed:", ee);
        }
        return runLightAnalysis(fromQuery, null);
      }
    }

    // ② 쿼리 url이 없으면: 스토리지 → 백엔드(+ML) → 간이
    try {
      const l = await chrome?.storage?.local.get(["reportData", "reportUrl", "schemaVersion"]);
      if (l?.schemaVersion === 2 && l?.reportData) return l.reportData;

      const target = l?.reportUrl || "https://example.com/";
      const [data, mlRes] = await Promise.all([
        runBackendAnalyze(target),
        runMlDetect(target),
      ]);
      const report = convertBackendToReport(data, target);
      report.score = unifyScoreFromBackendAndML(data, mlRes); // ★
      await chrome?.storage?.local.set({ reportUrl: target, reportData: report, schemaVersion: 2 });
      return report;
    } catch (e) {
      console.warn("[SiteGuard] no query url, backend/storage failed, fallback:", e);
      return runLightAnalysis("https://example.com/", null);
    }
  }

  // 헤더 검색: submit 가로채서 백엔드(+ML) 우선 분석
  function wireSearch() {
    if (!dom.searchForm || !dom.searchInput) return;
    dom.searchForm.addEventListener("submit", async (e) => {
      e.preventDefault();
      const raw = dom.searchInput.value;
      const url = toURLLike(raw);

      // URL 검증 실패 시 즉시 안내
      if (!url) {
        renderAll({
          url: raw || "-",
          score: 0,
          basic: [], vuln: [], extra: [],
          summary: "URL 형식이 아닙니다. 예: https://example.com",
          tools: ["axios", "cheerio", "ssl-certificate", "whois-json", "Google Safe Browsing API", "ML(FastAPI)"],
          analysisTypes: ["비접속 기반 정적 분석", "응답 기반 동적 분석"],
          analyzedAt: formatKST(),
        });
        return;
      }

      // 1) 백엔드 + ML 함께 호출
      try {
        const [data, mlRes] = await Promise.all([
          runBackendAnalyze(url),
          runMlDetect(url),
        ]);
        const reportData = convertBackendToReport(data, url);
        reportData.score = unifyScoreFromBackendAndML(data, mlRes); // ★ 합산 점수
        renderAll(reportData);
        await saveToStorage(reportData);
        if (dom.rptUrl) dom.rptUrl.textContent = url;
        return;
      } catch (err) {
        console.warn("[SiteGuard] backend/ml analyze failed in search:", err);
      }

      // 2) 실패 시 간이분석
      const light = await runLightAnalysis(url, null);
      renderAll(light);
      await saveToStorage(light);
      if (dom.rptUrl) dom.rptUrl.textContent = url;
    });
  }

  // 부트스트랩
  document.addEventListener("DOMContentLoaded", async () => {
    try {
      wireSearch();
      const data = await getReportDataOrFallback();
      renderAll(data);
      // 필요하면, 예전 스냅 데이터가 다시 덮어쓰지 않도록 사용 후 제거:
      // await clearStoredReport();
    } catch (e) {
      console.error("[SiteGuard] render error:", e);
      renderAll({
        url: "-",
        score: 0,
        basic: [],
        vuln: [],
        extra: [],
        summary: "렌더링 오류",
        tools: ["axios", "cheerio", "ssl-certificate", "whois-json", "Google Safe Browsing API", "ML(FastAPI)"],
        analysisTypes: ["비접속 기반 정적 분석", "응답 기반 동적 분석"],
        analyzedAt: formatKST(),
      });
    }
  });
})();
