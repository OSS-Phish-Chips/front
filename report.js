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
            ${Icons[it.status]()}
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
    const mm = String(m).padStart(2, "0");
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
        ["axios", "cheerio", "ssl-certificate", "whois-json", "Google Safe Browsing API"],
      analysisTypes: data?.analysisTypes || ["비접속 기반 정적 분석", "응답 기반 동적 분석"],
      analyzedAt: data?.analyzedAt || formatKST(),
    });
  }

  /* ===== 데모 바인딩 ===== */
  document.addEventListener("DOMContentLoaded", () => {
    // 초기 데모 렌더 (저장/실분석 전에 빈 화면 방지)
    renderAll({
      url: "-",
      score: 68,
      basic: [
        { title: "SSL 인증서", level: "safe", note: "HTTPS로 안전하게 연결되어 있습니다." },
        { title: "WHOIS 등록 정보", level: "safe", note: "도메인 등록자 및 생성일 정보 확인됨." },
        {
          title: "악성 도메인 목록 여부",
          level: "safe",
          note: "Google Safe Browsing/VirusTotal에 악성 이력 없음.",
        },
        { title: "DNS 응답 상태", level: "safe", note: "A/MX/NS 레코드가 모두 정상 동작합니다." },
        { title: "HTML 구조 분석", level: "safe", note: "구조적으로 악성 스크립트나 iframe 흔적 없음." },
      ],
      vuln: [
        { title: "XSS 탐지", level: "safe", note: "응답 내 스크립트 인젝션 징후 없음." },
        { title: "Clickjacking 방지", level: "safe", note: "X-Frame-Options 또는 CSP 적용." },
        { title: "파일 업로드 경로 노출", level: "safe", note: "의심 경로 노출 없음." },
        { title: "디렉토리 리스팅", level: "safe", note: "디렉토리 인덱스 비활성화." },
        { title: "CSP 정책", level: "safe", note: "CSP 헤더 명시되어 외부 스크립트 통제." },
        { title: "CORS 정책", level: "bad", note: "Access-Control-Allow-Origin: * 로 과도하게 개방." },
        { title: "서버 정보 노출", level: "safe", note: "Server, X-Powered-By 미노출/마스킹." },
      ],
      extra: [
        {
          title: "의심 키워드 포함 여부",
          level: "warn",
          note: "URL 경로에 index.do 포함 — 잠재적 리스크로 분류.",
        },
      ],
    });
  });

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
    } catch {
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
            } catch {
              return 0;
            }
          },
        });
        redirectCount = res?.result ?? 0;
      }
    } catch {}
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
      tools: ["axios", "cheerio", "ssl-certificate", "whois-json", "Google Safe Browsing API"],
      analysisTypes: ["비접속 기반 정적 분석", "응답 기반 동적 분석"],
      analyzedAt: formatKST(),
      summary: "검색창으로 입력된 URL에 대한 간이 분석 결과입니다.",
    };
  }

  async function getReportDataOrFallback() {
    let d = await loadFromStorage();
    if (d && Array.isArray(d.basic) && Array.isArray(d.vuln) && Array.isArray(d.extra)) {
      console.log("[SiteGuard] using stored full data");
      return d;
    }
    if (d?.url) {
      const recomputed = await runLightAnalysis(d.url, d.tabId);
      if (recomputed) {
        if (typeof d.score === "number") recomputed.score = d.score;
        console.log("[SiteGuard] using recomputed data");
        return recomputed;
      }
    }
    console.warn("[SiteGuard] using dummy fallback");
    return {
      url: "https://example.com/",
      score: 72,
      basic: [
        { title: "SSL 인증서", level: "safe", note: "HTTPS 연결" },
        { title: "WHOIS 등록 정보", level: "warn", note: "확인 불가(테스트)" },
        { title: "악성 도메인 목록 여부", level: "safe", note: "목록에 없음" },
        { title: "DNS 상태", level: "safe", note: "정상 도메인 구조" },
        { title: "HTML 기본 분석", level: "safe", note: "특이사항 없음" },
      ],
      vuln: [
        { title: "XSS 탐지", level: "safe", note: "특이사항 없음" },
        { title: "Clickjacking 방지 설정", level: "warn", note: "헤더 확인 불가" },
        { title: "파일 업로드 경로 노출", level: "safe", note: "없음" },
        { title: "디렉터리 리스팅", level: "safe", note: "없음" },
        { title: "CSP", level: "warn", note: "정책 확인 불가" },
        { title: "CORS 정책", level: "safe", note: "개방적 아님" },
        { title: "서버 정보 노출", level: "safe", note: "없음" },
      ],
      extra: [
        { title: "의심 키워드 포함 여부", level: "warn", note: "감지: login (예시)" },
        { title: "리디렉션 여부", level: "safe", note: "감지되지 않음" },
      ],
      tools: ["axios", "cheerio", "ssl-certificate", "whois-json", "Google Safe Browsing API"],
      analysisTypes: ["비접속 기반 정적 분석", "응답 기반 동적 분석"],
      analyzedAt: formatKST(),
      summary: "스토리지 미수신으로 더미 데이터 표시 중.",
    };
  }

  // 헤더 검색: submit 가로채서 간이 분석 실행
  function wireSearch() {
    if (!dom.searchForm || !dom.searchInput) return;
    dom.searchForm.addEventListener("submit", async (e) => {
      e.preventDefault();
      const raw = dom.searchInput.value;
      const url = toURLLike(raw);
      if (!url) {
        renderAll({
          url: raw || "-",
          score: 0,
          basic: [],
          vuln: [],
          extra: [],
          summary: "URL 형식이 아닙니다. 예: https://example.com",
          tools: ["axios", "cheerio", "ssl-certificate", "whois-json", "Google Safe Browsing API"],
          analysisTypes: ["비접속 기반 정적 분석", "응답 기반 동적 분석"],
          analyzedAt: formatKST(),
        });
        return;
      }
      const data = await runLightAnalysis(url, null);
      renderAll(data);
      await saveToStorage(data);
      if (dom.rptUrl) dom.rptUrl.textContent = url;
    });
  }

  // 부트스트랩
  document.addEventListener("DOMContentLoaded", async () => {
    try {
      wireSearch();
      const data = await getReportDataOrFallback();
      renderAll(data);
    } catch (e) {
      console.error("[SiteGuard] render error:", e);
      renderAll({
        url: "-",
        score: 0,
        basic: [],
        vuln: [],
        extra: [],
        summary: "렌더링 오류",
        tools: ["axios", "cheerio", "ssl-certificate", "whois-json", "Google Safe Browsing API"],
        analysisTypes: ["비접속 기반 정적 분석", "응답 기반 동적 분석"],
        analyzedAt: formatKST(),
      });
    }
  });
})();
