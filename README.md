# SiteGuard — URL Security & Phishing Detection (Chrome Extension)
URL/헤더/SSL/WHOIS/DNS 신호와 ML 피싱 확률을 결합해 0–100 점수로 시각화하는 확장 프로그램





## Features

- 백엔드 규칙(SSL/헤더/WHOIS/DNS/취약점 휴리스틱) + ML 피싱 예측 병합

- 팝업 요약 + 상세 리포트 페이지(게이지/표/요약)

- 최종 점수 = (백엔드 안전점수 + ML 안전점수) / 2 로 팝업·리포트 동일 반영

- 쿼리(report.html?url=...) 기반 분석, 실패 시 로컬 간이 분석 폴백






## Structure
        front/            # Chrome extension (frontend)
          ├─ manifest.json
          ├─ popup.css
          ├─ popup.html
          ├─ popup.js
          ├─ report.css
          ├─ report.html
          ├─ report.js
          ├─ styles.css
          └─ icons/
        ml_service/          # FastAPI (ML)  :8000
        security/            # Express API    :3000






## Quick Start

1. ML 서비스(:8000)

        cd ml_service
        python -m venv venv && source venv/bin/activate  # Windows: venv\Scripts\activate
        pip install -U pip fastapi uvicorn scikit-learn pandas numpy requests beautifulsoup4
        uvicorn app:app --host 127.0.0.1 --port 8000 --reload


2. 보안 백엔드(:3000)

        cd security
        npm i
        node server.js


3. 크롬 확장 로드

- chrome://extensions → 개발자 모드 ON → 압축해제된 확장 로드 → security/ 선택

- 확장 아이콘 클릭 → 리포트 열기





### Config

- 엔드포인트(포트 변경 시 수정)

  - popup.js, report.js

        const API_BASE = "http://127.0.0.1:3000"; // Express
        const ML_API   = "http://127.0.0.1:8000"; // FastAPI


- manifest.json 권한

        {
          "permissions": ["storage", "tabs", "scripting"],
          "host_permissions": [
            "http://*/*", "https://*/*",
            "http://127.0.0.1:3000/*",
            "http://127.0.0.1:8000/*"
          ]
        }





### Scoring

- (백엔드 + ML) / 2 (둘 중 하나 실패 시, 가능한 점수만 사용)





### Checklist

 - ML(:8000) & 백엔드(:3000) 실행

 - manifest.json 권한/호스트 권한 설정

 - API_BASE / ML_API 값 확인

 - 확장 개발자 모드로 로드 & 재로드

 - report.html?url=... 로 리포트 열림 확인
