// dashboard.js
// SQLi / XSS Lab에서 마지막으로 실행한 테스트 결과를 localStorage에서 읽어와
// 대시보드 상태 카드에 표시한다. (이 저장소는 이 컴퓨터의 브라우저 안에서만
// 유지되며, 서버로 전송되지 않는다.)

function readLast(key) {
  try {
    const raw = localStorage.getItem(key);
    return raw ? JSON.parse(raw) : null;
  } catch {
    return null;
  }
}

function paint(elId, last, breachWord, blockWord) {
  const el = document.getElementById(elId);
  if (!el) return;
  if (!last) {
    el.textContent = "대기 중";
    return;
  }
  const time = last.time || "";
  el.textContent = `${last.breached ? breachWord : blockWord} · ${time}`;
  el.style.color = last.breached ? "var(--danger)" : "var(--safe)";
}

const sqliVuln = readLast("sqli_vulnerable_last");
const sqliSafe = readLast("sqli_safe_last");
const xssVuln = readLast("xss_vulnerable_last");
const xssSafe = readLast("xss_safe_last");

paint("sqli-vuln-status", sqliVuln, "우회 성공", "정상 차단");
paint("sqli-safe-status", sqliSafe, "우회 성공", "정상 차단");
paint("xss-vuln-status", xssVuln, "스크립트 실행 가능", "일반 텍스트 처리");
paint("xss-safe-status", xssSafe, "스크립트 실행 가능", "일반 텍스트 처리");
