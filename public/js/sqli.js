// sqli.js — SQL Injection Lab 클라이언트 로직

function $(sel) {
  return document.querySelector(sel);
}

function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms));
}

// -----------------------------------------------------------------------
// 계정 / 페이로드 칩
// -----------------------------------------------------------------------

document.querySelectorAll("[data-fill-user]").forEach((chip) => {
  chip.addEventListener("click", () => {
    const user = chip.dataset.fillUser;
    const pass = chip.dataset.fillPass;
    $("#vuln-username").value = user;
    $("#vuln-password").value = pass;
    $("#safe-username").value = user;
    $("#safe-password").value = pass;
  });
});

document.querySelectorAll("[data-payload-target]").forEach((chip) => {
  chip.addEventListener("click", () => {
    const target = document.getElementById(chip.dataset.payloadTarget);
    if (target) target.value = chip.dataset.payload;
  });
});

// -----------------------------------------------------------------------
// 흐름 다이어그램 애니메이션
// -----------------------------------------------------------------------

async function playFlow(flowId, upToStep) {
  const flow = document.getElementById(flowId);
  if (!flow) return;
  flow.querySelectorAll(".flow-node, .flow-line").forEach((el) => el.classList.remove("active"));
  for (let step = 1; step <= upToStep; step++) {
    const node = flow.querySelector(`[data-step="${step}"]`);
    const line = flow.querySelector(`[data-line="${step - 1}"]`);
    if (line) line.classList.add("active");
    if (node) node.classList.add("active");
    await sleep(160);
  }
}

// -----------------------------------------------------------------------
// 로그 콘솔
// -----------------------------------------------------------------------

const consoleEl = $("#console-sqli");

function pushLog(lines, tone) {
  if (consoleEl.querySelector(".console-empty")) consoleEl.innerHTML = "";
  lines.forEach((line) => {
    const div = document.createElement("div");
    div.className = "console-line " + (tone ? `line-${tone}` : "");
    div.textContent = line;
    consoleEl.appendChild(div);
  });
  consoleEl.scrollTop = consoleEl.scrollHeight;
}

$("#clear-console-sqli").addEventListener("click", () => {
  consoleEl.innerHTML = '<div class="console-empty">// 로그가 초기화되었습니다.</div>';
});

// -----------------------------------------------------------------------
// 결과 렌더링
// -----------------------------------------------------------------------

function renderResult(elId, data, mode) {
  const el = document.getElementById(elId);
  el.classList.remove("is-breach", "is-blocked");

  if (data.dbError) {
    el.classList.add("is-breach");
    el.innerHTML =
      `<span class="result-title">DB ERROR</span>` +
      `쿼리 실행 중 SQL 문법 오류가 발생했습니다. (입력값이 SQL 문법을 깨뜨렸다는 신호입니다)`;
    return;
  }

  if (data.success) {
    const breached = mode === "vulnerable";
    el.classList.add("is-breach");
    el.innerHTML =
      `<span class="result-title">${breached ? "LOGIN BYPASSED" : "LOGIN SUCCESS"}</span>` +
      `${data.user} 계정으로 로그인되었습니다. (일치한 행: ${data.matchedRows}개)`;
  } else {
    el.classList.add("is-blocked");
    el.innerHTML =
      `<span class="result-title">LOGIN FAILED</span>` +
      `일치하는 계정을 찾지 못했습니다.`;
  }
}

// -----------------------------------------------------------------------
// 폼 제출
// -----------------------------------------------------------------------

async function submitLogin(mode) {
  const isVuln = mode === "vulnerable";
  const prefix = isVuln ? "vuln" : "safe";
  const username = $(`#${prefix}-username`).value;
  const password = $(`#${prefix}-password`).value;

  await playFlow(`flow-sqli-${prefix}`, 2);

  const res = await fetch(`/api/sqli/${isVuln ? "vulnerable-login" : "safe-login"}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ username, password }),
  });
  const data = await res.json();

  await playFlow(`flow-sqli-${prefix}`, 4);

  $(`#query-sqli-${prefix}`).textContent = data.query;
  renderResult(`result-sqli-${prefix}`, data, mode);
  pushLog(
    data.log.map((l) => `[${prefix}] ${l}`),
    isVuln ? (data.success ? "danger" : "muted") : data.success ? "safe" : "muted"
  );

  const breached = isVuln && data.success;
  try {
    localStorage.setItem(
      `sqli_${mode}_last`,
      JSON.stringify({ breached, time: new Date().toLocaleTimeString("ko-KR") })
    );
  } catch {}
}

$("#form-sqli-vuln").addEventListener("submit", (e) => {
  e.preventDefault();
  submitLogin("vulnerable");
});

$("#form-sqli-safe").addEventListener("submit", (e) => {
  e.preventDefault();
  submitLogin("safe");
});
