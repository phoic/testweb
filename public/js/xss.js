// xss.js — XSS Lab 클라이언트 로직

function $(sel) {
  return document.querySelector(sel);
}

function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms));
}

// HTML 특수문자를 escape하는 함수.
// 안전한 게시판은 이 함수를 거친 결과만 화면에 출력한다.
function escapeHtml(str) {
  return String(str)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

function looksExecutable(content) {
  return /on\w+\s*=/i.test(content) || /<\s*script\b/i.test(content);
}

// -----------------------------------------------------------------------
// 페이로드 칩
// -----------------------------------------------------------------------

document.querySelectorAll("[data-xss-payload]").forEach((chip) => {
  chip.addEventListener("click", () => {
    const payload = chip.dataset.xssPayload;
    $("#vuln-comment").value = payload;
    $("#safe-comment").value = payload;
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

const consoleEl = $("#console-xss");

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

$("#clear-console-xss").addEventListener("click", () => {
  consoleEl.innerHTML = '<div class="console-empty">// 로그가 초기화되었습니다.</div>';
});

// -----------------------------------------------------------------------
// 댓글 목록 렌더링
// -----------------------------------------------------------------------

async function loadComments(board) {
  const res = await fetch(`/api/xss/comments?board=${board}`);
  const data = await res.json();
  const listEl = document.getElementById(`list-xss-${board === "safe" ? "safe" : "vuln"}`);
  listEl.innerHTML = "";

  data.comments.forEach((c) => {
    const item = document.createElement("div");
    item.className = "comment-item";

    const meta = document.createElement("div");
    meta.className = "comment-meta";
    meta.textContent = `#${c.id} · ${c.created_at}`;
    item.appendChild(meta);

    const body = document.createElement("div");
    body.className = "comment-body";

    if (board === "vulnerable") {
      // EDUCATIONAL ONLY — 저장된 댓글을 이스케이프 없이 그대로 삽입한다.
      // content 안에 <img onerror=...> 같은 태그가 있으면 브라우저가
      // 실제로 그 이벤트 핸들러(JavaScript)를 실행한다.
      body.innerHTML = c.content;
    } else {
      // 출력 직전에 특수문자를 escape하므로, 태그처럼 보이는 문자열도
      // 항상 "글자 그대로"만 화면에 표시된다.
      body.innerHTML = escapeHtml(c.content);
    }

    item.appendChild(body);
    listEl.appendChild(item);
  });
}

// -----------------------------------------------------------------------
// 폼 제출
// -----------------------------------------------------------------------

async function submitComment(mode) {
  const isVuln = mode === "vulnerable";
  const prefix = isVuln ? "vuln" : "safe";
  const board = isVuln ? "vulnerable" : "safe";
  const textarea = $(`#${prefix}-comment`);
  const content = textarea.value;

  if (!content.trim()) return;

  await playFlow(`flow-xss-${prefix}`, 2);

  const res = await fetch("/api/xss/comments", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ board, content }),
  });
  const data = await res.json();

  await playFlow(`flow-xss-${prefix}`, 4);

  if (data.error) {
    pushLog([data.error], "muted");
    return;
  }

  await loadComments(board);
  textarea.value = "";

  const el = document.getElementById(`result-xss-${prefix}`);
  el.classList.remove("is-breach", "is-blocked");

  const executable = looksExecutable(content);
  if (isVuln && executable) {
    el.classList.add("is-breach");
    el.innerHTML = `<span class="result-title">SCRIPT MAY HAVE RUN</span>입력한 태그의 이벤트 핸들러가 브라우저에서 그대로 해석되었습니다.`;
  } else if (executable) {
    el.classList.add("is-blocked");
    el.innerHTML = `<span class="result-title">ESCAPED</span>태그처럼 보이는 문자열이 escape되어 일반 텍스트로만 표시되었습니다.`;
  } else {
    el.innerHTML = `<span class="result-title">POSTED</span>댓글이 정상적으로 등록되었습니다.`;
  }

  pushLog(
    data.log.map((l) => `[${prefix}] ${l}`),
    isVuln && executable ? "danger" : !isVuln ? "safe" : "muted"
  );

  const breached = isVuln && executable;
  try {
    localStorage.setItem(
      `xss_${mode}_last`,
      JSON.stringify({ breached, time: new Date().toLocaleTimeString("ko-KR") })
    );
  } catch {}
}

$("#form-xss-vuln").addEventListener("submit", (e) => {
  e.preventDefault();
  submitComment("vulnerable");
});

$("#form-xss-safe").addEventListener("submit", (e) => {
  e.preventDefault();
  submitComment("safe");
});

// -----------------------------------------------------------------------
// 초기 로드
// -----------------------------------------------------------------------

loadComments("vulnerable");
loadComments("safe");
