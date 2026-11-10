'use strict';
const $ = (selector) => document.querySelector(selector);
const examples = {
  normal: { username: 'alice', password: 'password123', label: '정상 계정 예시' },
  wrong: { username: 'alice', password: 'incorrect', label: '잘못된 비밀번호 예시' },
  bypass: { username: "' OR '1'='1' -- ", password: 'anything', label: '인증 우회 예시' },
  syntax: { username: "'", password: 'anything', label: '구문 오류 예시' },
};
const records = [];
let running = false;
let selected = null;
let reportView = false;
const model = ComparisonModel;
const json = (value) => JSON.stringify(value, null, 2);

function condition(input) {
  return Object.values(examples).find(example => example.username === input.username && example.password === input.password)?.label || '직접 입력';
}
function currentInput() {
  return { username: $('#username').value, password: $('#password').value };
}
function updateCondition() {
  $('#input-condition').textContent = condition(currentInput());
  $('#stale-warning').hidden = !selected || JSON.stringify(currentInput()) === JSON.stringify(selected.input);
}
for (const button of document.querySelectorAll('[data-example]')) {
  button.addEventListener('click', () => {
    const example = examples[button.dataset.example];
    $('#username').value = example.username;
    $('#password').value = example.password;
    updateCondition();
  });
}
for (const input of [$('#username'), $('#password')]) input.addEventListener('input', updateCondition);

function applyVisibility() {
  const show = $('#show-values').checked || reportView;
  $('#password').type = show ? 'text' : 'password';
  document.querySelectorAll('.sensitive').forEach(element => { element.hidden = !show; });
  document.querySelectorAll('.hidden-note').forEach(element => { element.hidden = show; });
}
$('#show-values').addEventListener('change', () => {
  applyVisibility();
  renderHistory();
});

function renderResult(mode, result, record) {
  const panel = $(`#${mode}-result`);
  panel.querySelector('.result-body, .empty')?.remove();
  const content = $('#result-template').content.cloneNode(true);
  const set = (selector, value) => { content.querySelector(selector).textContent = value; };
  set('.status', result.status);
  set('.row-count', result.matchedRows);
  set('.execution-id', result.executionId);
  set('.execution-time', result.executedAt);
  set('.auth-success', result.success ? '예 (true)' : '아니오 (false)');
  set('.db-error-presence', result.dbError === null ? '없음' : '있음');
  set('.input', json(result.input));
  set('.query-title', '읽기용 줄바꿈 표시 · 원문 복사로 서버의 원래 SQL 확인. 오류 시 준비/실행 시도문입니다.');
  const queryNode = content.querySelector('.query');
  const parts = mode === 'vulnerable' ? model.sqlParts(record) : [{ text: result.query, kind: '' }];
  for (const part of parts) {
    const span = document.createElement('span');
    span.className = part.kind;
    // 서버의 고정 접두부 안에서만 표시용 줄바꿈. 사용자 입력은 파싱하거나 수정하지 않는다.
    span.textContent = part.text.startsWith('SELECT id, username FROM users WHERE ')
      ? part.text.replace(' FROM users WHERE ', ' FROM users\nWHERE ') : part.text;
    queryNode.append(span);
  }
  const view = model.verdict(record, mode);
  set('.bypass-state', view.bypass);
  set('.interpretation', view.interpretation);
  set('.query-state', result.dbError === null ? '성공' : 'SQL 오류');
  const explanation = content.querySelector('.sql-explanation');
  if (mode === 'vulnerable' && model.explainable(record)) {
    for (const [kind, text] of [
      ['close-string', '① 작은따옴표: 아이디 문자열을 끝냄'],
      ['true-condition', '② OR 조건: 항상 참인 조건을 추가함'],
      ['commented', '③ -- 이후: 주석으로 처리되어 비밀번호 비교가 실행되지 않음']
    ]) {
      const note = document.createElement('p'); note.className = kind; note.textContent = text; explanation.append(note);
    }
  } else explanation.textContent = mode === 'safe' ? 'SQL의 아이디·비밀번호 비교 조건이 유지됩니다. ? 위치에 값이 별도로 바인딩됩니다.' : '임의 입력의 SQL 의미는 자동 판정하지 않습니다. SQL 원문과 실제 조회 결과를 확인하세요.';
  set('.binding-explanation', mode === 'safe' ? '첫 번째 ? ← 아이디 입력값 전체\n두 번째 ? ← 비밀번호 입력값 전체\n이 문자열 전체를 아이디 값으로 비교함' : '입력은 위 SQL 원문에 포함되어 전달됩니다.');
  content.querySelector('.copy-sql').addEventListener('click', async () => {
    const status = panel.querySelector('.copy-status');
    try { await navigator.clipboard.writeText(result.query); status.textContent = '서버 SQL 원문 복사 완료'; }
    catch { status.textContent = '클립보드 접근 실패 · 아래 원문을 선택해 복사하세요.'; const raw = document.createElement('pre'); raw.className = 'sensitive raw-sql'; raw.textContent = result.query; status.append(raw); applyVisibility(); }
  });
  set('.bindings', mode === 'safe' ? `첫 번째 ? ← 아이디: ${JSON.stringify(result.boundParams[0])}\n두 번째 ? ← 비밀번호: ${JSON.stringify(result.boundParams[1])}` : '별도로 전달한 매개변수 없음');
  set('.accounts', result.accounts.length ? result.accounts.map(account => JSON.stringify(account)).join('\n') : '[]');
  set('.db-error', result.dbError === null ? '없음' : result.dbError);
  set('.logs', result.log.map(entry => `[${entry.at}] [${entry.executionId}] [${entry.mode}] ${entry.event}\n${entry.message}${entry.error ? `: ${entry.error}` : ''}`).join('\n\n'));
  panel.dataset.status = result.dbError !== null ? 'error' : result.success ? 'success' : 'failure';
  panel.append(content);
}
function difference(record) {
  const { vulnerable, safe, analysis } = record;
  if (analysis.bypassObserved === true) return '인증 우회 관찰';
  if (vulnerable.dbError !== null || safe.dbError !== null) return 'DB 오류 포함 · 인증 실패와 구분';
  if (vulnerable.success !== safe.success) return '인증 결과 다름';
  if (vulnerable.matchedRows !== safe.matchedRows) return '반환 행 수 다름';
  return '인증 결과·반환 행 수 동일';
}
function showRecord(record) {
  selected = record;
  $('#report-toggle').disabled = false;
  $('#comparison-summary').textContent = model.summary(record);
  $('#snapshot').textContent = '해당 실행의 입력값 (가상 실험 데이터)\n' + json(record.input);
  updateCondition();
  renderResult('vulnerable', record.vulnerable, record);
  renderResult('safe', record.safe, record);
  $('#selected-run').textContent = `표시 중: ${record.executionId} · ${record.executedAt} (UTC) · ${record.inputCondition}`;
  const analysis = record.analysis;
  const exact = analysis.exactMatch === null ? '확인 불가' : analysis.exactMatch ? '일치' : '불일치';
  let text = `${difference(record)}\n분석용 별도 매개변수화 조회: 정확한 계정 ${exact}. `;
  text += analysis.bypassObserved === null || record.vulnerable.dbError !== null ? '실험 조회 또는 기준 조회 오류로 우회 판정 불가.' : analysis.bypassObserved ? '정확한 계정은 불일치하지만 취약 경로에서 계정이 반환되어 인증에 성공했습니다.' : '이 실행에서는 인증 우회가 관찰되지 않았습니다.';
  $('#analysis-result').textContent = text;
  // 분석 DB 오류도 숨기지 않는다. 입력값 포함 가능성이 있어 표시 설정을 따른다.
  if (analysis.dbError !== null) {
    const error = document.createElement('pre');
    error.className = 'sensitive';
    error.textContent = `분석 DB 오류: ${analysis.dbError}`;
    $('#analysis-result').append(error);
  }
  applyVisibility();
}
function renderHistory() {
  const body = $('#history-body');
  body.replaceChildren();
  for (const record of records) {
    const row = document.createElement('tr');
    const visibleInput = {
      username: record.input.username,
      password: $('#show-values').checked ? record.input.password : '•••• (숨김)',
    };
    const values = [
      `${record.executionId}\n${record.executedAt} (UTC)`, record.inputCondition,
      json(visibleInput), `${record.vulnerable.status}\n/ ${record.safe.status}`,
      `${record.vulnerable.matchedRows} / ${record.safe.matchedRows}`,
      [record.vulnerable, record.safe, record.analysis].map(result => result.dbError === null ? '없음' : '있음').join(' / '),
      difference(record),
    ];
    for (const value of values) {
      const cell = document.createElement('td');
      cell.textContent = value;
      row.append(cell);
    }
    const cell = document.createElement('td');
    const button = document.createElement('button');
    button.type = 'button';
    button.textContent = '결과 보기';
    button.setAttribute('aria-label', `${record.executionId} 결과 보기`);
    button.addEventListener('click', () => { showRecord(record); $('#result-title').scrollIntoView({ block: 'start' }); });
    cell.append(button);
    row.append(cell);
    body.append(row);
  }
  $('#history-empty').hidden = records.length > 0;
  $('#record-count').textContent = `${records.length}회`;
  $('#download').disabled = records.length === 0;
}
function freezeRecord(value) {
  if (value && typeof value === 'object') {
    for (const child of Object.values(value)) freezeRecord(child);
    Object.freeze(value);
  }
  return value;
}
$('#compare-form').addEventListener('submit', async event => {
  event.preventDefault();
  if (running) return;
  // 입력창을 이후에 바꿔도 이 비교 실행의 두 인증 경로에는 같은 값이 전달된다.
  const input = Object.freeze(currentInput());
  const inputCondition = condition(input);
  running = true;
  $('#run').disabled = true;
  $('#run').textContent = '비교 실행 중…';
  $('#request-error').hidden = true;
  $('#request-state').textContent = '고정한 입력을 서버에 전달했습니다. 두 인증 경로 실행 중…';
  try {
    const response = await fetch('/api/sqli/compare', {
      method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(input),
    });
    if (!response.ok) throw new Error(`HTTP ${response.status} · 비교 요청을 처리하지 못했습니다.`);
    const data = await response.json();
    // 응답은 JSON 복사본으로 보관하고 재귀적으로 동결한다. 현재 폼과 참조를 공유하지 않는다.
    const record = freezeRecord(JSON.parse(JSON.stringify({ ...data, inputCondition })));
    records.push(record);
    renderHistory();
    showRecord(record);
    $('#request-state').textContent = `비교 실행 완료 · ${record.executionId} · 기록 ${records.length}회`;
  } catch (error) {
    $('#request-error').textContent = `요청 오류: ${error.message} 이전 결과는 유지되며, 실패한 HTTP 요청은 DB 실행 기록으로 추가하지 않습니다.`;
    $('#request-error').hidden = false;
    $('#request-state').textContent = selected ? `새 요청 실패 · 상세 영역에는 이전 실행 ${selected.executionId} 표시 중` : '요청 실패 · 확인할 서버 실행 결과가 없습니다.';
  } finally {
    running = false;
    $('#run').disabled = false;
    $('#run').textContent = '두 방식 비교 실행';
  }
});
$('#download').addEventListener('click', () => {
  const blob = new Blob([json({ schemaVersion: 1, exportedAt: new Date().toISOString(), note: '가상 실험 데이터. 숨김 설정과 관계없이 원본 입력값과 서버 응답을 포함합니다.', records })], { type: 'application/json;charset=utf-8' });
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.download = `sqli-records-${new Date().toISOString().replaceAll(':', '-')}.json`;
  link.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
});
$('#report-toggle').addEventListener('click', () => {
  reportView = !reportView;
  document.body.classList.toggle('report-view', reportView);
  $('#report-toggle').textContent = reportView ? '실험 보기로 돌아가기' : '보고서용 보기';
  applyVisibility();
});
applyVisibility();
updateCondition();
