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
const json = (value) => JSON.stringify(value, null, 2);

function condition(input) {
  return Object.values(examples).find(example => example.username === input.username && example.password === input.password)?.label || '직접 입력';
}
function currentInput() {
  return { username: $('#username').value, password: $('#password').value };
}
function updateCondition() {
  $('#input-condition').textContent = condition(currentInput());
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
  const show = $('#show-values').checked;
  $('#password').type = show ? 'text' : 'password';
  document.querySelectorAll('.sensitive').forEach(element => { element.hidden = !show; });
  document.querySelectorAll('.hidden-note').forEach(element => { element.hidden = show; });
}
$('#show-values').addEventListener('change', () => {
  applyVisibility();
  renderHistory();
});

function renderResult(mode, result) {
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
  set('.query-title', mode === 'safe' ? '실제 SQL 템플릿 · 값은 아래에서 별도 바인딩' : '실행에 사용한 SQL 문자열 · 오류 시 준비/실행 시도문');
  set('.query', result.query);
  set('.bindings', mode === 'safe' ? json(result.boundParams) : '없음 (빈 배열 []) · 입력값은 SQL 문자열에 직접 포함');
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
  renderResult('vulnerable', record.vulnerable);
  renderResult('safe', record.safe);
  $('#selected-run').textContent = `표시 중: ${record.executionId} · ${record.executedAt} (UTC) · ${record.inputCondition}`;
  const analysis = record.analysis;
  const exact = analysis.exactMatch === null ? '확인 불가' : analysis.exactMatch ? '일치' : '불일치';
  let text = `${difference(record)}\n분석용 별도 매개변수화 조회: 정확한 계정 ${exact}. `;
  text += analysis.bypassObserved === null ? '분석 DB 오류로 우회 판정 불가.' : analysis.bypassObserved ? '정확한 계정은 불일치하지만 취약 경로에서 계정이 반환되어 인증에 성공했습니다.' : '이 실행에서는 인증 우회가 관찰되지 않았습니다.';
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
applyVisibility();
updateCondition();
