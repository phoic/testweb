const { randomUUID } = require('node:crypto');
const vulnerable = require('./vulnerable');
const parameterized = require('./parameterized');

const paths = { vulnerable, safe: parameterized };

function createContext(input) {
  const executionId = randomUUID();
  const executedAt = new Date().toISOString();
  // HTTP 처리 진입 시 생성한 수신 기록을 두 인증 경로가 공유한다.
  const requestLog = {
    at: executedAt, executionId, event: 'request_received',
    message: 'HTTP 로그인 요청 수신: 동일 입력으로 비교 실행',
  };
  return {
    executionId, executedAt, requestLog,
    input: Object.freeze({ username: input.username, password: input.password }),
  };
}

function runLogin(db, mode, context) {
  const log = [{ ...context.requestLog, mode }];
  function record(event, message, detail = {}) {
    log.push({ at: new Date().toISOString(), executionId: context.executionId, mode, event, message, ...detail });
  }
  const statement = paths[mode](db, context.input);
  record('sql_ready', '사용할 SQL 및 바인딩 값 구성 완료 (DB prepare 전)');

  let accounts = [];
  let dbError = null;
  try {
    accounts = statement.execute().map(({ id, username }) => ({ id, username }));
    record('db_completed', 'SQLite prepare 및 all() 조회 완료');
  } catch (error) {
    dbError = error.message;
    record('db_error', 'SQLite 준비 또는 조회 중 DB 오류', { error: dbError });
  }
  const matchedRows = accounts.length;
  // 두 경로에 동일하게 적용하는 인증 기준. 분석용 조회는 이 값을 바꾸지 않는다.
  const success = dbError === null && matchedRows > 0;
  const status = dbError !== null ? 'DB 오류' : success ? '인증 성공' : '인증 실패';
  record('rows_counted', `반환 행 수: ${matchedRows}`, { matchedRows });
  record('auth_decided', status, { success });
  return {
    ...context, mode, query: statement.query, boundParams: statement.boundParams,
    accounts, matchedRows, success, status, dbError, log,
  };
}

function analyzeCredentials(db, context, result) {
  const statement = parameterized(db, context.input);
  const log = [];
  function record(event, detail = {}) {
    log.push({ at: new Date().toISOString(), executionId: context.executionId, mode: 'analysis', event, ...detail });
  }
  record('exact_match_sql_ready');
  try {
    const accounts = statement.execute();
    const exactMatch = accounts.length > 0;
    const bypassObserved = result.success && !exactMatch;
    record('exact_match_completed', { matchedRows: accounts.length, exactMatch, bypassObserved });
    return { query: statement.query, boundParams: statement.boundParams, exactMatch, bypassObserved, dbError: null, log };
  } catch (error) {
    record('exact_match_error', { error: error.message });
    return { query: statement.query, boundParams: statement.boundParams, exactMatch: null, bypassObserved: null, dbError: error.message, log };
  }
}

function compareLogins(db, input) {
  const context = createContext(input);
  // 한 동기 트랜잭션에서 같은 DB 상태와 입력으로 두 인증 경로와 분석 조회를 실행한다.
  return db.transaction(() => {
    const vulnerableResult = runLogin(db, 'vulnerable', context);
    const safeResult = runLogin(db, 'safe', context);
    const analysis = analyzeCredentials(db, context, vulnerableResult);
    return { ...context, vulnerable: vulnerableResult, safe: safeResult, analysis };
  })();
}

module.exports = { compareLogins, createContext, runLogin, analyzeCredentials };
