// routes/sqli.js
// SQL Injection Lab — 취약한 로그인 vs 안전한 로그인
//
// 두 엔드포인트는 동일한 users 테이블을 대상으로 동일한 로직(아이디/비밀번호
// 일치 확인)을 수행하지만, SQL 쿼리를 만드는 방식이 다르다.
// 이 차이가 SQL Injection이 발생하는지 여부를 가른다.

const express = require("express");
const { db } = require("../db");

const router = express.Router();

function nowStamp() {
  return new Date().toTimeString().slice(0, 8);
}

// ---------------------------------------------------------------------------
// POST /api/sqli/vulnerable-login
// ---------------------------------------------------------------------------
router.post("/vulnerable-login", (req, res) => {
  const username = typeof req.body.username === "string" ? req.body.username : "";
  const password = typeof req.body.password === "string" ? req.body.password : "";
  const ts = nowStamp();

  // EDUCATIONAL ONLY
  // 사용자 입력을 SQL 문자열에 직접 결합하면
  // SQL Injection이 발생할 수 있다.
  // 아래 template literal은 username/password 값을 "그대로" SQL 문법의
  // 일부로 만들어 버린다. 예를 들어 username에   ' OR '1'='1' --  를 넣으면
  // WHERE 절 전체가 "항상 참"이 되어 비밀번호 검증이 무력화된다.
  const query =
    `SELECT id, username FROM users WHERE username = '${username}' ` +
    `AND password = '${password}'`;

  const log = [
    `[${ts}] Login request received`,
    `[${ts}] Authentication attempt (mode: vulnerable)`,
  ];

  let rows = [];
  let dbError = null;

  try {
    rows = db.prepare(query).all();
    log.push(`[${ts}] Database query executed`);
  } catch (err) {
    // 문법 오류 자체도 공격자에게 정보를 흘릴 수 있다는 점을 함께 보여준다.
    dbError = err.message;
    log.push(`[${ts}] Database query FAILED (SQL syntax error)`);
  }

  const success = rows.length > 0;
  log.push(`[${ts}] Result: ${success ? "SUCCESS" : "FAILED"}`);

  res.json({
    mode: "vulnerable",
    success,
    matchedRows: rows.length,
    user: success ? rows[0].username : null,
    query,
    dbError,
    log,
  });
});

// ---------------------------------------------------------------------------
// POST /api/sqli/safe-login
// ---------------------------------------------------------------------------
router.post("/safe-login", (req, res) => {
  const username = typeof req.body.username === "string" ? req.body.username : "";
  const password = typeof req.body.password === "string" ? req.body.password : "";
  const ts = nowStamp();

  // 사용자 입력과 SQL 명령의 구조를 분리한다 (Prepared Statement).
  // '?' 자리는 SQL 파서가 미리 "값이 들어올 자리"로 고정해 두기 때문에,
  // 이후 바인딩되는 입력값은 아무리 특수문자가 섞여 있어도 SQL 문법으로
  // 재해석되지 않는다. 따라서 입력값이 SQL 명령으로 해석되는 것을 방지한다.
  const queryTemplate =
    "SELECT id, username FROM users WHERE username = ? AND password = ?";

  const log = [
    `[${ts}] Login request received`,
    `[${ts}] Authentication attempt (mode: safe)`,
  ];

  let row;
  try {
    row = db.prepare(queryTemplate).get(username, password);
    log.push(`[${ts}] Parameterized query executed`);
    log.push(`[${ts}] Input treated as data, not SQL`);
  } catch (err) {
    log.push(`[${ts}] Database query FAILED`);
  }

  const success = !!row;
  log.push(`[${ts}] Result: ${success ? "SUCCESS" : "FAILED"}`);

  res.json({
    mode: "safe",
    success,
    matchedRows: row ? 1 : 0,
    user: success ? row.username : null,
    query: queryTemplate,
    boundParams: { username, password: password ? "•".repeat(Math.min(password.length, 12)) : "" },
    dbError: null,
    log,
  });
});

module.exports = router;
