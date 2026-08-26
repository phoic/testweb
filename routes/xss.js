// routes/xss.js
// XSS Lab — 취약한 게시판 vs 안전한 게시판
//
// 서버는 두 게시판 모두에 대해 사용자 입력을 "있는 그대로" 저장한다.
// 실제로 안전한지 여부를 가르는 지점은 저장이 아니라 "출력"이다.
// public/js/xss.js 를 보면:
//   - vulnerable 보드는 innerHTML로 그대로 꽂아 넣어 브라우저가 HTML/스크립트로
//     해석하게 만든다.
//   - safe 보드는 HTML 특수문자(< > & " ')를 escape한 뒤 텍스트로만 출력한다.
// 이 구조를 통해 "입력 저장"과 "출력 처리"가 별개의 문제라는 것을 보여준다.

const express = require("express");
const { db, resetComments } = require("../db");

const router = express.Router();

function nowStamp() {
  return new Date().toTimeString().slice(0, 8);
}

// ---------------------------------------------------------------------------
// GET /api/xss/comments?board=vulnerable|safe
// ---------------------------------------------------------------------------
router.get("/comments", (req, res) => {
  const board = req.query.board === "safe" ? "safe" : "vulnerable";
  const rows = db
    .prepare(
      "SELECT id, content, created_at FROM comments WHERE board = ? ORDER BY id ASC"
    )
    .all(board);
  res.json({ board, comments: rows });
});

// ---------------------------------------------------------------------------
// POST /api/xss/comments   { board, content }
// ---------------------------------------------------------------------------
router.post("/comments", (req, res) => {
  const board = req.body.board === "safe" ? "safe" : "vulnerable";
  const content = typeof req.body.content === "string" ? req.body.content : "";
  const ts = nowStamp();

  const log = [`[${ts}] Comment submit received`, `[${ts}] Target board: ${board}`];

  if (!content.trim()) {
    return res.status(400).json({ error: "댓글 내용을 입력하세요.", log });
  }

  const info = db
    .prepare("INSERT INTO comments (board, content) VALUES (?, ?)")
    .run(board, content);

  log.push(`[${ts}] Comment stored in database`);
  log.push(
    board === "vulnerable"
      ? `[${ts}] Render mode: raw HTML insertion (unsafe)`
      : `[${ts}] Render mode: HTML-escaped text (safe)`
  );

  const row = db
    .prepare("SELECT id, content, created_at FROM comments WHERE id = ?")
    .get(info.lastInsertRowid);

  res.json({ comment: row, log });
});

// ---------------------------------------------------------------------------
// POST /api/xss/reset   { board }
// 발표 중 반복 실습을 위해 게시판을 초기 상태로 되돌린다.
// ---------------------------------------------------------------------------
router.post("/reset", (req, res) => {
  const board = req.body.board === "safe" ? "safe" : "vulnerable";
  resetComments(board);
  res.json({ ok: true });
});

module.exports = router;
