// db.js
// SQLite 데이터베이스 초기화 및 발표용 테스트 데이터 시딩.
// 이 파일에서 생성되는 계정과 댓글은 전부 가짜 데이터이며,
// 실제 개인정보나 실제 서비스 계정과는 아무 관련이 없다.

const path = require("path");
const Database = require("better-sqlite3");

const dbPath = path.join(__dirname, "data", "lab.db");
const db = new Database(dbPath);

db.pragma("journal_mode = WAL");

// ---------------------------------------------------------------------------
// 테이블 생성
// ---------------------------------------------------------------------------

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    password TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS comments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    board TEXT NOT NULL CHECK (board IN ('vulnerable', 'safe')),
    content TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now', 'localtime'))
  );
`);

// ---------------------------------------------------------------------------
// 시드 데이터 (발표용 가짜 계정 / 초기 댓글)
// ---------------------------------------------------------------------------

const userCount = db.prepare("SELECT COUNT(*) AS n FROM users").get().n;

if (userCount === 0) {
  const insertUser = db.prepare(
    "INSERT INTO users (username, password) VALUES (?, ?)"
  );
  const seedUsers = [
    ["alice", "password123"],
    ["bob", "test1234"],
    ["carol", "letmein00"],
  ];
  const insertMany = db.transaction((rows) => {
    for (const row of rows) insertUser.run(row[0], row[1]);
  });
  insertMany(seedUsers);
}

const commentCount = db.prepare("SELECT COUNT(*) AS n FROM comments").get().n;

if (commentCount === 0) {
  const insertComment = db.prepare(
    "INSERT INTO comments (board, content) VALUES (?, ?)"
  );
  const seedComments = db.transaction(() => {
    insertComment.run("vulnerable", "환영합니다! 이 게시판은 실습용입니다.");
    insertComment.run("safe", "환영합니다! 이 게시판은 실습용입니다.");
  });
  seedComments();
}

// ---------------------------------------------------------------------------
// 초기화 유틸리티 (대시보드의 "초기화" 버튼에서 사용)
// ---------------------------------------------------------------------------

function resetComments(board) {
  db.prepare("DELETE FROM comments WHERE board = ?").run(board);
  db.prepare("INSERT INTO comments (board, content) VALUES (?, ?)").run(
    board,
    "환영합니다! 이 게시판은 실습용입니다."
  );
}

module.exports = { db, resetComments };
