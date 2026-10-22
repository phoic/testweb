// VS Code 분할 비교: vulnerable.js와 같은 위치에서 비교하세요.
function prepareLogin(db, { username, password }) {
  // SQL 구조 고정
  const query =
    'SELECT id, username FROM users WHERE username = ? AND password = ?';
  const boundParams = [username, password];

  return {
    query,
    boundParams,
    execute() {
      return db.prepare(query).all(...boundParams); // 입력값을 매개변수로 바인딩
    },
  };
}

module.exports = prepareLogin;
