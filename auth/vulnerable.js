// VS Code 분할 비교: parameterized.js와 같은 위치에서 비교하세요.
function prepareLogin(db, { username, password }) {
  // 사용자 입력을 SQL 문자열에 직접 결합
  const query =
    `SELECT id, username FROM users WHERE username = '${username}' AND password = '${password}'`;
  const boundParams = [];

  return {
    query,
    boundParams,
    execute() {
      return db.prepare(query).all(...boundParams);
    },
  };
}

module.exports = prepareLogin;
