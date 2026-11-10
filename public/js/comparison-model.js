// 실제 서버 응답의 표시만 해석하며 인증 결과를 생성하거나 바꾸지 않는다.
(function (root) {
  const payload = "' OR '1'='1' -- ";
  const prefix = "SELECT id, username FROM users WHERE username = '";
  function verdict(record, mode) {
    const result = record[mode];
    const unknown = result.dbError !== null || record.analysis.exactMatch === null || record.analysis.dbError !== null;
    const bypass = unknown ? '판정 불가' : result.success && !record.analysis.exactMatch ? '발생' : '발생하지 않음';
    const interpretation = result.dbError !== null ? 'SQL 오류로 인증 결과를 해석할 수 없음'
      : !result.success ? '일치하는 계정이 없어 인증 실패'
      : bypass === '발생' ? '인증 우회 관찰'
      : bypass === '판정 불가' ? '인증 성공 · 기준 조회 오류로 우회 판정 불가' : '정상 인증 성공';
    return { bypass, interpretation };
  }
  function explainable(record) {
    return record.input.username === payload && record.input.password === 'anything'
      && record.vulnerable.query === prefix + payload + "' AND password = 'anything'"
      && record.safe.query === 'SELECT id, username FROM users WHERE username = ? AND password = ?'
      && JSON.stringify(record.safe.boundParams) === JSON.stringify([payload, 'anything']);
  }
  function sqlParts(record) {
    if (!explainable(record)) return [{ text: record.vulnerable.query, kind: '' }];
    return [
      { text: prefix, kind: '' },
      { text: "'", kind: 'close-string' },
      { text: ' ', kind: '' },
      { text: "OR '1'='1'", kind: 'true-condition' },
      { text: ' ', kind: '' },
      { text: "-- ' AND password = 'anything'", kind: 'commented' },
    ];
  }
  function summary(record) {
    if (record.vulnerable.dbError !== null || record.safe.dbError !== null) return 'SQL 오류가 발생했습니다. 일반적인 인증 실패와 구분해 결과를 확인하세요.';
    if (record.analysis.dbError !== null || record.analysis.exactMatch === null) return '기준 조회가 실패하여 인증 우회 여부를 판정할 수 없습니다.';
    if (record.analysis.exactMatch && record.vulnerable.success && record.safe.success) return '두 방식 모두 일치하는 계정을 조회하여 인증에 성공했습니다.';
    if (explainable(record) && verdict(record, 'vulnerable').bypass === '발생' && !record.safe.success) return '같은 입력이 왼쪽에서는 조회 조건을 바꿨고, 오른쪽에서는 아이디 값으로 처리되었습니다.';
    if (!record.vulnerable.success && !record.safe.success) return '두 방식 모두 일치하는 계정이 없어 인증에 실패했습니다.';
    return '두 방식의 실제 조회 결과가 다릅니다. 반환 계정과 인증 우회 판정을 확인하세요.';
  }
  const api = { verdict, explainable, sqlParts, summary };
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
  else root.ComparisonModel = api;
})(globalThis);
