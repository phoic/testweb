# Web Security Lab

SQL Injection과 XSS(Cross-Site Scripting)의 발생 원리를, **취약한 버전**과
**방어된 버전**을 나란히 놓고 같은 입력으로 비교 실험할 수 있는 교육용
로컬 웹 애플리케이션입니다. 고등학생 진로탐색 발표를 위해 만들어졌으며,
`localhost` 밖의 어떤 대상도 공격하지 않습니다.

---

## 1. 프로젝트 목적

이 프로젝트는 실제 웹사이트를 공격하기 위한 도구가 아닙니다. 직접 만든
`localhost` 환경 안에서

- 왜 특정 코드가 SQL Injection이나 XSS에 취약해지는지
- 그 취약점을 막는 코드는 무엇을 다르게 하는지

를 눈으로 직접 확인하고, 발표 자리에서 시연할 수 있도록 만든 학습용
샌드박스입니다. 모든 계정과 댓글은 가짜 데이터이며, 외부 서버나 실제
서비스와는 연결되지 않습니다.

---

## 2. 설치 방법

Node.js(권장 18 버전 이상)와 npm이 설치되어 있어야 합니다.

```bash
cd web-security-lab
npm install
```

`npm install`은 이 프로젝트가 사용하는 두 패키지, 웹 서버 프레임워크인
`express`와 파일 기반 데이터베이스 드라이버인 `better-sqlite3`를
내려받습니다.

---

## 3. 실행 방법

```bash
npm start
```

터미널에 아래와 같은 메시지가 보이면 정상적으로 실행된 것입니다.

```text
Web Security Lab 실행 중
→ http://localhost:3000
```

브라우저에서 `http://localhost:3000` 으로 접속하면 대시보드가 열립니다.
데이터베이스 파일(`data/lab.db`)은 최초 실행 시 자동으로 생성되고, 테스트
계정과 초기 댓글이 함께 시딩됩니다.

---

## 4. 프로젝트 구조

```text
web-security-lab/
├── package.json          의존성 정의(express, better-sqlite3)
├── server.js              Express 서버 진입점, 정적 파일 서빙 + 라우터 연결
├── db.js                  SQLite 초기화, 테이블 생성, 테스트 데이터 시딩
├── routes/
│   ├── sqli.js             /api/sqli/vulnerable-login, /api/sqli/safe-login
│   └── xss.js               /api/xss/comments (GET/POST), /api/xss/reset
├── public/
│   ├── index.html           대시보드
│   ├── sqli.html             SQL Injection Lab 화면
│   ├── xss.html               XSS Lab 화면
│   ├── css/style.css          공통 다크 테마 스타일
│   └── js/
│       ├── dashboard.js       대시보드 상태 표시
│       ├── sqli.js             SQL Injection Lab 동작 로직
│       └── xss.js               XSS Lab 동작 로직
└── data/
    └── lab.db                SQLite 데이터베이스 파일 (최초 실행 시 자동 생성)
```

**역할 요약**

- `db.js`는 `users`(로그인 테스트 계정)와 `comments`(게시판 댓글) 두
  테이블을 관리합니다. 두 테이블 모두 가짜 데이터만 담습니다.
- `routes/sqli.js`는 완전히 같은 로그인 로직을, "문자열을 이어 붙인
  쿼리"(취약)와 "Prepared Statement"(안전) 두 가지 방식으로 각각
  구현합니다.
- `routes/xss.js`는 두 게시판 모두 입력을 그대로 저장합니다 — XSS 방어는
  저장이 아니라 **출력 시점**에서 이루어진다는 것을 보여주기 위한 설계이며,
  실제 escape 처리는 `public/js/xss.js`에서 화면에 그릴 때 수행합니다.

---

## 5. SQL Injection 원리

웹 앱은 보통 사용자 입력을 SQL 쿼리에 끼워 넣어 데이터베이스에 물어봅니다.
문제는 **"어떻게 끼워 넣는가"**입니다.

```js
// 취약한 방식 — 문자열을 그대로 이어 붙인다
const query = `SELECT * FROM users WHERE username = '${username}'
               AND password = '${password}'`;
```

`username`에 `' OR '1'='1' -- ` 를 넣으면 실제로 실행되는 쿼리는 다음과
같아집니다.

```sql
SELECT * FROM users WHERE username = '' OR '1'='1' -- ' AND password = '...'
```

- `OR '1'='1'` 은 항상 참이므로 WHERE 조건 전체가 참이 되어 모든 행이
  조회 대상이 됩니다.
- `--` 는 SQL의 한 줄 주석 기호이기 때문에, 그 뒤에 있던 원래의 비밀번호
  비교 조건은 통째로 무시됩니다.

즉, 사용자가 입력한 값이 데이터가 아니라 **SQL 문법의 일부**로
해석되면서 인증 로직이 우회되는 것입니다.

---

## 6. XSS 원리

XSS는 사용자 입력이 브라우저에서 **HTML/JavaScript로 해석**될 때
발생합니다.

```js
// 취약한 방식 — 저장된 댓글을 그대로 HTML에 삽입한다
commentElement.innerHTML = comment.content;
```

댓글에 `<img src=x onerror="alert('XSS')">` 를 남기면, 브라우저는 이
문자열을 "글자"가 아니라 "이미지 태그"로 해석합니다. `src=x`는 존재하지
않는 이미지이므로 로딩에 실패하고, 그 순간 `onerror` 속성에 적힌
JavaScript가 실행됩니다. 실제 서비스라면 이 방식으로 다른 방문자의
브라우저에서 임의의 스크립트를 실행시킬 수 있습니다.

---

## 7. 취약한 코드와 안전한 코드의 차이

| 구분 | 취약한 방식 | 안전한 방식 |
|---|---|---|
| SQL Injection | 사용자 입력을 SQL 문자열에 직접 결합 | Prepared Statement로 쿼리 구조와 입력값을 분리 |
| XSS | 저장된 값을 `innerHTML`로 그대로 출력 | 출력 직전 `< > & " '` 를 HTML 엔티티로 escape 후 출력 |

두 경우 모두 공통점이 있습니다. **"사용자 입력"과 "코드(SQL 문법 또는
HTML 마크업)"가 뒤섞이는 순간 취약점이 생기고, 이 둘을 구조적으로
분리하는 순간 방어가 됩니다.**

---

## 8. 실험 방법

1. 대시보드에서 원하는 Lab으로 이동합니다.
2. 상단의 테스트 계정 칩(SQLi) 또는 페이로드 칩(XSS)을 눌러 두 입력창에
   동일한 값을 채웁니다.
3. Vulnerable / Secure 버튼을 각각 눌러 동일한 입력을 두 시스템에
   보냅니다.
4. 입력 → 서버 → DB/브라우저로 이어지는 흐름 다이어그램과, 실제로 실행된
   쿼리(또는 렌더링 방식)를 확인합니다.
5. 하단 Security Monitor 로그와 보안 분석 패널에서 왜 그런 결과가
   나왔는지 다시 확인합니다.

---

## 9. 방어 방법 요약

- **SQL Injection** → Prepared Statement / parameterized query를 사용해
  쿼리 구조와 사용자 입력을 분리한다. (`db.prepare(sql).get(param1, param2)`)
- **XSS** → 사용자 입력을 화면에 출력하기 직전, 항상 `< > & " '` 를 HTML
  엔티티로 escape한다. 저장 시점이 아니라 출력 시점에 처리하는 것이
  핵심이다.

---

## 10. 발표에서 사용할 수 있는 실험 시나리오

**시나리오 A — 정상 로그인 비교**
`alice / password123`으로 두 로그인에 각각 로그인해 정상 동작이 동일함을
먼저 보여줍니다.

**시나리오 B — SQL Injection 우회**
Vulnerable Login의 Username에 `' OR '1'='1' -- ` 를 입력하고 비밀번호는
아무 값이나 넣습니다. 취약한 로그인은 뚫리고, Secure Login은 동일한
입력에도 로그인에 실패하는 것을 보여줍니다. 이때 실제 실행된 SQL 쿼리
텍스트를 함께 보여주면 "왜" 뚫렸는지가 명확해집니다.

**시나리오 C — XSS 실행 vs 무력화**
`<img src=x onerror="alert('XSS 실행됨!')">` 를 두 게시판에 각각
남깁니다. Vulnerable Board에서는 실제로 알림창이 뜨고, Secure Board에는
그 문자열이 그대로 "글자"로만 보이는 차이를 보여줍니다.

**시나리오 D — 방어 코드 대조**
`routes/sqli.js`의 두 엔드포인트, `public/js/xss.js`의 렌더링 분기를
화면에 띄워 놓고 코드 몇 줄 차이가 결과를 완전히 바꾼다는 점을 강조하며
마무리합니다.

---

## 안전 관련 안내

이 프로젝트는 다음을 포함하지 않습니다.

- 실제 외부 웹사이트나 서비스에 대한 공격 기능
- 실제 계정 정보 수집 또는 실제 개인정보 저장
- 외부 시스템을 대상으로 하는 자동화된 공격 도구

모든 실습은 이 컴퓨터의 `localhost` 안에서만 동작하도록 설계되었습니다.
# testweb
