// server.js
// Web Security Lab — 교육용 로컬 실습 서버
//
// 기본 실행은 localhost 전용이며, Render에서는 접근 암호로 보호한다.
// 외부 사이트를 공격하거나 대상으로 하는 기능은 포함하지 않는다.

const express = require("express");
const path = require("path");

const sqliRoutes = require("./routes/sqli");

const app = express();
const { runtimeConfig, accessGuard } = require('./runtime');
const config = runtimeConfig();
// 이 경로는 포트/프로세스 생존 확인용이며 실습 접근 설정 완료를 뜻하지 않는다.
app.get('/healthz', (req, res) => res.json({ ok: true }));
app.use(accessGuard(config));

app.use(express.json({ limit: "32kb" }));
app.get("/", (req, res) => res.redirect("/sqli.html"));
app.use(express.static(path.join(__dirname, "public")));

app.use("/api/sqli", sqliRoutes);

app.listen(config.port, config.host, () => {
  if (config.requireAccess && !process.env.LAB_ACCESS_PASSWORD) {
    console.warn('LAB_ACCESS_PASSWORD 미설정: 포트는 열렸지만 실습 페이지/API 접근은 차단됩니다.');
  }
  console.log(`\n  Web Security Lab 실행 중`);
  console.log(`  → http://${config.host}:${config.port}\n`);
});
