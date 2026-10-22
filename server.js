// server.js
// Web Security Lab — 교육용 로컬 실습 서버
//
// 이 서버는 localhost 전용으로 설계되었다.
// 외부 사이트를 공격하거나 대상으로 하는 기능은 포함하지 않는다.

const express = require("express");
const path = require("path");

const sqliRoutes = require("./routes/sqli");

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json({ limit: "32kb" }));
app.get("/", (req, res) => res.redirect("/sqli.html"));
app.use(express.static(path.join(__dirname, "public")));

app.use("/api/sqli", sqliRoutes);

app.listen(PORT, "127.0.0.1", () => {
  console.log(`\n  Web Security Lab 실행 중`);
  console.log(`  → http://127.0.0.1:${PORT}\n`);
});
