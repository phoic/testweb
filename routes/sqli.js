const express = require('express');
const { db } = require('../db');
const { compareLogins, createContext, runLogin, analyzeCredentials } = require('../auth/experiment');
const router = express.Router();

router.use((req, res, next) => {
  res.set('Cache-Control', 'no-store');
  next();
});
function validateInput(req, res, next) {
  if (typeof req.body?.username !== 'string' || typeof req.body?.password !== 'string') {
    return res.status(400).json({ error: '아이디와 비밀번호는 문자열이어야 합니다.' });
  }
  next();
}
router.post('/compare', validateInput, (req, res) => {
  res.json(compareLogins(db, req.body));
});

// 기존 개별 경로도 동일한 실행·응답 처리와 실제 인증 파일을 사용한다.
for (const mode of ['vulnerable', 'safe']) {
  router.post(`/${mode}-login`, validateInput, (req, res) => {
    const context = createContext(req.body);
    const result = runLogin(db, mode, context);
    const analysis = analyzeCredentials(db, context, result);
    res.json({ ...result, analysis });
  });
}
module.exports = router;
