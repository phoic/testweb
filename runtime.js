const { createHash, timingSafeEqual } = require('node:crypto');

function runtimeConfig(env = process.env) {
  const host = env.HOST || (env.RENDER === 'true' ? '0.0.0.0' : '127.0.0.1');
  const port = Number(env.PORT || 3000);
  if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error('PORT must be an integer from 1 to 65535');
  return { host, port, requireAccess: !['127.0.0.1', 'localhost', '::1'].includes(host) };
}
function accessGuard(config, env = process.env) {
  if (!config.requireAccess) return (req, res, next) => next();
  const username = env.LAB_ACCESS_USER || 'lab';
  const password = env.LAB_ACCESS_PASSWORD;
  const hash = value => createHash('sha256').update(value).digest();
  return (req, res, next) => {
    res.set('Cache-Control', 'no-store');
    // 외부 바인딩에서 암호 미설정 시 실습 페이지와 API를 모두 닫는다.
    if (!password) return res.status(503).send('실습 접근 암호가 설정되지 않았습니다. Render Environment에 LAB_ACCESS_PASSWORD를 설정하세요.');
    const authorization = req.headers.authorization || '';
    const credentials = authorization.startsWith('Basic ') ? Buffer.from(authorization.slice(6), 'base64').toString('utf8') : '';
    const separator = credentials.indexOf(':');
    const valid = separator >= 0 && credentials.slice(0, separator) === username
      && timingSafeEqual(hash(credentials.slice(separator + 1)), hash(password));
    if (valid) return next();
    res.set('WWW-Authenticate', 'Basic realm="SQL Learning Lab", charset="UTF-8"');
    return res.status(401).send('실습 접근 인증이 필요합니다.');
  };
}
module.exports = { runtimeConfig, accessGuard };
