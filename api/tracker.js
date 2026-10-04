const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

function b64urlDecode(s) {
  return Buffer.from(s.replace(/-/g, '+').replace(/_/g, '/'), 'base64');
}

function b64urlEncode(b) {
  return Buffer.from(b).toString('base64')
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

function verify(token, secret, userAgent) {
  if (!token || !secret) return false;
  const parts = token.split('.');
  if (parts.length !== 2) return false;

  try {
    const payload = JSON.parse(b64urlDecode(parts[0]).toString('utf8'));

    if (
      !payload ||
      typeof payload.exp !== 'number' ||
      payload.exp < Math.floor(Date.now() / 1000) ||
      !payload.ua
    ) return false;

    const uaHash = b64urlEncode(
      crypto.createHash('sha256').update(userAgent || '').digest()
    );

    if (uaHash !== payload.ua) return false;

    const expected = crypto.createHmac('sha256', secret).update(parts[0]).digest();
    const actual = b64urlDecode(parts[1]);

    return expected.length === actual.length &&
      crypto.timingSafeEqual(expected, actual);
  } catch {
    return false;
  }
}

module.exports = async function(req, res) {
  res.setHeader('Cache-Control', 'private, no-store, no-cache, must-revalidate');
  res.setHeader('X-Content-Type-Options', 'nosniff');

  const cookie = (req.headers.cookie || '')
    .split(';')
    .map(x => x.trim())
    .find(x => x.startsWith('clad_session='));

  const token = cookie ? decodeURIComponent(cookie.slice('clad_session='.length)) : '';
  const ok = verify(
    token,
    process.env.CLAD_SESSION_SECRET,
    req.headers['user-agent'] || ''
  );

  if (!ok) {
    res.statusCode = 302;
    res.setHeader('Location', '/activate.html');
    res.end();
    return;
  }

  try {
    const file = fs.readFileSync(path.join(process.cwd(), 'index.html'));
    res.statusCode = 200;
    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    res.end(file);
  } catch (err) {
    res.statusCode = 500;
    res.setHeader('Content-Type', 'text/plain; charset=utf-8');
    res.end('Unable to load CLADHABITS.');
  }
};
