// Spendly bank-SMS inbox. An iPhone Shortcut POSTs each debit SMS here; Spendly pulls and acknowledges them.
// Env: SPENDLY_KEY (shared secret), BLOB_READ_WRITE_TOKEN (Vercel Blob). Messages are AES-GCM encrypted at rest.
const crypto = require('crypto');
const { put, list, del } = require('@vercel/blob');
const same = (a, b) => { const x = Buffer.from(String(a || '')), y = Buffer.from(String(b || '')); return x.length === y.length && crypto.timingSafeEqual(x, y); };
const ck = () => crypto.createHash('sha256').update('spendly-sms:' + process.env.SPENDLY_KEY).digest();
const enc = t => { const iv = crypto.randomBytes(12), c = crypto.createCipheriv('aes-256-gcm', ck(), iv), b = Buffer.concat([c.update(t, 'utf8'), c.final()]); return Buffer.concat([iv, c.getAuthTag(), b]).toString('base64'); };
const dec = s => { const b = Buffer.from(s, 'base64'), d = crypto.createDecipheriv('aes-256-gcm', ck(), b.subarray(0, 12)); d.setAuthTag(b.subarray(12, 28)); return Buffer.concat([d.update(b.subarray(28)), d.final()]).toString('utf8'); };
const tok = () => crypto.createHmac('sha256', String(process.env.SPENDLY_KEY)).update('spendly-cookie').digest('hex');
const ck2 = req => { const m = String(req.headers.cookie || '').match(/(?:^|;\s*)spendly_auth=([a-f0-9]+)/); return m ? m[1] : ''; };
const MONEY = /(?:rs\.?|inr|₹)\s*[\d]/i, TXN = /\b(debited|credited|spent|withdrawn|purchase)\b/i;
const body = req => { let b = req.body; if (typeof b === 'string') { try { b = JSON.parse(b); } catch (e) { b = Object.fromEntries(new URLSearchParams(b)); } } return b || {}; };
module.exports = async (req, res) => {
  res.setHeader('Cache-Control', 'no-store'); res.setHeader('Access-Control-Allow-Origin', '*'); res.setHeader('Access-Control-Allow-Headers', 'x-spendly-key, content-type');
  if (req.method === 'OPTIONS') return res.status(204).end();
  const q = req.query || {};
  if (q.a === 'ping') return res.status(200).json({ ok: true, key: !!process.env.SPENDLY_KEY, blob: !!process.env.BLOB_READ_WRITE_TOKEN });
  if (!process.env.SPENDLY_KEY || !process.env.BLOB_READ_WRITE_TOKEN) return res.status(500).json({ error: 'Server is not configured.' });
  try {
    const b = body(req), key = req.headers['x-spendly-key'] || b.key || b.k;
    const okKey = same(key, process.env.SPENDLY_KEY), okCookie = same(ck2(req), tok());
    if (!okKey && !okCookie) return res.status(401).json({ error: 'Wrong or missing key.' });
    if (req.method === 'POST' && q.a === 'login') {
      if (!okKey) return res.status(401).json({ error: 'Wrong or missing key.' });
      res.setHeader('Set-Cookie', 'spendly_auth=' + tok() + '; Max-Age=31536000; Path=/; HttpOnly; Secure; SameSite=Strict');
      return res.status(200).json({ ok: true });
    }
    if (req.method === 'GET') {
      const { blobs } = await list({ prefix: 'sms/', limit: 200 });
      const msgs = (await Promise.all(blobs.map(async x => { try { const j = await (await fetch(x.url + '?t=' + Date.now())).json(); return { id: x.pathname, at: j.at, t: dec(j.c) }; } catch (e) { return null; } }))).filter(Boolean).sort((p, q) => p.at - q.at);
      return res.status(200).json({ msgs });
    }
    if (req.method === 'POST' && q.a === 'ack') {
      const ids = new Set((Array.isArray(b.ids) ? b.ids : []).map(String));
      if (!ids.size) return res.status(200).json({ ok: true, removed: 0 });
      const { blobs } = await list({ prefix: 'sms/', limit: 500 }), urls = blobs.filter(x => ids.has(x.pathname)).map(x => x.url);
      if (urls.length) await del(urls);
      return res.status(200).json({ ok: true, removed: urls.length });
    }
    if (req.method === 'POST') {
      const t = String(b.text || b.t || b.message || '').trim().slice(0, 2000);
      if (!t || !MONEY.test(t) || !TXN.test(t)) return res.status(200).json({ ok: true, ignored: true });
      await put('sms/' + Date.now() + '-' + crypto.randomBytes(4).toString('hex') + '.json', JSON.stringify({ at: Date.now(), c: enc(t) }), { access: 'public', addRandomSuffix: false, contentType: 'application/json' });
      return res.status(200).json({ ok: true });
    }
    return res.status(405).json({ error: 'Method not allowed.' });
  } catch (e) { return res.status(500).json({ error: String(e && e.message || e).slice(0, 120) }); }
};
