'use strict';
const crypto = require('crypto');

const NICK_RE = /^[a-zA-Z0-9_]{3,16}$/;
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/;
const CODE_TTL_MS = 10 * 60 * 1000;
const RESEND_MS = 60 * 1000;
const MAX_SENDS_PER_HOUR = 5;
const MAX_ATTEMPTS = 5;
const IP_MAX_PER_HOUR = 30;

const nickToEmail = n => `${n.toLowerCase()}@yevroloto.app`;
const maskEmail = e => {
  const [local, domain] = e.split('@');
  return local[0] + '*'.repeat(Math.max(local.length - 1, 4)) + '@' + domain;
};
const hashCode = (uid, code) =>
  crypto.createHash('sha256').update(`${uid}|${code}|yl-reset`).digest('hex');

class HttpErr extends Error {
  constructor(status, message) { super(message); this.status = status; }
}

async function sendMail(to, code) {
  const key = process.env.BREVO_API_KEY;
  const from = process.env.MAIL_FROM;
  if (!key || !from) throw new Error('BREVO_API_KEY / MAIL_FROM təyin olunmayıb');
  const r = await fetch('https://api.brevo.com/v3/smtp/email', {
    method: 'POST',
    headers: { 'api-key': key, 'Content-Type': 'application/json', Accept: 'application/json' },
    body: JSON.stringify({
      sender: { name: process.env.MAIL_FROM_NAME || 'YevroLato', email: from },
      to: [{ email: to }],
      subject: 'YevroLato — şifrə yeniləmə kodu',
      textContent: `Şifrə yeniləmə kodunuz: ${code}\n\nKod 10 dəqiqə etibarlıdır. Bunu siz istəməmisinizsə, bu məktubu nəzərə almayın.`,
      htmlContent: `<div style="font-family:Arial,sans-serif;max-width:420px;margin:auto;padding:24px;border-radius:14px;background:#06261b;color:#e8f6ee">
        <h2 style="margin:0 0 12px;color:#e6c87a">YevroLato</h2>
        <p>Şifrə yeniləmə kodunuz:</p>
        <p style="font-size:34px;font-weight:800;letter-spacing:8px;margin:12px 0;color:#fff">${code}</p>
        <p style="color:#8fb3a3;font-size:13px">Kod 10 dəqiqə etibarlıdır. Bunu siz istəməmisinizsə, məktubu nəzərə almayın.</p></div>`
    }),
    signal: AbortSignal.timeout(15000)
  });
  if (!r.ok) {
    const t = await r.text().catch(() => '');
    throw new Error('Brevo ' + r.status + ' ' + t.slice(0, 200));
  }
}

module.exports = function registerPasswordResetRoutes(app, { admin, db }) {
  const ipHits = new Map();
  function ipAllowed(ip) {
    const now = Date.now();
    const arr = (ipHits.get(ip) || []).filter(t => now - t < 3600000);
    if (arr.length >= IP_MAX_PER_HOUR) { ipHits.set(ip, arr); return false; }
    arr.push(now); ipHits.set(ip, arr);
    return true;
  }

  async function findAccount(nick) {
    if (typeof nick !== 'string' || !NICK_RE.test(nick)) throw new HttpErr(400, 'Ləqəb düzgün deyil');
    let uid;
    try { uid = (await admin.auth().getUserByEmail(nickToEmail(nick))).uid; }
    catch (_) { throw new HttpErr(404, 'Bu ləqəblə hesab tapılmadı'); }

    const adm = await db.collection('admins').doc(uid).get();
    if (adm.exists && adm.data().active === true) {
      throw new HttpErr(403, 'Bu hesab üçün şifrə yeniləmə mümkün deyil');
    }
    const u = await db.collection('users').doc(uid).get();
    const email = u.exists ? String(u.data().email || '').trim() : '';
    if (!EMAIL_RE.test(email)) throw new HttpErr(400, 'Bu hesaba e-mail bağlanmayıb. Dəstəyə yazın.');
    return { uid, email };
  }

  const wrap = fn => async (req, res) => {
    try {
      if (!ipAllowed(req.ip)) throw new HttpErr(429, 'Çox cəhd edildi, sonra yenidən yoxlayın');
      res.json({ success: true, ...(await fn(req.body || {})) });
    } catch (e) {
      if (e instanceof HttpErr) return res.status(e.status).json({ success: false, error: e.message });
      console.error('[password-reset]', e);
      res.status(500).json({ success: false, error: 'Server xətası, bir az sonra yenidən yoxlayın' });
    }
  };

  app.post(['/password-reset/lookup', '/api/password-reset/lookup'], wrap(async (b) => {
    const { email } = await findAccount(b.nick);
    return { masked: maskEmail(email) };
  }));

  app.post(['/password-reset/send', '/api/password-reset/send'], wrap(async (b) => {
    const { uid, email } = await findAccount(b.nick);
    const ref = db.collection('passwordResets').doc(uid);
    const now = Date.now();
    const d = (await ref.get()).data() || {};

    if (d.sentAt && now - d.sentAt < RESEND_MS) throw new HttpErr(429, 'Bir az gözləyin, sonra yenidən göndərin');
    let hourStart = d.hourStart || now, hourCount = d.hourCount || 0;
    if (now - hourStart > 3600000) { hourStart = now; hourCount = 0; }
    if (hourCount >= MAX_SENDS_PER_HOUR) throw new HttpErr(429, 'Çox cəhd edildi. 1 saat sonra yoxlayın');

    const code = String(crypto.randomInt(100000, 1000000));
    await ref.set({
      codeHash: hashCode(uid, code), expiresAt: now + CODE_TTL_MS,
      attempts: 0, sentAt: now, hourStart, hourCount: hourCount + 1
    });
    try { await sendMail(email, code); }
    catch (e) {
      console.error('[password-reset] mail xətası:', e.message);
      await ref.delete().catch(() => {});
      throw new HttpErr(502, 'E-mail göndərilmədi, bir az sonra yenidən yoxlayın');
    }
    return {};
  }));

  app.post(['/password-reset/confirm', '/api/password-reset/confirm'], wrap(async (b) => {
    const { nick, code, newPassword } = b;
    if (typeof code !== 'string' || !/^\d{6}$/.test(code)) throw new HttpErr(400, 'Kod 6 rəqəm olmalıdır');
    if (typeof newPassword !== 'string' || newPassword.length < 6 || newPassword.length > 64) {
      throw new HttpErr(400, 'Şifrə 6–64 simvol olmalıdır');
    }
    const { uid } = await findAccount(nick);
    const ref = db.collection('passwordResets').doc(uid);
    const snap = await ref.get();
    if (!snap.exists) throw new HttpErr(400, 'Əvvəlcə kod göndərin');
    const d = snap.data();

    if (Date.now() > d.expiresAt) {
      await ref.delete().catch(() => {});
      throw new HttpErr(400, 'Kodun vaxtı bitib. Yenidən kod göndərin');
    }
    if (d.attempts >= MAX_ATTEMPTS) {
      await ref.delete().catch(() => {});
      throw new HttpErr(429, 'Çox yanlış cəhd. Yeni kod istəyin');
    }
    const a = Buffer.from(hashCode(uid, code)), c = Buffer.from(d.codeHash);
    if (a.length !== c.length || !crypto.timingSafeEqual(a, c)) {
      await ref.update({ attempts: admin.firestore.FieldValue.increment(1) });
      throw new HttpErr(400, 'Kod yanlışdır');
    }
    await admin.auth().updateUser(uid, { password: newPassword });
    await admin.auth().revokeRefreshTokens(uid);
    await ref.delete().catch(() => {});
    return {};
  }));
};
