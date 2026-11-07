'use strict';
const crypto = require('crypto');

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/;
const AUTO_MAIL_RE = /@(phone\.)?yevroloto\.app$/i;
const CODE_TTL_MS = 10 * 60 * 1000;
const RESEND_MS = 60 * 1000;
const MAX_SENDS_PER_HOUR = 5;
const MAX_ATTEMPTS = 5;
const IP_MAX_PER_HOUR = 40;

class HttpErr extends Error {
  constructor(status, message, extra) { super(message); this.status = status; this.extra = extra || {}; }
}

const maskEmail = e => {
  const [local, domain] = e.split('@');
  return local[0] + '*'.repeat(Math.max(local.length - 1, 3)) + '@' + domain;
};
const hashCode = (uid, email, code) =>
  crypto.createHash('sha256').update(`${uid}|${email}|${code}|yl-email`).digest('hex');

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
      subject: 'YevroLato — e-poçt təsdiq kodu',
      textContent: `E-poçt təsdiq kodunuz: ${code}\n\nKod 10 dəqiqə etibarlıdır. Bunu siz istəməmisinizsə, bu məktubu nəzərə almayın.`,
      htmlContent: `<div style="font-family:Arial,sans-serif;max-width:420px;margin:auto;padding:24px;border-radius:14px;background:#06261b;color:#e8f6ee">
        <h2 style="margin:0 0 12px;color:#e6c87a">YevroLato</h2>
        <p>E-poçt təsdiq kodunuz:</p>
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

module.exports = function registerEmailVerifyRoutes(app, { admin, db }) {
  const ipHits = new Map();
  const ipAllowed = ip => {
    const now = Date.now();
    const arr = (ipHits.get(ip) || []).filter(t => now - t < 3600000);
    if (arr.length >= IP_MAX_PER_HOUR) { ipHits.set(ip, arr); return false; }
    arr.push(now); ipHits.set(ip, arr);
    return true;
  };

  async function authUid(req) {
    const h = String(req.headers.authorization || '');
    const m = h.match(/^Bearer (.+)$/);
    if (!m) throw new HttpErr(401, 'Təhlükəsizlik üçün yenidən daxil olun');
    try { return (await admin.auth().verifyIdToken(m[1])).uid; }
    catch (_) { throw new HttpErr(401, 'Təhlükəsizlik üçün yenidən daxil olun'); }
  }

  async function loadUser(uid) {
    const snap = await db.collection('users').doc(uid).get();
    if (!snap.exists) throw new HttpErr(404, 'Hesab tapılmadı');
    const d = snap.data();
    if (d.banned === true) throw new HttpErr(403, 'Hesab bloklanıb');
    const email = String(d.email || '').trim().toLowerCase();
    if (!EMAIL_RE.test(email) || AUTO_MAIL_RE.test(email)) throw new HttpErr(400, 'Əvvəlcə düzgün e-poçt əlavə edin');
    return { data: d, email };
  }

  const wrap = fn => async (req, res) => {
    try {
      if (!ipAllowed(req.ip)) throw new HttpErr(429, 'Çox cəhd edildi, sonra yenidən yoxlayın');
      const uid = await authUid(req);
      res.json({ success: true, ...(await fn(uid, req.body || {})) });
    } catch (e) {
      if (e instanceof HttpErr) return res.status(e.status).json({ success: false, error: e.message, ...e.extra });
      console.error('[email-verify]', e);
      res.status(500).json({ success: false, error: 'Server xətası, bir az sonra yenidən yoxlayın' });
    }
  };

  app.post(['/email-verify/send', '/api/email-verify/send'], wrap(async (uid) => {
    const { data, email } = await loadUser(uid);
    if (data.emailVerified === true && String(data.emailVerifiedFor || '') === email) return { alreadyVerified: true };

    const taken = await db.collection('users').where('emailVerifiedFor', '==', email).limit(5).get();
    if (taken.docs.some(d => d.id !== uid && d.data().emailVerified === true)) throw new HttpErr(409, 'Bu e-poçt başqa hesabda doğrulanıb');

    const ref = db.collection('emailVerifications').doc(uid);
    const now = Date.now();
    const d = (await ref.get()).data() || {};
    if (d.sentAt && now - d.sentAt < RESEND_MS) {
      const wait = Math.ceil((RESEND_MS - (now - d.sentAt)) / 1000);
      throw new HttpErr(429, `${wait} saniyə sonra yenidən göndərin`, { retryAfter: wait });
    }
    let hourStart = d.hourStart || now, hourCount = d.hourCount || 0;
    if (now - hourStart > 3600000) { hourStart = now; hourCount = 0; }
    if (hourCount >= MAX_SENDS_PER_HOUR) throw new HttpErr(429, 'Çox cəhd edildi. 1 saat sonra yoxlayın', { retryAfter: 3600 });

    const code = String(crypto.randomInt(100000, 1000000));
    await ref.set({
      email, codeHash: hashCode(uid, email, code), expiresAt: now + CODE_TTL_MS,
      attempts: 0, sentAt: now, hourStart, hourCount: hourCount + 1
    });
    try { await sendMail(email, code); }
    catch (e) {
      console.error('[email-verify] mail xətası:', e.message);
      await ref.delete().catch(() => {});
      throw new HttpErr(502, 'E-poçt göndərilmədi, bir az sonra yenidən yoxlayın');
    }
    return { masked: maskEmail(email), cooldown: RESEND_MS / 1000 };
  }));

  app.post(['/email-verify/confirm', '/api/email-verify/confirm'], wrap(async (uid, b) => {
    const code = b.code;
    if (typeof code !== 'string' || !/^\d{6}$/.test(code)) throw new HttpErr(400, 'Kod 6 rəqəm olmalıdır');
    const { email } = await loadUser(uid);
    const ref = db.collection('emailVerifications').doc(uid);
    const snap = await ref.get();
    if (!snap.exists) throw new HttpErr(400, 'Əvvəlcə kod göndərin');
    const d = snap.data();

    if (d.email !== email) {
      await ref.delete().catch(() => {});
      throw new HttpErr(400, 'E-poçt dəyişib. Yeni kod istəyin');
    }
    if (Date.now() > d.expiresAt) {
      await ref.delete().catch(() => {});
      throw new HttpErr(400, 'Kodun vaxtı bitib. Yenidən kod göndərin');
    }
    if (d.attempts >= MAX_ATTEMPTS) {
      await ref.delete().catch(() => {});
      throw new HttpErr(429, 'Çox yanlış cəhd. Yeni kod istəyin');
    }
    const a = Buffer.from(hashCode(uid, email, code)), c = Buffer.from(d.codeHash);
    if (a.length !== c.length || !crypto.timingSafeEqual(a, c)) {
      await ref.update({ attempts: admin.firestore.FieldValue.increment(1) });
      throw new HttpErr(400, 'Kod yanlışdır');
    }

    const taken = await db.collection('users').where('emailVerifiedFor', '==', email).limit(5).get();
    if (taken.docs.some(x => x.id !== uid && x.data().emailVerified === true)) throw new HttpErr(409, 'Bu e-poçt başqa hesabda doğrulanıb');

    const uref = db.collection('users').doc(uid);
    const result = await db.runTransaction(async tx => {
      const u = (await tx.get(uref)).data() || {};
      if (String(u.email || '').trim().toLowerCase() !== email) throw new HttpErr(400, 'E-poçt dəyişib. Yeni kod istəyin');
      const upd = {
        emailVerified: true,
        emailVerifiedFor: email,
        emailVerifiedAt: admin.firestore.FieldValue.serverTimestamp()
      };
      let spinBonus = 0, spins = Math.max(0, Math.floor(Number(u.payWheelSpins) || 0));
      if (u.emailSpinGiven !== true) {          // 1 PayÇarx, yalnız bir dəfə
        spinBonus = 1; spins += 1;
        upd.payWheelSpins = spins;
        upd.emailSpinGiven = true;
        tx.set(uref.collection('history').doc(), {
          type: 'bonus', amount: 0, description: 'E-poçt doğrulama: 1 PayÇarx',
          createdAt: admin.firestore.FieldValue.serverTimestamp()
        });
      }
      tx.update(uref, upd);
      return { spinBonus, spins };
    });
    await ref.delete().catch(() => {});
    return result;
  }));
};
