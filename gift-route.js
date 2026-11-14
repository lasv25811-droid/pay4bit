'use strict';
/**
 * Hədiyyə qutusu — nömrə təsdiqindən sonra, HƏR IP üçün 1 dəfə
 * AZ: 1-2 AZN. Xarici: 1-2 EUR. Balans artır.
 */

module.exports = function registerGiftRoutes(app, { admin, db, authUser, uidLimit, region }) {
  const FieldValue = admin.firestore.FieldValue;
  const round2 = n => Math.round(n * 100) / 100;

  /* İstifadəçi status yoxlaya bilər: "hədiyyə qutusunu görmək olarmı?" */
  app.get(['/gift/status', '/api/gift/status'], authUser, async (req, res) => {
    try {
      const uid = req.user.uid;
      const ip = String(req.realIp || req.ip || '').replace(/^::ffff:/i, '');
      const ipHash = require('crypto').createHash('sha256').update('yl-gift|' + ip).digest('hex');
      const [uSnap, ipSnap] = await Promise.all([
        db.collection('users').doc(uid).get(),
        db.collection('giftClaims').doc('ip_' + ipHash).get()
      ]);
      if (!uSnap.exists) return res.status(404).json({ success: false });
      const u = uSnap.data();
      const phoneOk = u.phoneVerified === true;
      const alreadyClaimed = u.giftBoxClaimed === true;
      const ipUsed = ipSnap.exists;
      const rg = region.resolveForRequest(req);

      let currency = 'AZN';
      if (!rg.isAZ) currency = 'EUR';

      res.json({
        success: true,
        canClaim: phoneOk && !alreadyClaimed && !ipUsed,
        phoneOk, alreadyClaimed, ipUsed,
        currency,
        range: rg.isAZ ? [1, 2] : [1, 2]
      });
    } catch (e) { res.status(500).json({ success: false, error: 'Server xətası' }); }
  });

  /* Hədiyyə qutusunu aç — random 1 və ya 2 vahid */
  app.post(['/gift/claim', '/api/gift/claim'], authUser, uidLimit('gift', 3, 60000), async (req, res) => {
    try {
      const uid = req.user.uid;
      const ip = String(req.realIp || req.ip || '').replace(/^::ffff:/i, '');
      const crypto = require('crypto');
      const ipHash = crypto.createHash('sha256').update('yl-gift|' + ip).digest('hex');
      const ipRef = db.collection('giftClaims').doc('ip_' + ipHash);
      const uRef = db.collection('users').doc(uid);

      // Random məbləğ: 1 və ya 2
      const winAmount = crypto.randomInt(0, 2) === 0 ? 1 : 2;
      const rg = region.resolveForRequest(req);
      const currency = rg.isAZ ? 'AZN' : 'EUR';

      let result = { success: false };
      await db.runTransaction(async tx => {
        const [uSnap, ipSnap] = await Promise.all([tx.get(uRef), tx.get(ipRef)]);
        if (!uSnap.exists) throw new Error('user_not_found');
        const u = uSnap.data();
        if (u.phoneVerified !== true) throw new Error('phone_not_verified');
        if (u.giftBoxClaimed === true) throw new Error('already_claimed');
        if (ipSnap.exists) throw new Error('ip_used');

        // Balansa əlavə et (AZ → AZN, xarici → EUR; balans həmişə AZN-də saxlanılır?)
        // DİQQƏT: Balans sistemdə AZN-də saxlanılır. EUR üçün AZN-ə çevrilir.
        let amountAzn = winAmount;
        if (currency === 'EUR') {
          // 1 EUR ≈ 1.98 AZN (statik, hədiyyə üçün)
          amountAzn = round2(winAmount * 1.98);
        }

        tx.update(uRef, {
          balance: round2((Number(u.balance) || 0) + amountAzn),
          giftBoxClaimed: true,
          giftBoxClaimedAt: FieldValue.serverTimestamp(),
          giftBoxAmount: amountAzn,
          giftBoxCurrency: currency
        });
        tx.set(ipRef, {
          uid, ip, currency, amount: amountAzn,
          claimedAt: FieldValue.serverTimestamp()
        });
        tx.set(uRef.collection('history').doc(), {
          type: 'bonus', amount: amountAzn,
          description: `Hədiyyə qutusu: +${winAmount} ${currency}`, createdAt: FieldValue.serverTimestamp()
        });
        result = { success: true, winAmount, currency, amountAzn };
      });

      res.json(result);
    } catch (e) {
      const m = e && e.message;
      if (m === 'phone_not_verified') return res.status(400).json({ success: false, error: 'Nömrə təsdiqlənməyib' });
      if (m === 'already_claimed') return res.status(409).json({ success: false, error: 'Artıq açmısınız' });
      if (m === 'ip_used') return res.status(409).json({ success: false, error: 'Bu IP-dən artıq istifadə olunub' });
      if (m === 'user_not_found') return res.status(404).json({ success: false, error: 'İstifadəçi tapılmadı' });
      console.error('[gift-claim]', e);
      res.status(500).json({ success: false, error: 'Server xətası' });
    }
  });
};