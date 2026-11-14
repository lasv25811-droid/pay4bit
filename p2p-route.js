'use strict';
/**
 * P2P (USDT TRC20 + BTC) depozit + admin approve/reject
 */

const P2P_WALLETS = {
  usdt: { network: 'TRC20', address: 'THirzpbmU6TAagug6PX8cZb5QYPSFrDb2H', label: 'USDT (TRC20)' },
  btc:  { network: 'Bitcoin', address: '14ZgDgW2HU1HMdYo4K7VNFkRBFcYDY3D7L', label: 'BTC' }
};
const MIN_EUR = 10;

module.exports = function registerP2PRoutes(app, { admin, db, DB_ANALYTICS, authUser, uidLimit, region, round2g, FieldValue, requireFullAdmin }) {
  const round2 = round2g || (n => Math.round((Number(n) || 0) * 100) / 100);
  const API_BASE = 'https://pay4bit.onrender.com';

  async function getRates() {
    try {
      const r = await fetch(API_BASE + '/api/region', { signal: AbortSignal.timeout(6000) });
      const j = await r.json();
      if (j && j.success && j.rates) return j.rates;
    } catch (_) {}
    return { aznPerEur: 1.98, usdPerEur: 1.08 };
  }

  /* ═════ 1) İstifadəçi: P2P info ═════ */
  app.get(['/p2p/info', '/api/p2p/info'], authUser, async (req, res) => {
    try {
      const rg = region.resolveForRequest(req);
      res.json({ success: true, wallets: P2P_WALLETS, minDeposit: rg.minDeposit, defaultCurrency: rg.defaultCurrency, currencyOptions: rg.currencyOptions, isAZ: rg.isAZ });
    } catch (e) { res.status(500).json({ success: false, error: 'Server xətası' }); }
  });

  /* ═════ 2) İstifadəçi: order yarat ═════ */
  app.post(['/p2p/create', '/api/p2p/create'], authUser, uidLimit('p2p', 6, 60000), async (req, res) => {
    try {
      const method = String(req.body.method || '').toLowerCase();
      if (!P2P_WALLETS[method]) return res.status(400).json({ success: false, error: 'Yanlış üsul' });

      const rg = region.resolveForRequest(req);
      const cur = String(req.body.currency || rg.defaultCurrency).toUpperCase();
      if (!rg.currencyOptions.includes(cur)) return res.status(400).json({ success: false, error: 'Bu valyuta icazəli deyil' });

      const raw = String(req.body.amount ?? '').trim().replace(',', '.');
      if (!/^\d+(\.\d{1,2})?$/.test(raw)) return res.status(400).json({ success: false, error: 'Məbləğ yanlışdır' });
      const amt = Number(raw);
      if (amt < rg.minDeposit) return res.status(400).json({ success: false, error: `Minimum ${rg.minDeposit} ${cur}` });
      if (amt > 5000) return res.status(400).json({ success: false, error: 'Maksimum 5000' });

      const rates = await getRates();
      let amtEur = amt;
      if (cur === 'USD') amtEur = amt / (rates.usdPerEur || 1.08);
      if (amtEur < MIN_EUR) return res.status(400).json({ success: false, error: `Minimum ${MIN_EUR} EUR ekvivalenti` });

      const uid = req.user.uid;
      const orderId = 'p2p' + Date.now().toString(36) + require('crypto').randomBytes(3).toString('hex');
      const w = P2P_WALLETS[method];

      let uName = '', uUnique = '';
      try { const us = await db.collection('users').doc(uid).get(); if (us.exists) { uName = us.data().displayName || ''; uUnique = us.data().uniqueId || ''; } } catch (_) {}

      await db.collection('p2pOrders').doc(orderId).set({
        uid, userName: uName, userUniqueId: uUnique,
        method, network: w.network, address: w.address,
        amount: round2(amt), amountEur: round2(amtEur), currency: cur,
        status: 'awaiting_check', has2x: false,
        createdAt: FieldValue.serverTimestamp()
      });

      res.json({ success: true, orderId, address: w.address, network: w.network, amount: amt, currency: cur, amountEur: round2(amtEur) });
    } catch (e) { console.error('[p2p-create]', e); res.status(500).json({ success: false, error: 'Server xətası' }); }
  });

  /* ═════ 3) İstifadəçi: çek yüklə ═════ */
  app.post(['/p2p/upload-proof', '/api/p2p/upload-proof'], authUser, uidLimit('p2pu', 8, 60000), async (req, res) => {
    try {
      const orderId = String(req.body.orderId || '').trim();
      const imgBase64 = String(req.body.image || '').trim();
      const txHash = String(req.body.txHash || '').trim().slice(0, 100);
      if (!orderId || !imgBase64) return res.status(400).json({ success: false, error: 'Çek və sifariş lazımdır' });
      if (imgBase64.length > 8 * 1024 * 1024) return res.status(413).json({ success: false, error: 'Şəkil çox böyükdür (maks 6MB)' });

      const ref = db.collection('p2pOrders').doc(orderId);
      const snap = await ref.get();
      if (!snap.exists) return res.status(404).json({ success: false, error: 'Sifariş tapılmadı' });
      const o = snap.data();
      if (o.uid !== req.user.uid) return res.status(403).json({ success: false, error: 'İcazə yoxdur' });
      if (o.status !== 'awaiting_check') return res.status(409).json({ success: false, error: 'Bu sifariş artıq yoxlanılıb' });

      const IMGBB_KEY = process.env.IMGBB_API_KEY || 'ab45ef0467f470764f8a79f0dd243828';
      const m = imgBase64.match(/^data:image\/(jpe?g|png|webp);base64,(.+)$/i);
      if (!m) return res.status(400).json({ success: false, error: 'Yalnız JPG/PNG/WEBP' });
      const b64 = m[2];

      const fd = new URLSearchParams();
      fd.set('image', b64);
      let imgUrl = '';
      try {
        const r = await fetch('https://api.imgbb.com/1/upload?key=' + encodeURIComponent(IMGBB_KEY), { method: 'POST', body: fd, signal: AbortSignal.timeout(20000) });
        const j = await r.json();
        if (!j || !j.success || !j.data) throw new Error('ImgBB cavabı yanlışdır');
        imgUrl = j.data.display_url || j.data.url;
      } catch (e) {
        console.error('[p2p-upload] ImgBB:', e.message);
        return res.status(502).json({ success: false, error: 'Şəkil yüklənmədi, bir az sonra yoxlayın' });
      }

      await ref.update({ status: 'pending', proofUrl: imgUrl, txHash, uploadedAt: FieldValue.serverTimestamp() });

      try {
        await DB_ANALYTICS.collection('p2pDeposits').doc(orderId).set({
          uid: o.uid, userName: o.userName, userUniqueId: o.userUniqueId,
          amount: o.amount, currency: o.currency, method: o.method,
          proofUrl: imgUrl, status: 'pending', createdAt: FieldValue.serverTimestamp()
        });
      } catch (_) {}

      res.json({ success: true, imageUrl: imgUrl, message: 'Çek yükləndi. Admin təsdiqindən sonra balans artacaq.' });
    } catch (e) { console.error('[p2p-upload]', e); res.status(500).json({ success: false, error: 'Server xətası' }); }
  });

  /* ═════ 4) İstifadəçi: status ═════ */
  app.get(['/p2p/status', '/api/p2p/status'], authUser, async (req, res) => {
    try {
      const orderId = String(req.query.order || '');
      const snap = await db.collection('p2pOrders').doc(orderId).get();
      if (!snap.exists) return res.status(404).json({ success: false });
      const o = snap.data();
      if (o.uid !== req.user.uid) return res.status(403).json({ success: false });
      res.json({ success: true, order: { id: orderId, ...o } });
    } catch (e) { res.status(500).json({ success: false, error: 'Server xətası' }); }
  });

  /* ═══════════ ADMIN: TƏSDİQ ═══════════ */
  app.post(['/admin/p2p/approve', '/api/admin/p2p/approve'], authUser, uidLimit('p2pa', 60, 60000), requireFullAdmin, async (req, res) => {
    try {
      const orderId = String(req.body.orderId || '').trim();
      if (!orderId) return res.status(400).json({ success: false, error: 'orderId yoxdur' });

      const rates = await getRates();
      let approvedAmt = null;
      await db.runTransaction(async tx => {
        const oref = db.collection('p2pOrders').doc(orderId);
        const os = await tx.get(oref);
        if (!os.exists) throw new Error('order_not_found');
        const o = os.data();
        if (o.status === 'approved') throw new Error('already_approved');
        if (o.status !== 'pending') throw new Error('not_pending');

        const uref = db.collection('users').doc(o.uid);
        const us = await tx.get(uref);
        if (!us.exists) throw new Error('user_not_found');
        const u = us.data();

        const amtAzn = round2((Number(o.amountEur) || 0) * (rates.aznPerEur || 1.98));
        if (amtAzn <= 0) throw new Error('bad_amount');

        tx.update(uref, {
          balance: round2((Number(u.balance) || 0) + amtAzn),
          totalDepositedAZN: round2((Number(u.totalDepositedAZN) || 0) + amtAzn),
          hasDeposited: true,
          points: round2((Number(u.points) || 0) + amtAzn)
        });
        tx.set(uref.collection('history').doc('p2p_' + orderId), {
          type: 'deposit', amount: amtAzn,
          description: `P2P ${String(o.method || '').toUpperCase()} depozit (${o.currency} → AZN)`,
          createdAt: FieldValue.serverTimestamp()
        });
        tx.update(oref, {
          status: 'approved',
          approvedAzn: amtAzn,
          processedBy: req.user.uid,
          processedAt: FieldValue.serverTimestamp()
        });
        approvedAmt = amtAzn;
      });
      res.json({ success: true, amountAzn: approvedAmt });
    } catch (e) {
      const m = e && e.message;
      if (m === 'order_not_found') return res.status(404).json({ success: false, error: 'Sifariş tapılmadı' });
      if (m === 'already_approved') return res.status(409).json({ success: false, error: 'Artıq təsdiqlənib' });
      if (m === 'not_pending') return res.status(409).json({ success: false, error: 'Bu statusda təsdiq mümkün deyil' });
      if (m === 'user_not_found') return res.status(404).json({ success: false, error: 'İstifadəçi tapılmadı' });
      console.error('[p2p-approve]', e);
      res.status(500).json({ success: false, error: 'Server xətası' });
    }
  });

  /* ═══════════ ADMIN: RƏDD ═══════════ */
  app.post(['/admin/p2p/reject', '/api/admin/p2p/reject'], authUser, uidLimit('p2pr', 60, 60000), requireFullAdmin, async (req, res) => {
    try {
      const orderId = String(req.body.orderId || '').trim();
      const reason = String(req.body.reason || '').slice(0, 300);
      if (!orderId) return res.status(400).json({ success: false, error: 'orderId yoxdur' });

      const oref = db.collection('p2pOrders').doc(orderId);
      const os = await oref.get();
      if (!os.exists) return res.status(404).json({ success: false, error: 'Sifariş tapılmadı' });
      const o = os.data();
      if (o.status === 'approved' || o.status === 'rejected') return res.status(409).json({ success: false, error: 'Artıq işlənib' });

      await oref.update({
        status: 'rejected', rejectReason: reason,
        processedBy: req.user.uid, processedAt: FieldValue.serverTimestamp()
      });
      res.json({ success: true });
    } catch (e) {
      console.error('[p2p-reject]', e);
      res.status(500).json({ success: false, error: 'Server xətası' });
    }
  });
};