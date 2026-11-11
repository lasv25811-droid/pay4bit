'use strict';
/**
 * Son çıxarışlar (ana səhifə üçün) — yalnız REAL, admin tərəfindən TƏSDİQLƏNMİŞ çıxarışlar.
 *   GET /recent-payouts  (və /api/recent-payouts)  -> { success, items: [{ name: 'e*****5', amount: 60 }] }
 * Yalnız maskalanmış ad və məbləğ qaytarılır (uid, kart, tam ad YOXDUR). Nəticə 60 saniyə yaddaşda saxlanır.
 * Kompozit indeks tələb etmir: createdAt üzrə son sənədlər oxunur, "approved" yaddaşda süzülür.
 */
const CACHE_MS = 60 * 1000;
const SCAN = 80;      // son neçə çıxarış sorğusuna baxılsın
const MAX_ITEMS = 12;

function maskName(raw) {
  let s = String(raw || '').trim();
  if (s.includes('@')) s = s.split('@')[0];
  const a = Array.from(s);
  if (!a.length) return '';
  if (a.length === 1) return a[0] + '*****';
  return a[0] + '*****' + a[a.length - 1];
}
function toMs(ts) {
  if (!ts) return 0;
  if (typeof ts.toMillis === 'function') return ts.toMillis();
  if (ts.seconds) return ts.seconds * 1000;
  const d = new Date(ts).getTime();
  return Number.isNaN(d) ? 0 : d;
}

module.exports = function registerPayoutRoutes(app, { db }) {
  let cache = { at: 0, items: [] };
  let pending = null;

  async function load() {
    const snap = await db.collection('withdrawRequests').orderBy('createdAt', 'desc').limit(SCAN).get();
    const items = [];
    for (const d of snap.docs) {
      const w = d.data() || {};
      if (w.status !== 'approved') continue;
      const amount = Math.round((Number(w.amount) > 0 ? Number(w.amount) : Number(w.total)) * 100) / 100;
      const name = maskName(w.userName);
      if (!name || !(amount > 0)) continue;
      items.push({ name, amount });
      if (items.length >= MAX_ITEMS) break;
    }
    return items;
  }

  app.get(['/recent-payouts', '/api/recent-payouts'], async (req, res) => {
    try {
      if (Date.now() - cache.at > CACHE_MS) {
        pending = pending || load().finally(() => { pending = null; });
        cache = { at: Date.now(), items: await pending };
      }
      res.set('Cache-Control', 'public, max-age=30');
      res.json({ success: true, items: cache.items });
    } catch (e) {
      console.error('[recent-payouts]', e && e.message ? e.message : e);
      res.json({ success: true, items: cache.items || [] });   // xəta olsa səhifə sınmasın
    }
  });
};
module.exports._maskName = maskName;
