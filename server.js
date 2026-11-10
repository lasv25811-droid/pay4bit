const express = require('express');
const cors = require('cors');
const path = require('path');
const TelegramBot = require('node-telegram-bot-api');
const admin = require('firebase-admin');
const crypto = require('crypto');
require('dotenv').config();

// ---------- Firebase ----------
function normalizePrivateKey(key) {
    if (!key) return key;
    key = String(key).replace(/\\n/g, '\n').replace(/\r/g, '').trim();
    const m = key.match(/-----BEGIN PRIVATE KEY-----([\s\S]*?)-----END PRIVATE KEY-----/);
    if (!m) return key;
    const body = m[1].replace(/[^A-Za-z0-9+/=]/g, '');
    const lines = body.match(/.{1,64}/g) || [];
    return '-----BEGIN PRIVATE KEY-----\n' + lines.join('\n') + '\n-----END PRIVATE KEY-----\n';
}

let serviceAccount;
try {
    let raw = (process.env.FIREBASE_SERVICE_ACCOUNT || '').trim();
    if ((raw.startsWith("'") && raw.endsWith("'")) || (raw.startsWith('"') && raw.endsWith('"') && !raw.startsWith('{'))) {
        raw = raw.slice(1, -1);
    }
    if (!raw.startsWith('{')) {
        raw = Buffer.from(raw, 'base64').toString('utf8');
    }
    serviceAccount = JSON.parse(raw);
    serviceAccount.private_key = normalizePrivateKey(serviceAccount.private_key);
} catch (e) {
    console.error("❌ FIREBASE_SERVICE_ACCOUNT JSON hatası:", e.message);
    process.exit(1);
}
admin.initializeApp({ credential: admin.credential.cert(serviceAccount) });
const db = admin.firestore();
const FieldValue = admin.firestore.FieldValue;

// ---------- Express ----------
const app = express();
app.use(cors());
app.use(express.json({ limit: '15mb' }));

const ROOT = __dirname;
['/','/index.html','/app.js','/style.css','/admin.html','/admin.js','/admin.css'].forEach(p => {
    app.get(p, (req, res) => {
        const f = p === '/' ? 'index.html' : p.slice(1);
        res.sendFile(path.join(ROOT, f));
    });
});

// ---------- Bot (TÜRKÇE) ----------
// Render uyuyup uyandığı için webhook kullanılır (polling çakışması/409 olmaz).
const BASE_URL = (process.env.RENDER_EXTERNAL_URL || process.env.MINI_APP_URL || '').trim().replace(/\/+$/, '');
const USE_WEBHOOK = !!BASE_URL && process.env.USE_POLLING !== '1';
const bot = new TelegramBot(process.env.BOT_TOKEN, { polling: !USE_WEBHOOK });
bot.on('polling_error', (err) => console.error('Polling hatası:', err.message));
bot.on('webhook_error', (err) => console.error('Webhook hatası:', err.message));

const WEBHOOK_PATH = '/tg-' + crypto.createHash('sha256').update(String(process.env.BOT_TOKEN)).digest('hex').slice(0, 32);
if (USE_WEBHOOK) {
    app.post(WEBHOOK_PATH, (req, res) => {
        try { bot.processUpdate(req.body); } catch (e) { console.error('processUpdate:', e.message); }
        res.sendStatus(200);
    });
    bot.setWebHook(BASE_URL + WEBHOOK_PATH)
        .then(() => console.log('🤖 Webhook ayarlandı:', BASE_URL + '/tg-***'))
        .catch(e => console.error('Webhook ayarlanamadı:', e.message));
} else {
    console.log('🤖 Bot polling modunda');
}

bot.onText(/\/start/, (msg) => {
    const url = (process.env.MINI_APP_URL || '').trim();
    bot.sendMessage(msg.chat.id,
        "👋 *Reklam Yönetim Sistemine Hoş Geldiniz!*\n\n" +
        "Aşağıdaki butona basarak Mini App'i açabilirsiniz.",
        {
            parse_mode: 'Markdown',
            reply_markup: { inline_keyboard: [[{ text: "🚀 Mini App'i Aç", web_app: { url } }]] }
        }
    ).catch(err => console.error('sendMessage hatası:', err.message));
});

bot.onText(/\/yardim|\/help/, (msg) => {
    bot.sendMessage(msg.chat.id,
        "📖 *Yardım*\n\n" +
        "• /start — Sistemi başlat\n" +
        "• /yardim — Bu mesaj\n\n" +
        "Mini App üzerinden Telegram hesabınızı bağlayarak reklamlarınızı yönetebilirsiniz.",
        { parse_mode: 'Markdown' }
    );
});

// ---------- initData doğrulama ----------
function validateInitData(initData) {
    try {
        if (!initData) return null;
        const urlParams = new URLSearchParams(initData);
        const hash = urlParams.get('hash');
        urlParams.delete('hash');
        const dataCheckString = Array.from(urlParams.entries())
            .sort(([a], [b]) => a.localeCompare(b))
            .map(([k, v]) => `${k}=${v}`).join('\n');
        const secretKey = crypto.createHmac('sha256', 'WebAppData').update(process.env.BOT_TOKEN).digest();
        const calcHash = crypto.createHmac('sha256', secretKey).update(dataCheckString).digest('hex');
        return calcHash === hash ? JSON.parse(urlParams.get('user')) : null;
    } catch (e) { return null; }
}
function isAdminUser(u) { return u && u.id.toString() === (process.env.ADMIN_ID || '').trim(); }

// ---------- Admin oturumları (stateless: Render yeniden başlasa da çıkış yapmaz) ----------
const TOKEN_SECRET = crypto.createHash('sha256')
    .update('admin-token|' + (process.env.ADMIN_PASSWORD || '') + '|' + (process.env.BOT_TOKEN || '')).digest();
function makeAdminToken() {
    const exp = Date.now() + 7 * 24 * 60 * 60 * 1000;
    const sig = crypto.createHmac('sha256', TOKEN_SECRET).update(String(exp)).digest('hex');
    return exp + '.' + sig;
}
function verifyAdminToken(token) {
    if (!token || typeof token !== 'string') return false;
    const [exp, sig] = token.split('.');
    if (!exp || !sig || Number(exp) < Date.now()) return false;
    const calc = crypto.createHmac('sha256', TOKEN_SECRET).update(exp).digest('hex');
    if (calc.length !== sig.length) return false;
    return crypto.timingSafeEqual(Buffer.from(calc), Buffer.from(sig));
}

function isAdminRequest(req) {
    const initData = req.body?.initData || req.query?.initData;
    const user = validateInitData(initData);
    if (isAdminUser(user)) return true;
    const token = req.headers['x-admin-token'] || req.body?.adminToken || req.query?.adminToken;
    return verifyAdminToken(token);
}
const adminOnly = (handler) => async (req, res) => {
    if (!isAdminRequest(req)) return res.status(403).json({ error: 'Yetkisiz erişim' });
    try { await handler(req, res); }
    catch (e) { res.status(500).json({ error: e.message }); }
};

// ---------- Auth ----------
app.post('/api/auth', async (req, res) => {
    try {
        const user = validateInitData(req.body.initData);
        if (!user) return res.status(401).json({ error: "Güvenlik hatası" });
        const ref = db.collection('users').doc(user.id.toString());
        const doc = await ref.get();
        if (!doc.exists) {
            await ref.set({
                id: user.id, firstName: user.first_name,
                lastName: user.last_name || '', username: user.username || '',
                status: 'pending', isActive: true, createdAt: new Date()
            });
        }
        res.json({ success: true, userId: user.id, isAdmin: isAdminUser(user) });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

// ---------- Admin giriş ----------
app.post('/api/admin/login', (req, res) => {
    const { username, password } = req.body || {};
    const expected = (process.env.ADMIN_PASSWORD || '').trim();
    const expectedUser = (process.env.ADMIN_USERNAME || 'admin555').trim().toLowerCase();
    if (!expected) {
        console.error('⚠️ ADMIN_PASSWORD .env dosyasında tanımlı değil! (dosya adı tam olarak ".env" olmalı)');
    }
    if (!username || String(username).trim().toLowerCase() !== expectedUser ||
        !password || !expected || String(password).trim() !== expected) {
        return res.status(401).json({ error: 'Kullanıcı adı veya şifre yanlış' });
    }
    res.json({ token: makeAdminToken() });
});

// ---------- Userbot API ----------
const { startUserbotLogin, verifyUserbotCode, fetchGroups } = require('./userbot');

app.post('/api/userbot/send-code', async (req, res) => {
    try {
        const { phone } = req.body;
        if (!phone) return res.status(400).json({ error: "Telefon numarası gerekli" });
        const info = await startUserbotLogin(phone.trim());
        res.json({ success: true, phoneHash: info.phoneCodeHash });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/userbot/verify', async (req, res) => {
    try {
        const { phone, code, phoneCodeHash, password, initData } = req.body;
        const user = validateInitData(initData);
        if (!user) return res.status(401).json({ error: "Güvenlik hatası" });

        const sessionString = await verifyUserbotCode(phone.trim(), code, phoneCodeHash, password);

        // Grupları çek
        let groups = [];
        try { groups = await fetchGroups(sessionString); } catch (e) { console.error('grup çekme:', e.message); }

        await db.collection('accounts').add({
            userId: user.id.toString(),
            phone: phone.trim(),
            session: sessionString,
            groups,
            selectedGroups: [],
            adId: null,
            intervalMinutes: 60,
            isRunning: false,
            lastSentAt: null,
            createdAt: new Date()
        });
        res.json({ success: true, message: "Hesap başarıyla bağlandı!", groupCount: groups.length });
    } catch (e) {
        if (e.needPassword) return res.status(200).json({ success: false, needPassword: true, error: e.message });
        res.status(500).json({ error: e.message });
    }
});

// ---------- Admin API ----------
app.post('/api/admin/users', adminOnly(async (req, res) => {
    const uSnap = await db.collection('users').get();
    const aSnap = await db.collection('accounts').get();
    const users = uSnap.docs.map(d => ({ id: d.id, ...d.data() }));
    const accounts = aSnap.docs.map(d => ({ id: d.id, ...d.data(), session: undefined }));
    users.forEach(u => { u.accounts = accounts.filter(a => a.userId === u.id); });
    res.json({ users });
}));

app.post('/api/admin/account/:id/start', adminOnly(async (req, res) => {
    await db.collection('accounts').doc(req.params.id).update({ isRunning: true });
    res.json({ success: true });
}));
app.post('/api/admin/account/:id/stop', adminOnly(async (req, res) => {
    await db.collection('accounts').doc(req.params.id).update({ isRunning: false });
    res.json({ success: true });
}));

app.post('/api/admin/accounts/bulk', adminOnly(async (req, res) => {
    const { accountIds, action } = req.body;
    const batch = db.batch();
    (accountIds || []).forEach(id => {
        batch.update(db.collection('accounts').doc(id), { isRunning: action === 'start' });
    });
    await batch.commit();
    res.json({ success: true });
}));

app.post('/api/admin/all/start', adminOnly(async (req, res) => {
    const snap = await db.collection('accounts').get();
    const batch = db.batch();
    snap.docs.forEach(d => batch.update(d.ref, { isRunning: true }));
    await batch.commit();
    res.json({ success: true, count: snap.size });
}));
app.post('/api/admin/all/stop', adminOnly(async (req, res) => {
    const snap = await db.collection('accounts').get();
    const batch = db.batch();
    snap.docs.forEach(d => batch.update(d.ref, { isRunning: false }));
    await batch.commit();
    res.json({ success: true, count: snap.size });
}));

app.post('/api/admin/user/:id/toggle', adminOnly(async (req, res) => {
    const ref = db.collection('users').doc(req.params.id);
    const doc = await ref.get();
    if (!doc.exists) return res.status(404).json({ error: 'Kullanıcı yok' });
    await ref.update({ isActive: !doc.data().isActive });
    res.json({ success: true });
}));

app.post('/api/admin/account/:id/refresh-groups', adminOnly(async (req, res) => {
    const ref = db.collection('accounts').doc(req.params.id);
    const doc = await ref.get();
    if (!doc.exists) return res.status(404).json({ error: 'Hesap yok' });
    const groups = await fetchGroups(doc.data().session);
    await ref.update({ groups, groupsFetchedAt: new Date() });
    res.json({ groups });
}));

app.post('/api/admin/account/:id/update', adminOnly(async (req, res) => {
    const { selectedGroups, adId, intervalMinutes } = req.body;
    const upd = {};
    if (selectedGroups !== undefined) upd.selectedGroups = selectedGroups;
    if (adId !== undefined) upd.adId = adId;
    if (intervalMinutes !== undefined) upd.intervalMinutes = parseInt(intervalMinutes);
    await db.collection('accounts').doc(req.params.id).update(upd);
    res.json({ success: true });
}));

app.post('/api/admin/account/:id/send-now', adminOnly(async (req, res) => {
    const ref = db.collection('accounts').doc(req.params.id);
    const doc = await ref.get();
    if (!doc.exists) return res.status(404).json({ error: 'Hesap yok' });
    try {
        const result = await sendAdForAccount(doc.id, doc.data());
        res.json({ success: true, result });
    } catch (e) { res.status(500).json({ error: e.message }); }
}));

// ---------- Reklam CRUD ----------
app.post('/api/admin/ads/list', adminOnly(async (req, res) => {
    const snap = await db.collection('ads').orderBy('createdAt', 'desc').get();
    res.json({ ads: snap.docs.map(d => ({ id: d.id, ...d.data() })) });
}));
app.post('/api/admin/ads/save', adminOnly(async (req, res) => {
    const { id, type, text, mediaUrl } = req.body;
    if (id) {
        await db.collection('ads').doc(id).update({ type, text, mediaUrl });
        return res.json({ success: true, id });
    }
    const ref = await db.collection('ads').add({ type, text, mediaUrl, createdAt: new Date() });
    res.json({ success: true, id: ref.id });
}));
app.post('/api/admin/ads/delete', adminOnly(async (req, res) => {
    await db.collection('ads').doc(req.body.id).delete();
    res.json({ success: true });
}));

// ---------- İstatistik ----------
app.post('/api/admin/stats', adminOnly(async (req, res) => {
    const snap = await db.collection('stats').get();
    const out = {};
    snap.docs.forEach(d => { out[d.id] = d.data(); });
    res.json({ stats: out });
}));

// ---------- Yardımcı: istatistik kaydet ----------
async function recordSend(accountId, type, success) {
    const now = new Date();
    const dk = now.toISOString().slice(0, 10);
    const mk = now.toISOString().slice(0, 7);
    const wk = getWeekKey(now);
    const ref = db.collection('stats').doc(accountId);
    const field = success ? 'success' : 'fail';
    const upd = {
        total: FieldValue.increment(1),
        [field]: FieldValue.increment(1),
        [`byType.${type}`]: FieldValue.increment(1),
        [`daily.${dk}.total`]: FieldValue.increment(1),
        [`daily.${dk}.${field}`]: FieldValue.increment(1),
        [`daily.${dk}.byType.${type}`]: FieldValue.increment(1),
        [`monthly.${mk}.total`]: FieldValue.increment(1),
        [`monthly.${mk}.${field}`]: FieldValue.increment(1),
        [`weekly.${wk}.total`]: FieldValue.increment(1),
        [`weekly.${wk}.${field}`]: FieldValue.increment(1)
    };
    await ref.set(upd, { merge: true }).catch(async () => {
        // Doc yoksa oluştur
        await ref.set({ total: 0, success: 0, fail: 0, byType: {} });
        await ref.set(upd, { merge: true });
    });
}
function getWeekKey(d) {
    const onejan = new Date(d.getFullYear(), 0, 1);
    const week = Math.ceil((((d - onejan) / 86400000) + onejan.getDay() + 1) / 7);
    return `${d.getFullYear()}-W${String(week).padStart(2, '0')}`;
}

// ---------- Scheduler ----------
const { sendAdToGroups } = require('./userbot');

async function sendAdForAccount(accountId, acc) {
    if (!acc.adId) throw new Error('Reklam atanmamış');
    if (!acc.selectedGroups || acc.selectedGroups.length === 0) throw new Error('Grup seçilmemiş');
    const adDoc = await db.collection('ads').doc(acc.adId).get();
    if (!adDoc.exists) throw new Error('Reklam bulunamadı');
    const ad = adDoc.data();

    const results = await sendAdToGroups(acc.session, acc.selectedGroups, ad);
    let ok = 0, bad = 0;
    for (const r of results) {
        if (r.success) ok++; else bad++;
    }
    for (let i = 0; i < ok; i++) await recordSend(accountId, ad.type, true);
    for (let i = 0; i < bad; i++) await recordSend(accountId, ad.type, false);

    return { ok, bad, total: results.length };
}

let schedulerBusy = false;
async function runScheduler() {
    if (schedulerBusy) return;
    schedulerBusy = true;
    try {
        const snap = await db.collection('accounts').where('isRunning', '==', true).get();
        const now = Date.now();
        for (const doc of snap.docs) {
            const acc = doc.data();
            if (!acc.adId || !acc.selectedGroups?.length || !acc.intervalMinutes) continue;
            const last = acc.lastSentAt?.toMillis?.() || 0;
            if (now < last + acc.intervalMinutes * 60 * 1000) continue;
            // Kilit: önce lastSentAt güncelle (çift gönderimi önlemek için)
            await doc.ref.update({ lastSentAt: new Date() });
            try {
                await sendAdForAccount(doc.id, acc);
                console.log(`✅ ${acc.phone} için reklam gönderildi`);
            } catch (e) {
                console.error(`❌ ${acc.phone} gönderim hatası:`, e.message);
            }
        }
    } catch (e) { console.error('Scheduler hatası:', e.message); }
    finally { schedulerBusy = false; }
}

setInterval(runScheduler, 60 * 1000); // her dakika
setTimeout(runScheduler, 5000);       // uyanır uyanmaz hemen kontrol et
console.log('⏰ Scheduler aktif (60sn)');

// ---------- Ping ----------
// cron-job.org her 10 dk bu adresi çağırır: sunucuyu uyandırır + zamanlayıcıyı tetikler
app.get('/ping', (req, res) => {
    res.send('Alive');
    runScheduler();
});
app.head('/ping', (req, res) => res.sendStatus(200));

// Yedek: kendi kendine ping (cron çalışmasa bile uyanık kalmaya yardım eder)
if (BASE_URL && typeof fetch === 'function') {
    setInterval(() => { fetch(BASE_URL + '/ping').catch(() => {}); }, 9 * 60 * 1000);
}

// Beklenmeyen hatalarda sunucu çökmesin
process.on('unhandledRejection', (e) => console.error('unhandledRejection:', e?.message || e));
process.on('uncaughtException', (e) => console.error('uncaughtException:', e?.message || e));

app.get('*', (req, res) => res.sendFile(path.join(ROOT, 'index.html')));

const PORT = process.env.PORT || 3000;
app.listen(PORT, '0.0.0.0', () => {
    console.log(`🚀 Server ${PORT} portunda`);
    console.log(process.env.ADMIN_PASSWORD
        ? '✅ ADMIN_PASSWORD yüklendi (uzunluk: ' + process.env.ADMIN_PASSWORD.trim().length + ')'
        : '❌ ADMIN_PASSWORD BULUNAMADI — .env dosyasını (veya hosting panelindeki Environment Variables kısmını) kontrol edin!');
});