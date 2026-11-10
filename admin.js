const tg = window.Telegram?.WebApp;
if (tg) { tg.ready(); tg.expand(); }
const initData = tg?.initData || '';

let adminToken = localStorage.getItem('admin_token') || '';
let currentData = { users: [], ads: [], stats: {} };

function showMsg(m) { if (tg?.showAlert) tg.showAlert(m); else alert(m); }
function confirmMsg(m, cb) {
    if (tg?.showConfirm) tg.showConfirm(m, cb);
    else cb(confirm(m));
}

function api(path, body = {}) {
    return fetch(path, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'x-admin-token': adminToken },
        body: JSON.stringify({ ...body, initData, adminToken })
    }).then(async r => {
        const j = await r.json().catch(() => ({}));
        if (r.status === 403) throw new Error('Yetkisiz');
        if (!r.ok && j.error) throw new Error(j.error);
        return j;
    });
}

// ---------- Giriş ----------
async function tryInitAuth() {
    // Telegram içinden geldiyse initData ile dene
    try {
        const r = await fetch('/api/auth', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ initData })
        }).then(x => x.json());
        if (r.isAdmin) { showPanel(); return true; }
    } catch (e) {}
    // Token varsa dene
    if (adminToken) {
        try {
            await api('/api/admin/users');
            showPanel(); return true;
        } catch (e) { adminToken = ''; localStorage.removeItem('admin_token'); }
    }
    return false;
}

async function doLogin() {
    const usr = document.getElementById('admin-username').value;
    const pwd = document.getElementById('admin-password').value;
    const err = document.getElementById('login-error');
    err.textContent = '';
    try {
        const r = await fetch('/api/admin/login', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username: usr, password: pwd })
        });
        const j = await r.json();
        if (j.token) {
            adminToken = j.token;
            localStorage.setItem('admin_token', adminToken);
            showPanel();
        } else err.textContent = j.error || 'Kullanıcı adı veya şifre yanlış';
    } catch (e) { err.textContent = 'Bağlantı hatası'; }
}

function showPanel() {
    document.getElementById('login-screen').style.display = 'none';
    document.getElementById('admin-panel').style.display = 'block';
    loadAll();
}

function logout() {
    adminToken = '';
    localStorage.removeItem('admin_token');
    location.reload();
}

// ---------- Tabs ----------
document.querySelectorAll('.tab').forEach(t => {
    t.addEventListener('click', () => showTab(t.dataset.tab));
});
function showTab(name) {
    document.querySelectorAll('.tab').forEach(x => x.classList.toggle('active', x.dataset.tab === name));
    document.querySelectorAll('.tab-content').forEach(x => x.classList.toggle('active', x.id === 'tab-' + name));
    if (name === 'dashboard') loadDashboard();
    if (name === 'users') loadUsers();
    if (name === 'ads') loadAds();
    if (name === 'stats') loadStats();
}

// ---------- Yükleme ----------
async function loadAll() {
    await loadDashboard();
    await loadUsers();
    await loadAds();
    await loadStats();
}

async function loadDashboard() {
    try {
        const { users } = await api('/api/admin/users');
        const { stats } = await api('/api/admin/stats');
        let totalAcc = 0, activeAcc = 0, total = 0, success = 0, fail = 0;
        users.forEach(u => {
            totalAcc += (u.accounts || []).length;
            (u.accounts || []).forEach(a => { if (a.isRunning) activeAcc++; });
        });
        Object.values(stats).forEach(s => {
            total += s.total || 0; success += s.success || 0; fail += s.fail || 0;
        });
        document.getElementById('ov-users').textContent = users.length;
        document.getElementById('ov-accounts').textContent = totalAcc;
        document.getElementById('ov-active').textContent = activeAcc;
        document.getElementById('ov-total').textContent = total;
        document.getElementById('ov-success').textContent = success;
        document.getElementById('ov-fail').textContent = fail;
    } catch (e) { showMsg('Hata: ' + e.message); }
}

async function loadUsers() {
    try {
        const { users } = await api('/api/admin/users');
        currentData.users = users;
        const box = document.getElementById('users-list');
        if (!users.length) { box.innerHTML = '<div class="empty">Henüz kullanıcı yok</div>'; return; }
        box.innerHTML = users.map(u => renderUser(u)).join('');
    } catch (e) { showMsg('Hata: ' + e.message); }
}

function renderUser(u) {
    const accs = u.accounts || [];
    return `<div class="user-card">
        <div class="user-header">
            <div>
                <div class="user-name">${esc(u.firstName || '')} ${esc(u.lastName || '')}</div>
                <div class="user-sub">ID: ${u.id}${u.username ? ' · @' + esc(u.username) : ''}</div>
            </div>
            <button class="badge-status ${u.isActive ? 'on' : 'off'}" onclick="toggleUser('${u.id}')" style="border:none;cursor:pointer;padding:5px 10px;">
                ${u.isActive ? '● Aktif' : '○ Pasif'}
            </button>
        </div>
        ${accs.length ? accs.map(a => renderAccount(a)).join('') : '<div class="user-sub">Hesap bağlı değil</div>'}
    </div>`;
}

function renderAccount(a) {
    return `<div class="account-item ${a.isRunning ? '' : 'off'}">
        <div class="account-row">
            <span class="account-phone">📱 ${esc(a.phone)}</span>
            <span class="badge-status ${a.isRunning ? 'on' : 'off'}">${a.isRunning ? 'Çalışıyor' : 'Durdu'}</span>
        </div>
        <div class="user-sub">
            Grup: ${(a.selectedGroups || []).length}/${(a.groups || []).length} seçili · 
            Aralık: ${a.intervalMinutes || 0} dk · 
            ${a.adId ? '✅ Reklam atanmış' : '⚠️ Reklam atanmamış'}
        </div>
        <div class="account-actions">
            <button class="btn-sm-${a.isRunning ? 'stop' : 'start'}" onclick="toggleAccount('${a.id}', ${!a.isRunning})">
                ${a.isRunning ? '⏸ Durdur' : '▶ Başlat'}
            </button>
            <button class="btn-sm-config" onclick="openConfig('${a.id}')">⚙️ Ayar</button>
            <button class="btn-sm-groups" onclick="openGroups('${a.id}')">👥 Gruplar</button>
            <button class="btn-sm-send" onclick="sendNow('${a.id}')">📤 Şimdi Gönder</button>
        </div>
    </div>`;
}

async function toggleUser(id) {
    try { await api(`/api/admin/user/${id}/toggle`); loadUsers(); loadDashboard(); }
    catch (e) { showMsg('Hata: ' + e.message); }
}

async function toggleAccount(id, start) {
    try {
        await api(`/api/admin/account/${id}/${start ? 'start' : 'stop'}`);
        loadUsers(); loadDashboard();
    } catch (e) { showMsg('Hata: ' + e.message); }
}

async function startAll() {
    confirmMsg('Tüm hesapları başlatmak istediğinize emin misiniz?', async ok => {
        if (!ok) return;
        try { await api('/api/admin/all/start'); loadUsers(); loadDashboard(); showMsg('Tümü başlatıldı'); }
        catch (e) { showMsg('Hata: ' + e.message); }
    });
}
async function stopAll() {
    confirmMsg('Tüm hesapları durdurmak istediğinize emin misiniz?', async ok => {
        if (!ok) return;
        try { await api('/api/admin/all/stop'); loadUsers(); loadDashboard(); showMsg('Tümü durduruldu'); }
        catch (e) { showMsg('Hata: ' + e.message); }
    });
}

async function sendNow(id) {
    try { const r = await api(`/api/admin/account/${id}/send-now`); showMsg(`Gönderildi: ${r.result.ok} ✅ / ${r.result.bad} ❌`); loadStats(); loadDashboard(); }
    catch (e) { showMsg('Hata: ' + e.message); }
}

// ---------- Hesap ayarları ----------
function findAccount(id) {
    for (const u of currentData.users) {
        const a = (u.accounts || []).find(x => x.id === id);
        if (a) return a;
    }
    return null;
}

async function openConfig(id) {
    const a = findAccount(id); if (!a) return;
    const { ads } = await api('/api/admin/ads/list').catch(() => ({ ads: [] }));
    const opt = ads.map(ad => `<option value="${ad.id}" ${ad.id === a.adId ? 'selected' : ''}>[${ad.type}] ${esc((ad.text || '').slice(0, 40))}</option>`).join('');
    document.getElementById('modal-body').innerHTML = `
        <h3>⚙️ Hesap Ayarı — ${esc(a.phone)}</h3>
        <label style="color:#9ca3af;font-size:12px;display:block;margin:12px 0 6px;">Gönderim Aralığı (dakika)</label>
        <input type="number" id="cfg-interval" min="1" value="${a.intervalMinutes || 60}" style="width:100%;padding:10px;background:#0f0f15;border:1px solid #2a2a35;border-radius:8px;color:#fff;">
        <label style="color:#9ca3af;font-size:12px;display:block;margin:12px 0 6px;">Reklam Seç</label>
        <select id="cfg-ad" style="width:100%;padding:10px;background:#0f0f15;border:1px solid #2a2a35;border-radius:8px;color:#fff;">
            <option value="">— Reklam seçilmedi —</option>
            ${opt}
        </select>
        <div class="row" style="margin-top:16px;">
            <button class="btn-primary" onclick="saveConfig('${a.id}')">Kaydet</button>
            <button class="btn-ghost" onclick="closeModal()">İptal</button>
        </div>
    `;
    openModal();
}

async function saveConfig(id) {
    const intervalMinutes = document.getElementById('cfg-interval').value;
    const adId = document.getElementById('cfg-ad').value || null;
    try {
        await api(`/api/admin/account/${id}/update`, { intervalMinutes, adId });
        closeModal(); loadUsers();
        showMsg('✅ Ayar kaydedildi');
    } catch (e) { showMsg('Hata: ' + e.message); }
}

async function openGroups(id) {
    const a = findAccount(id); if (!a) return;
    const groups = a.groups || [];
    const selected = new Set(a.selectedGroups || []);
    const html = groups.length
        ? groups.map(g => `<label class="group-item">
            <input type="checkbox" value="${g.id}" ${selected.has(g.id) ? 'checked' : ''}>
            <span>${esc(g.title)} ${g.isChannel ? '📢' : '👥'}</span>
        </label>`).join('')
        : '<div class="empty">Grup bulunamadı. Yenile\'ye basın.</div>';
    document.getElementById('modal-body').innerHTML = `
        <h3>👥 Gruplar — ${esc(a.phone)}</h3>
        <button class="btn-primary" onclick="refreshGroups('${a.id}')" style="margin:10px 0;">🔄 Grupları Yenile</button>
        <div class="group-list">${html}</div>
        <div class="row">
            <button class="btn-primary" onclick="saveGroups('${a.id}')">Kaydet</button>
            <button class="btn-ghost" onclick="closeModal()">İptal</button>
        </div>
    `;
    openModal();
}

async function refreshGroups(id) {
    showMsg('Gruplar yenileniyor...');
    try {
        await api(`/api/admin/account/${id}/refresh-groups`);
        await loadUsers();
        openGroups(id);
    } catch (e) { showMsg('Hata: ' + e.message); }
}

async function saveGroups(id) {
    const checked = Array.from(document.querySelectorAll('.group-list input:checked')).map(x => x.value);
    try {
        await api(`/api/admin/account/${id}/update`, { selectedGroups: checked });
        closeModal(); loadUsers();
        showMsg('✅ Gruplar kaydedildi');
    } catch (e) { showMsg('Hata: ' + e.message); }
}

// ---------- Ads ----------
async function loadAds() {
    try {
        const { ads } = await api('/api/admin/ads/list');
        currentData.ads = ads;
        const box = document.getElementById('ads-list');
        if (!ads.length) { box.innerHTML = '<div class="empty">Henüz reklam yok</div>'; return; }
        box.innerHTML = ads.map(a => `
            <div class="ad-item">
                <div class="ad-header">
                    <span class="ad-type ${a.type}">${a.type.toUpperCase()}</span>
                    <div class="ad-actions">
                        <button class="btn-sm-config" onclick="editAd('${a.id}')">✏️</button>
                        <button class="btn-sm-stop" onclick="deleteAd('${a.id}')">🗑️</button>
                    </div>
                </div>
                <div class="ad-text">${esc(a.text || '(boş)')}</div>
                ${a.mediaUrl ? `<div class="ad-media">🔗 ${esc(a.mediaUrl)}</div>` : ''}
            </div>
        `).join('');
    } catch (e) { showMsg('Hata: ' + e.message); }
}

function showAdForm(ad = null) {
    document.getElementById('ad-form').style.display = 'block';
    document.getElementById('ad-form-title').textContent = ad ? 'Reklamı Düzenle' : 'Yeni Reklam';
    document.getElementById('ad-id').value = ad?.id || '';
    document.getElementById('ad-type').value = ad?.type || 'text';
    document.getElementById('ad-text').value = ad?.text || '';
    document.getElementById('ad-media').value = ad?.mediaUrl || '';
}
function hideAdForm() { document.getElementById('ad-form').style.display = 'none'; }
function editAd(id) { showAdForm(currentData.ads.find(a => a.id === id)); }

async function saveAd() {
    const id = document.getElementById('ad-id').value;
    const type = document.getElementById('ad-type').value;
    const text = document.getElementById('ad-text').value;
    const mediaUrl = document.getElementById('ad-media').value;
    if (type !== 'text' && !mediaUrl) { showMsg('Medya URL gerekli'); return; }
    try {
        await api('/api/admin/ads/save', { id: id || undefined, type, text, mediaUrl });
        hideAdForm(); loadAds();
        showMsg('✅ Kaydedildi');
    } catch (e) { showMsg('Hata: ' + e.message); }
}

async function deleteAd(id) {
    confirmMsg('Bu reklamı silmek istiyor musunuz?', async ok => {
        if (!ok) return;
        try { await api('/api/admin/ads/delete', { id }); loadAds(); }
        catch (e) { showMsg('Hata: ' + e.message); }
    });
}

// ---------- Stats ----------
async function loadStats() {
    try {
        const { users } = await api('/api/admin/users');
        const { stats } = await api('/api/admin/stats');
        currentData.users = users;
        currentData.stats = stats;
        const box = document.getElementById('stats-container');
        let html = '';
        users.forEach(u => {
            (u.accounts || []).forEach(a => {
                const s = stats[a.id] || {};
                const days = Object.keys(s.daily || {}).sort().slice(-7).reverse();
                const dayRows = days.map(d => {
                    const info = s.daily[d];
                    return `<tr><td>${d}</td><td style="color:#4ade80">${info.success || 0}</td><td style="color:#f87171">${info.fail || 0}</td><td>${info.total || 0}</td></tr>`;
                }).join('');
                html += `<div class="card">
                    <h3>📱 ${esc(a.phone)} <span style="color:#6b7280;font-size:12px;">(${esc(u.firstName || '')})</span></h3>
                    <div class="stats-grid">
                        <div class="stat-card"><div class="stat-num">${s.total || 0}</div><div class="stat-lbl">Toplam</div></div>
                        <div class="stat-card green"><div class="stat-num">${s.success || 0}</div><div class="stat-lbl">Başarılı</div></div>
                        <div class="stat-card red"><div class="stat-num">${s.fail || 0}</div><div class="stat-lbl">Başarısız</div></div>
                        <div class="stat-card"><div class="stat-num">${(s.byType?.text || 0)}</div><div class="stat-lbl">📝 Metin</div></div>
                        <div class="stat-card"><div class="stat-num">${(s.byType?.photo || 0)}</div><div class="stat-lbl">🖼️ Foto</div></div>
                        <div class="stat-card"><div class="stat-num">${(s.byType?.video || 0)}</div><div class="stat-lbl">🎬 Video</div></div>
                    </div>
                    ${days.length ? `<h3 style="margin-top:14px;">Son 7 Gün</h3>
                    <table style="width:100%;font-size:12px;color:#9ca3af;border-collapse:collapse;">
                        <tr style="border-bottom:1px solid #2a2a35;"><th align="left" style="padding:6px;">Tarih</th><th>Başarılı</th><th>Başarısız</th><th>Toplam</th></tr>
                        ${dayRows}
                    </table>` : '<div class="empty">Henüz veri yok</div>'}
                </div>`;
            });
        });
        box.innerHTML = html || '<div class="empty">İstatistik yok</div>';
    } catch (e) { showMsg('Hata: ' + e.message); }
}

// ---------- Modal ----------
function openModal() { document.getElementById('modal').style.display = 'flex'; }
function closeModal() { document.getElementById('modal').style.display = 'none'; }

// ---------- Helpers ----------
function esc(s) { return String(s ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c])); }

// ---------- Init ----------
(async () => {
    const ok = await tryInitAuth();
    if (!ok) document.getElementById('login-screen').style.display = 'flex';
})();