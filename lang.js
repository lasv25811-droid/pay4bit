/* YevroLato — dil idarəetməsi (az/ru/en) */
(function () {
  'use strict';
  const SUPPORTED = ['az', 'ru', 'en'];
  const FLAGS = { az: '🇦🇿 AZ', ru: '🇷🇺 RU', en: '🇬🇧 EN' };

  function detect() {
    try {
      const saved = (localStorage.getItem('yl_lang') || '').toLowerCase();
      if (SUPPORTED.includes(saved)) return saved;
    } catch (_) {}
    const nav = (navigator.language || 'az').toLowerCase();
    if (nav.startsWith('ru')) return 'ru';
    if (nav.startsWith('az')) return 'az';
    if (nav.startsWith('en')) return 'en';
    return 'az';
  }

  let current = detect();
  document.documentElement.lang = current;

  function set(l) {
    if (!SUPPORTED.includes(l)) return;
    current = l;
    document.documentElement.lang = l;
    try { localStorage.setItem('yl_lang', l); } catch (_) {}
    applyAll();
    document.dispatchEvent(new CustomEvent('yl-lang-change', { detail: { lang: l } }));
  }

  function applyAll() {
    document.querySelectorAll('[data-i18n]').forEach(el => {
      const key = el.getAttribute('data-i18n');
      const val = window.LANG.t(key);
      if (val !== key) el.textContent = val;
    });
    document.querySelectorAll('[data-i18n-ph]').forEach(el => {
      const key = el.getAttribute('data-i18n-ph');
      const val = window.LANG.t(key);
      if (val !== key) el.setAttribute('placeholder', val);
    });
    // Switcher labels
    document.querySelectorAll('.yl-lang-current').forEach(el => { el.textContent = FLAGS[current]; });
    document.querySelectorAll('.yl-lang-opt').forEach(el => {
      el.classList.toggle('is-active', el.dataset.lang === current);
    });
  }

  /* Sadə t() — səhifə `<script>`-də `window.LANG_DICT = {az:{...}, en:{...}, ru:{...}}` təyin edir */
  function t(key) {
    const d = window.LANG_DICT || {};
    const k = String(key || '').toLowerCase();
    return (d[current] && d[current][k]) || (d.az && d.az[k]) || (d.en && d.en[k]) || key;
  }

  /* Switcher HTML (bir dəfə DOM-a əlavə etmək üçün) */
  function switcherHTML() {
    return `
      <div class="yl-lang-switcher" id="ylLangSwitcher">
        <button type="button" class="yl-lang-btn" aria-haspopup="true" aria-expanded="false">
          <span class="yl-lang-current">${FLAGS[current]}</span>
          <span class="yl-lang-arrow">▾</span>
        </button>
        <div class="yl-lang-menu" role="menu">
          <button type="button" class="yl-lang-opt" data-lang="az" role="menuitem">🇦🇿 Azərbaycan</button>
          <button type="button" class="yl-lang-opt" data-lang="ru" role="menuitem">🇷🇺 Русский</button>
          <button type="button" class="yl-lang-opt" data-lang="en" role="menuitem">🇬🇧 English</button>
        </div>
      </div>`;
  }

  function initSwitcher() {
    document.querySelectorAll('#ylLangSwitcher').forEach(root => {
      const btn = root.querySelector('.yl-lang-btn');
      const menu = root.querySelector('.yl-lang-menu');
      if (!btn || !menu) return;
      btn.addEventListener('click', e => {
        e.stopPropagation();
        const open = root.classList.toggle('open');
        btn.setAttribute('aria-expanded', open ? 'true' : 'false');
      });
      menu.querySelectorAll('.yl-lang-opt').forEach(opt => {
        opt.addEventListener('click', () => { set(opt.dataset.lang); root.classList.remove('open'); btn.setAttribute('aria-expanded', 'false'); });
      });
    });
    document.addEventListener('click', () => {
      document.querySelectorAll('.yl-lang-switcher.open').forEach(r => {
        r.classList.remove('open');
        const b = r.querySelector('.yl-lang-btn'); if (b) b.setAttribute('aria-expanded', 'false');
      });
    });
    document.querySelectorAll('.yl-lang-opt').forEach(el => el.classList.toggle('is-active', el.dataset.lang === current));
  }

  window.LANG = { t, set, get lang() { return current; }, switcherHTML, initSwitcher, applyAll };
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', () => { initSwitcher(); applyAll(); });
  else { initSwitcher(); applyAll(); }
})();