'use strict';
/**
 * IP → ölkə → dil + valyuta.
 * Cloudflare `cf-ipcountry` header-ı əsas, fallback AZ.
 */

// Azərbaycan → AZ
// Rusiya → RU
// Avropa (bütün) → EN
// Digər → EN
const AZ = new Set(['AZ']);
const RU = new Set(['RU','BY','KZ','KG','TJ','UZ','AM']); // postsovet rus dili
const EUROPE = new Set([
  'DE','FR','NL','BE','LU','AT','CH','IT','ES','PT','IE','GB','UK','SE','NO','DK','FI','IS',
  'PL','CZ','SK','HU','RO','BG','GR','HR','SI','EE','LV','LT','MT','CY',
  'AL','BA','ME','MK','RS','XK','LI','MC','SM','AD','VA','MD','UA'
]);

function classify(cc) {
  cc = String(cc || '').toUpperCase().slice(0, 2);
  if (AZ.has(cc)) return 'AZ';
  if (RU.has(cc)) return 'RU';
  if (EUROPE.has(cc)) return 'EU';
  return 'OTHER';
}

// AZ → AZN; xaricdə → EUR/USD
// Dil: AZ → az; RU → ru; qalanı → en
function resolve(cc) {
  const cls = classify(cc);
  const isAZ = cls === 'AZ';
  const lang = cls === 'AZ' ? 'az' : cls === 'RU' ? 'ru' : 'en';
  const currencyOptions = isAZ ? ['AZN'] : ['EUR', 'USD'];
  const defaultCurrency = isAZ ? 'AZN' : 'EUR';
  // Deposit üsulları: AZ-da hamısı; xaricdə yalnız beynəlxalq (kart/google/apple + P2P USDT/BTC)
  const depositMethods = isAZ
    ? ['card','card2card','google','apple','telegram','p2p_usdt','p2p_btc']
    : ['card','google','apple','p2p_usdt','p2p_btc'];
  // Withdraw: xaricdə yalnız BTC/USDT
  const withdrawMethods = isAZ
    ? ['card','whatsapp']
    : ['btc','usdt'];
  // Min məbləğ (sistem valyutası ilə — UI tərəfində göstərilir)
  const minDeposit = isAZ ? 7 : 10;    // 7 AZN / 10 EUR
  const minWithdraw = isAZ ? 35 : 50;  // 35 AZN / 50 EUR
  // Azərbaycanda Pay4bit depoziti AZN-lə (2x bonus), xaricdə EUR/USD-lə
  const pay4bitCurrency = isAZ ? 'AZN' : 'EUR';
  return { country: cc || 'AZ', cls, lang, isAZ, currencyOptions, defaultCurrency, depositMethods, withdrawMethods, minDeposit, minWithdraw, pay4bitCurrency };
}

function resolveForRequest(req) {
  const cc = String(req.countryCode || '').toUpperCase();
  return resolve(cc);
}

module.exports = { resolve, resolveForRequest, classify, AZ, RU, EUROPE };