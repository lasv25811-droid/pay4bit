'use strict';
/**
 * PayÇarx SAF məntiqi (Firebase/Firestore asılılığı YOXDUR -> test etmək asandır).
 * Render-dəki spin-route.js-dən AYNEN köçürülüb. Çəkiləri (w / nw) YALNIZ burada dəyiş.
 * DİQQƏT: SEGMENTS sırası paycarx.html-dəki SEGMENTS ilə eyni olmalıdır.
 */
const crypto = require('crypto');

const FREE_SPIN_MS = 24 * 60 * 60 * 1000;
const MATRIX_POINTS = 5000;

const WELCOME_DELAY_MS = process.env.WELCOME_DELAY_MS !== undefined && process.env.WELCOME_DELAY_MS !== ''
  ? Math.max(0, Number(process.env.WELCOME_DELAY_MS) || 0) : FREE_SPIN_MS;
const WELCOME_MAX_PER_IP = Math.max(1, Number(process.env.WELCOME_MAX_PER_IP) || 1);
const WELCOME_MAX_PER_DEVICE = Math.max(1, Number(process.env.WELCOME_MAX_PER_DEVICE) || 1);
const CLAIM_SALT = process.env.WELCOME_CLAIM_SALT || 'yevrolato-welcome-v1';
const DEVICE_ID_RE = /^[A-Za-z0-9_-]{16,64}$/;

const SEGMENTS = [
  { type: 'money',  value: 1,   label: '1 AZN',                w: 18, nw: 10 },
  { type: 'spin',   value: 2,   label: 'PayÇarx 2 dəfə',       w: 1,  nw: 0  },
  { type: 'money',  value: 2,   label: '2 AZN',                w: 16, nw: 8  },
  { type: 'x2',     value: 2,   label: 'İlk depozitin 2 qatı', w: 5,  nw: 3  },
  { type: 'money',  value: 3,   label: '3 AZN',                w: 7,  nw: 25 },
  { type: 'lose',   value: 0,   label: 'Bu dəfə olmadı',       w: 32, nw: 20 },
  { type: 'money',  value: 5,   label: '5 AZN',                w: 1,  nw: 0  },
  { type: 'points', value: 100, label: '100 level xalı',       w: 6,  nw: 2  },
  { type: 'money',  value: 4,   label: '4 AZN',                w: 3,  nw: 0  },
  { type: 'points', value: 50,  label: '50 level xalı',        w: 10, nw: 32 },
  { type: 'money',  value: 10,  label: '10 AZN',               w: 1,  nw: 0  }
];
const TOTAL_W = SEGMENTS.reduce((a, s) => a + s.w, 0);
const TOTAL_NW = SEGMENTS.reduce((a, s) => a + s.nw, 0);

const r2 = (n) => Math.round((Number(n) || 0) * 100) / 100;

function pickSegment(deposited = true, rand = crypto.randomInt) {
  const key = deposited ? 'w' : 'nw';
  const total = deposited ? TOTAL_W : TOTAL_NW;
  let r = rand(0, total);
  for (let i = 0; i < SEGMENTS.length; i++) {
    r -= SEGMENTS[i][key];
    if (r < 0) return i;
  }
  return SEGMENTS.length - 1;
}

function createdMs(d, now) {
  let c = 0;
  if (d.createdAt && typeof d.createdAt.toMillis === 'function') c = d.createdAt.toMillis();
  if (c > now) c = now;
  return c;
}
function isMatrix(d) { return (Number(d.points) || 0) >= MATRIX_POINTS; }
function welcomeDone(d) { return d.welcomeSpinGiven === true || (Number(d.lastSpinAtMs) || 0) > 0; }

function resolveSpins(d, now, gate) {
  let spins = Math.max(0, Math.floor(Number(d.payWheelSpins) || 0));
  const upd = {};
  const matrix = isMatrix(d);
  let nextFreeAtMs = 0;
  let mode = 'deposit';
  let welcomeDue = false;
  let welcomeGranted = false;

  if (spins === 0) {
    if (!welcomeDone(d)) {
      if (d.phoneVerified !== true && d.emailVerified !== true) {
        mode = 'welcome_sms';
      } else {
        const at = createdMs(d, now) + WELCOME_DELAY_MS;
        if (now < at) { nextFreeAtMs = at; mode = 'welcome'; }
        else if (!gate) { welcomeDue = true; mode = 'welcome_check'; }
        else if (gate.ok) {
          spins = 1; upd.payWheelSpins = 1; upd.welcomeSpinGiven = true; welcomeGranted = true;
        } else { mode = gate.reason || 'welcome_blocked'; }
      }
    } else if (matrix) {
      let last = Number(d.lastDailySpinAtMs) || 0;
      if (last > now) last = now;
      const at = last + FREE_SPIN_MS;
      if (!last || now >= at) { spins = 1; upd.payWheelSpins = 1; upd.lastDailySpinAtMs = now; }
      else { nextFreeAtMs = at; mode = 'matrix'; }
    }
  }
  return { spins, upd, nextFreeAtMs, mode, matrix, welcomeDue, welcomeGranted };
}

function applyPrize(d, spinsBefore, idx, now) {
  const prize = SEGMENTS[idx];
  const upd = {
    payWheelSpins: spinsBefore - 1 + (prize.type === 'spin' ? prize.value : 0),
    lastSpinAtMs: now
  };
  let alreadyX2 = false;
  if (prize.type === 'money') {
    upd.balance = r2((Number(d.balance) || 0) + prize.value);
    upd.points = r2((Number(d.points) || 0) + prize.value);
  } else if (prize.type === 'points') {
    upd.points = r2((Number(d.points) || 0) + prize.value);
  } else if (prize.type === 'x2') {
    if (d.firstDepositBonus === 'pending') alreadyX2 = true;
    else upd.firstDepositBonus = 'pending';
  }
  return { upd, alreadyX2, prize };
}

function publicState(d, upd, spins, info, now) {
  const merged = { ...d, ...upd };
  return {
    spins,
    nextFreeAtMs: spins > 0 ? 0 : (info.nextFreeAtMs || 0),
    freeMode: spins > 0 ? 'ready' : info.mode,
    isMatrix: isMatrix(merged),
    phoneVerified: merged.phoneVerified === true,
    matrixPoints: MATRIX_POINTS,
    points: r2(merged.points),
    serverNow: now,
    balance: r2(merged.balance),
    currency: merged.currency || 'AZN'
  };
}

module.exports = {
  SEGMENTS, TOTAL_W, TOTAL_NW, FREE_SPIN_MS, MATRIX_POINTS, WELCOME_DELAY_MS, WELCOME_MAX_PER_IP,
  WELCOME_MAX_PER_DEVICE, CLAIM_SALT, DEVICE_ID_RE,
  r2, pickSegment, createdMs, isMatrix, welcomeDone, resolveSpins, applyPrize, publicState
};
