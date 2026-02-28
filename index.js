// index.js — SurveyCash: grå landing + gul tema + auth-modal (login/signup)
require('dotenv').config();

const { createClient } = require('@supabase/supabase-js');

const supabaseAdmin = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_ROLE_KEY
);

const supabasePublic = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_ANON_KEY
);

const express = require('express');
const cors = require('cors');
const cookieParser = require('cookie-parser');

const rateLimit = require('express-rate-limit');

// Baseline limiter (fx login/signup)
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 min
  max: 20,                 // 20 requests pr. IP pr. 15 min
  standardHeaders: true,
  legacyHeaders: false,
  message: 'Too many attempts. Please try again later.',
});

// Hårdere limiter kun for login (anti brute-force)
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10, // 10 login attempts pr IP pr 15 min
  standardHeaders: true,
  legacyHeaders: false,
  message: 'Too many login attempts. Please try again later.',
});


const fs = require('fs');
const path = require('path');
const bcrypt = require('bcrypt');
const crypto = require('crypto');
const IS_PROD = process.env.NODE_ENV === 'production';


const fetch = (...args) =>
  import('node-fetch').then(({ default: fetch }) => fetch(...args));


function md5(s) {
  return crypto
    .createHash('md5')
    .update(String(s), 'utf8')
    .digest('hex');
}


const app = express();

app.set('trust proxy', 1);


app.use(express.json());


app.use(express.static(path.join(__dirname, 'public')));

const PORT = process.env.PORT || 6000;
const BASE_URL = process.env.BASE_URL || `http://localhost:${PORT}`;

const CPX_APP_ID = process.env.CPX_APP_ID || '30422';
const CPX_APP_SECURE_HASH = process.env.CPX_APP_SECURE_HASH || '';

const USERS_FILE = path.join(__dirname, 'users.json');
const BCRYPT_ROUNDS = 10;

const CPX_POSTBACK_FILE = path.join(__dirname, 'cpx_postbacks.json');

let cpxPostbacks = {};
try {
  cpxPostbacks = JSON.parse(fs.readFileSync(CPX_POSTBACK_FILE, 'utf8'));
} catch {
  cpxPostbacks = {};
}

function saveCpxPostbacks() {
  fs.writeFileSync(CPX_POSTBACK_FILE, JSON.stringify(cpxPostbacks, null, 2));
}


// (simpel valuta – vi viser nu kun tal + $ i UI)
const CURRENCY = process.env.CURRENCY || 'USD';


// ---------- User storage (simple fil-database) ----------
// Vi bruger ÉN sandhed: globalt "users" objekt (key = email) + saveUsers() til at skrive filen.

let users = {};
try {
  const raw = fs.readFileSync(USERS_FILE, 'utf8');
  users = JSON.parse(raw) || {};
} catch {
  users = {};
}

function saveUsers() {
  try {
    fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2));
  } catch (e) {
    console.error('Kunne ikke gemme users.json:', e.message);
  }
}

// Hjælper: sikrer at en user har alle felter vi forventer
function ensureUserFields(user) {
  let changed = false;

  if (typeof user.balanceCents !== 'number') {
    user.balanceCents = 0;
    changed = true;
  }
  if (typeof user.totalEarnedCents !== 'number') {
    user.totalEarnedCents = user.balanceCents || 0;
    changed = true;
  }
  if (typeof user.completedSurveys !== 'number') {
    user.completedSurveys = 0;
    changed = true;
  }
  if (typeof user.completedOffers !== 'number') {
    user.completedOffers = 0;
    changed = true;
  }

  // Sørg for at user har en stabil id vi kan sende til CPX
  // (vi bruger den senere som ext_user_id, så postbacks matcher)
  if (!user.id) {
    user.id = String(user.email || '').toLowerCase();
    changed = true;
  }

  return changed;
}

function getUserFromReq(req) {
  return req.user || null;
}



// -------- helpers ----------
const isLoggedIn = (req) => !!getUserFromReq(req);

// vi laver en separat reference til users.json kun til stats
const USERS_FILE_STATS = path.join(__dirname, 'users.json');

// cents -> USD string
function formatUsdFromCents(cents) {
  return ((typeof cents === 'number' ? cents : 0) / 100).toFixed(2);
}

// Cashout presets (som cards): $5, $10, $15, $25, $50, $100, $200
const CASHOUT_DEFAULT_CENTS = 500;
const CASHOUT_ALLOWED_CENTS = [500, 1000, 1500, 2500, 5000, 7500, 10000, 15000, 20000];
const CASHOUT_ALLOWED_SET = new Set(CASHOUT_ALLOWED_CENTS);



function isValidEmail(s) {
  const str = String(s || '').trim();
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(str);
}


function createSessionToken() {
  return crypto.randomBytes(32).toString('hex');
}

async function createSession(userId) {
  const token = createSessionToken();
  const expiresAt = new Date(Date.now() + 1000 * 60 * 60 * 24 * 30); // 30 dage

  const { error } = await supabaseAdmin
    .from('sessions')
    .insert({
      token,
      user_id: userId,
      expires_at: expiresAt,
    });

  if (error) throw error;

  return { token, expiresAt };
}


async function getProfileByUserId(userId) {
  const { data, error } = await supabaseAdmin
    .from('profiles')
    .select('user_id, balance_cents, pending_cents')
    .eq('user_id', userId)
    .single();

  if (error) throw error;
  return data;
}

const PAYPAL_ENV = process.env.PAYPAL_ENV || 'sandbox';
const PAYPAL_BASE =
  PAYPAL_ENV === 'live'
    ? 'https://api-m.paypal.com'
    : 'https://api-m.sandbox.paypal.com';

async function paypalGetAccessToken() {
  const clientId = process.env.PAYPAL_CLIENT_ID;
  const secret = process.env.PAYPAL_CLIENT_SECRET;

  const basic = Buffer.from(`${clientId}:${secret}`).toString('base64');

  const r = await fetch(`${PAYPAL_BASE}/v1/oauth2/token`, {
    method: 'POST',
    headers: {
      Authorization: `Basic ${basic}`,
      'Content-Type': 'application/x-www-form-urlencoded',
    },
    body: 'grant_type=client_credentials',
  });

  const data = await r.json();
  if (!r.ok) throw new Error(JSON.stringify(data));
  return data.access_token;
}

async function paypalCreatePayout({ receiverEmail, amountUsd, withdrawalId }) {
  const token = await paypalGetAccessToken();

  const payload = {
    sender_batch_header: {
      sender_batch_id: `sc_${withdrawalId}_${Date.now()}`,
      email_subject: 'You have a payout from SurveyCash',
    },
    items: [
      {
        recipient_type: 'EMAIL',
        receiver: receiverEmail,
        amount: { value: amountUsd.toFixed(2), currency: 'USD' },
        note: 'SurveyCash payout',
        sender_item_id: String(withdrawalId),
      },
    ],
  };

  const r = await fetch(`${PAYPAL_BASE}/v1/payments/payouts`, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${token}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(payload),
  });

  const data = await r.json();
  if (!r.ok) throw new Error(JSON.stringify(data));

  return data.batch_header.payout_batch_id;
}

async function paypalGetPayoutBatch(payoutBatchId) {
  const token = await paypalGetAccessToken();

  const r = await fetch(`${PAYPAL_BASE}/v1/payments/payouts/${payoutBatchId}`, {
    method: 'GET',
    headers: { Authorization: `Bearer ${token}` },
  });

  const data = await r.json();
  if (!r.ok) throw new Error(JSON.stringify(data));
  return data;
}


// Returnerer: 'processing' | 'paid' | 'failed'
function mapPayPalBatchStatus(batch) {
  // 1) item status (mest præcis)
  const itemStatus = String(
    batch?.items?.[0]?.transaction_status ||
    batch?.items?.[0]?.transaction_status?.status ||
    ''
  ).toUpperCase();

  // Typiske item statuses: SUCCESS, PENDING, FAILED, RETURNED, UNCLAIMED, ONHOLD, BLOCKED, REFUNDED
  if (itemStatus === 'SUCCESS') return 'paid';
  if (itemStatus === 'FAILED' || itemStatus === 'RETURNED' || itemStatus === 'BLOCKED' || itemStatus === 'REFUNDED') {
    return 'failed';
  }
  if (itemStatus) return 'processing';

  // 2) fallback til batch header
  const batchStatus = String(batch?.batch_header?.batch_status || '').toUpperCase();
  if (batchStatus === 'SUCCESS') return 'paid';
  if (batchStatus === 'DENIED' || batchStatus === 'CANCELED' || batchStatus === 'FAILED') return 'failed';
  return 'processing';
}

// --- Background payout checker (server-side) ---
async function processOpenWithdrawals() {
  try {
    // Find alle withdrawals der stadig er processing
    const { data: list, error } = await supabaseAdmin
      .from('withdrawals')
      .select('*')
      .in('status', ['pending', 'processing'])
      .order('id', { ascending: true })
      .limit(50);

    if (error) {
      console.error('processOpenWithdrawals list error:', error);
      return;
    }
    if (!list || list.length === 0) return;

    for (const w of list) {
      try {
        if (!w.paypal_batch_id) continue;

        const batch = await paypalGetPayoutBatch(w.paypal_batch_id);
        const nextStatus = mapPayPalBatchStatus(batch);

        if (nextStatus === 'paid') {
          // idempotent update (kun én gang)
          const { data: upd } = await supabaseAdmin
            .from('withdrawals')
            .update({ status: 'paid', error_text: null })
            .eq('id', w.id)
            .neq('status', 'paid')
            .select('id')
            .maybeSingle();

          if (upd) {
            // træk pending ned
            const { data: prof } = await supabaseAdmin
              .from('profiles')
              .select('pending_cents')
              .eq('user_id', w.user_id)
              .single();

            const pendingNow = Number(prof?.pending_cents || 0);
            const amount = Number(w.amount_cents || 0);

            await supabaseAdmin
              .from('profiles')
              .update({ pending_cents: Math.max(0, pendingNow - amount) })
              .eq('user_id', w.user_id);
          }
        }

        if (nextStatus === 'failed') {
          await supabaseAdmin
            .from('withdrawals')
            .update({ status: 'failed', error_text: 'PayPal payout failed/denied' })
            .eq('id', w.id);

          await supabaseAdmin.rpc('fail_cashout_return_funds', {
            p_withdrawal_id: w.id,
          });
        }

        // processing -> gør ingenting
      } catch (e) {
        console.error('processOpenWithdrawals item error:', w?.id, e);
      }
    }
  } catch (e) {
    console.error('processOpenWithdrawals fatal:', e);
  }
}

// Kør hvert 60. sekund (i live kan du sætte 30-120s)
setInterval(processOpenWithdrawals, 60 * 1000);
processOpenWithdrawals();



// kun brugt til statistik – uafhængig af anden user-logik
function loadUsersForStats() {
  try {
    if (!fs.existsSync(USERS_FILE_STATS)) return [];

    const raw = fs.readFileSync(USERS_FILE_STATS, 'utf8');
    if (!raw.trim()) return [];

    const data = JSON.parse(raw);

    if (Array.isArray(data)) return data;
    if (data && typeof data === 'object') return Object.values(data);
    return [];
  } catch (err) {
    console.error('Failed to read users for stats', err);
    return [];
  }
}

// Saml platform-statistik
function aggregatePlatformStats() {
  const users = loadUsersForStats();

  const stats = {
    totalUsers: users.length,
    totalEarnedCents: 0,
    totalCompletedSurveys: 0,
    topUser: null,
  };

  for (const u of users) {
    const earned =
      typeof u.totalEarnedCents === 'number'
        ? u.totalEarnedCents
        : (u.balanceCents || 0);

    stats.totalEarnedCents += earned;

    if (typeof u.completedSurveys === 'number') {
      stats.totalCompletedSurveys += u.completedSurveys;
    }

    if (!stats.topUser || earned > stats.topUser.earned) {
      stats.topUser = {
        name: u.username || (u.email ? u.email.split('@')[0] : 'User'),
        earned,
      };
    }
  }

  return stats;
}

app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

// --- Auth middleware: cookie -> Supabase profile -> req.user ---
async function loadUserFromCookie(req, res, next) {
  try {
    const token = req.cookies.session;
    if (!token) {
      req.user = null;
      return next();
    }

    const { data: session, error: sErr } = await supabaseAdmin
      .from('sessions')
      .select('user_id, expires_at')
      .eq('token', token)
      .maybeSingle();

    if (sErr || !session) {
      req.user = null;
      return next();
    }

    if (new Date(session.expires_at) < new Date()) {
      await supabaseAdmin.from('sessions').delete().eq('token', token);
      req.user = null;
      return next();
    }

    const { data: profile, error: pErr } = await supabaseAdmin
      .from('profiles')
      .select('*')
      .eq('user_id', session.user_id)
      .maybeSingle();

    if (pErr || !profile) {
      req.user = null;
      return next();
    }

    req.user = {
      id: profile.user_id,
      email: profile.email,
      username: profile.username,
      createdAt: new Date(profile.created_at).getTime(),
      balanceCents: Number(profile.balance_cents || 0),
      totalEarnedCents: Number(profile.total_earned_cents || 0),
      completedSurveys: Number(profile.completed_surveys || 0),
      completedOffers: Number(profile.completed_offers || 0),
      usernameChangedAt: Number(profile.username_changed_at || 0),
      passwordChangedAt: Number(profile.password_changed_at || 0),
    };

    return next();
  } catch (e) {
    console.error('loadUserFromCookie error:', e);
    req.user = null;
    return next();
  }
}

app.use(loadUserFromCookie);


function layout({ title, active, bodyHtml, loggedIn }) {
  const tab = (path, label) => {
    const isActive = active === path;
    return `<a href="${path}" class="nav-item ${isActive ? 'active' : ''}">${label}</a>`;
  };

  // loggedIn er nu enten null eller user-objekt
  const user = loggedIn || null;

  // Navn der vises i chippen (username først, ellers email-del før @)
  const displayName =
    user && user.username && user.username.trim()
      ? user.username.trim()
      : user && user.email
        ? String(user.email).split('@')[0]
        : '';

  // Avatar-initial: ALTID første tegn i displayName (username),
  // fallback til første tegn i email hvis displayName er tom
  const userInitial =
    displayName && displayName.trim().length > 0
      ? displayName.trim().charAt(0).toUpperCase()
      : (user && user.email
          ? String(user.email).trim().charAt(0).toUpperCase()
          : '');

  // balance (cents -> "0.00")
  const balanceCents =
    user && typeof user.balanceCents === 'number' ? user.balanceCents : 0;
  const balanceAmountText = (balanceCents / 100).toFixed(2);

  const clientScript = `
<script>
(function () {
  var backdrop = document.getElementById('auth-backdrop');
  var modeInput = document.getElementById('auth-mode');
  var titleEl = document.getElementById('auth-title');
  var submitLabel = document.getElementById('auth-submit-label');
  var form = document.getElementById('auth-form');
  var switchText = document.getElementById('auth-switch-text');
  var switchLink = document.getElementById('auth-switch-link');
  var errorBox = document.getElementById('auth-error');
  var emailInput = form ? form.querySelector('input[name="email"]') : null;
  var passInput  = form ? form.querySelector('input[name="password"]') : null;
  var usernameField = document.getElementById('field-username');
  var ageCheck = document.getElementById('ageConfirm');

  if (!backdrop) return;

  var infoPop = document.getElementById('auth-info-pop');

  function clearInfo() {
    if (!infoPop) return;
    infoPop.style.display = 'none';
    infoPop.innerHTML = '';
  }

  function showInfoPopup(title, text) {
    if (!infoPop) return;
    infoPop.innerHTML =
      '<div class="auth-info-title">' + title + '</div>' +
      '<div class="auth-info-text">' + text + '</div>' +
      '<div class="auth-info-actions">' +
        '<button type="button" class="auth-info-btn" onclick="window.location.reload()">Refresh</button>' +
        '<button type="button" class="auth-info-btn primary" onclick="closeAuth()">OK</button>' +
      '</div>';
    infoPop.style.display = 'block';
  }

  function clearError() {
    if (errorBox) {
      errorBox.style.display = 'none';
      errorBox.textContent = '';
    }
    clearInfo();
  }

  function resetAgeGate() {
    if (!ageCheck || !submitLabel) return;
    ageCheck.checked = false;
    submitLabel.disabled = true;
    submitLabel.style.opacity = 0.5;
    submitLabel.style.cursor = 'not-allowed';
  }

  function setMode(mode) {
    modeInput.value = mode;
    clearError();
    if (mode === 'login') {
      titleEl.textContent = 'Log in';
      submitLabel.textContent = 'Log in';
      form.action = '/login';
      switchText.textContent = "Don't have an account?";
      switchLink.textContent = ' Sign up';
      if (usernameField) usernameField.style.display = 'none';
    } else {
      titleEl.textContent = 'Sign up';
      submitLabel.textContent = 'Sign up with email';
      form.action = '/signup';
      switchText.textContent = 'Already have an account?';
      switchLink.textContent = ' Log in';
      if (usernameField) usernameField.style.display = 'block';
    }
    // hver gang vi skifter mode, reset 18+ checkbox
    resetAgeGate();
  }

  function openAuth(mode) {
    if (!mode) mode = 'login';
    setMode(mode);
    backdrop.classList.add('open');
  }

  function closeAuth() {
    backdrop.classList.remove('open');
    clearError();
  }

  window.openAuth = openAuth;
  window.closeAuth = closeAuth;


 
// ✅ resend verify email + cooldown
var resendBtn = null;
var resendHint = null;
var resendSecsEl = null;

var resendCooldown = 0;
var resendTimer = null;

// ✅ VERIFY OVERLAY FUNCTIONS
function openVerify() {
  var vb = document.getElementById('verify-backdrop');
  if (vb) vb.classList.add('open');

  // ✅ find elements hver gang overlay åbnes
  resendBtn = document.getElementById('verify-resend-btn');
  resendHint = document.getElementById('verify-resend-hint');
  resendSecsEl = document.getElementById('verify-resend-secs');

  // ✅ start cooldown med det samme (anti spam)
  startResendCooldown(60);
}

function closeVerify() {
  var vb = document.getElementById('verify-backdrop');
  if (vb) vb.classList.remove('open');
}

window.openVerify = openVerify;
window.closeVerify = closeVerify;

function startResendCooldown(seconds) {
  resendCooldown = seconds || 60;
  if (!resendBtn) return;

  // ✅ stop gammel timer så den ikke kører dobbelt
  if (resendTimer) {
    clearInterval(resendTimer);
    resendTimer = null;
  }

  resendBtn.disabled = true;
  if (resendHint) resendHint.style.display = 'block';

  function tick() {
    if (!resendBtn) return;
    if (resendSecsEl) resendSecsEl.textContent = String(resendCooldown);

    if (resendCooldown <= 0) {
      resendBtn.disabled = false;
      resendBtn.textContent = 'Resend email';
      if (resendHint) resendHint.style.display = 'none';
      clearInterval(resendTimer);
      resendTimer = null;
      return;
    }

    resendBtn.textContent = 'Resend in ' + resendCooldown + 's';
    resendCooldown--;
  }

  tick();
  resendTimer = setInterval(tick, 1000);
}

window.resendVerifyEmail = async function () {
  if (!resendBtn || resendBtn.disabled) return;

  resendBtn.disabled = true;
  resendBtn.textContent = 'Sending...';

  try {
    const r = await fetch('/auth/resend-verify', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'same-origin',
      body: JSON.stringify({}),
    });

    const j = await r.json().catch(() => null);

    if (!r.ok || !j?.ok) {
      resendBtn.disabled = false;
      resendBtn.textContent = 'Resend email';
      alert('Could not resend email. Please try again later.');
      return;
    }

    // ✅ start cooldown 60 sek
    startResendCooldown(60);
  } catch (e) {
    resendBtn.disabled = false;
    resendBtn.textContent = 'Resend email';
    alert('Network error. Please try again.');
  }
};


  // VI LUKKER IKKE LÆNGERE MODAL VED KLIK UDENFOR
  // backdrop.addEventListener('click', function (e) {
  //   if (e.target === backdrop) closeAuth();
  // });

  document.getElementById('auth-close')?.addEventListener('click', closeAuth);

  switchLink?.addEventListener('click', function (e) {
    e.preventDefault();
    var newMode = modeInput.value === 'login' ? 'signup' : 'login';
    setMode(newMode);
  });

  // skjul fejl når man begynder at skrive
  [emailInput, passInput].forEach(function (inp) {
    if (!inp) return;
    inp.addEventListener('input', clearError);
  });

  // 18+ checkbox styrer om knappen er aktiv
  if (ageCheck && submitLabel) {
    function updateAgeState() {
      if (ageCheck.checked) {
        submitLabel.disabled = false;
        submitLabel.style.opacity = 1;
        submitLabel.style.cursor = 'pointer';
      } else {
        submitLabel.disabled = true;
        submitLabel.style.opacity = 0.5;
        submitLabel.style.cursor = 'not-allowed';
      }
    }
    ageCheck.addEventListener('change', updateAgeState);
    updateAgeState();
  }

// --- vis auth fejl fra querystring ---
var params = new URLSearchParams(window.location.search);
var err = params.get('authError');
var modeFromUrl = params.get('mode') || 'login';

if (err) {
  // reset visning
  clearError();

  // ✅ CHECKEMAIL: kun verify overlay (ingen auth modal bagved)
  if (err === 'checkemail') {
    openVerify();

    // fjern fejl-parametre fra URL så den ikke kommer igen ved refresh
    window.history.replaceState(
      null,
      '',
      window.location.pathname + window.location.hash
    );
    return;
  }

  // ✅ Alle andre errors: åbn auth modal og vis rød boks
  setMode(modeFromUrl);
  openAuth(modeFromUrl);

  if (errorBox) {
    if (err === 'nouser') {
      errorBox.textContent = "This account doesn't exist.";
    } else if (err === 'badpass') {
      errorBox.textContent = "Wrong password.";
    } else if (err === 'exists') {
      errorBox.textContent = "This e-mail is already in use.";
    } else if (err === 'username_taken') {
      errorBox.textContent = "Name already in use.";
    } else if (err === 'notconfirmed') {
      errorBox.textContent = "Please confirm your e-mail before logging in.";
    } else if (err === 'invalid') {
      errorBox.textContent = "Please enter a valid e-mail, password and username.";
    } else {
      errorBox.textContent = "Something went wrong. Please try again.";
    }

    errorBox.style.display = 'block';
  }

  // fjern fejl-parametre fra URL så de ikke kommer igen ved refresh
  window.history.replaceState(
    null,
    '',
    window.location.pathname + window.location.hash
  );
}

   // default-mode: login (username skjult)
  if (usernameField && modeInput.value === 'login') {
    usernameField.style.display = 'none';
  }

  // --- Sync login/logout mellem faner ---
  window.addEventListener('storage', function (e) {
    if (e.key === 'surveycash:login' || e.key === 'surveycash:logout') {
      window.location.reload();
    }
  });

})();

// --- profil-menu til avatar i header ---
window.toggleProfileMenu = function () {
  var menu = document.getElementById('profile-menu');
  if (!menu) return;
  menu.style.display = (menu.style.display === 'block') ? 'none' : 'block';
};

document.addEventListener('click', function (e) {
  var menu = document.getElementById('profile-menu');
  if (!menu) return;
  if (!e.target.closest('.profile-wrap')) {
    menu.style.display = 'none';
  }
});
</script>`;

  return `<!doctype html>
<html lang="en">

<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>${title}</title>

<!-- TrustBox script -->
<script
  type="text/javascript"
  src="//widget.trustpilot.com/bootstrap/v5/tp.widget.bootstrap.min.js"
  async>
</script>
<!-- End TrustBox script -->

<style>
  :root { color-scheme: dark; }
  * {
    box-sizing: border-box;
    -webkit-user-select: none;
    -ms-user-select: none;
    user-select: none;       /* ALT tekst kan ikke markeres som standard */
  }

  body {
    margin: 0;
    font-family: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
    background: #111827; /* mørk grå */
    color: #e5e7eb;
  }

  /* Header */
  header {
    position: sticky;
    top: 0;
    background: #151c2e; /* lidt lysere end baggrund */
    border-bottom: 1px solid #1f2937;
    padding: 12px 20px;
    z-index: 20;
    display: flex;
    align-items: center;
    gap: 16px;
  }

  .logo {
    font-size: 26px;
    font-weight: 900;
    color: #fff;
    letter-spacing: .2px;
    margin-right: 8px;
  }
  .logo .accent { color: #fbbf24; }

  nav { display:flex; gap:16px; flex:1; justify-content:center; }

  .nav-item {
    color:#d1d5db;
    text-decoration:none;
    font-weight:600;
    padding:8px 14px;
    border-radius:10px;
    transition:background .15s, color .15s;
  }
  .nav-item:hover{ background:#1f2937; color:#fff; }
  .nav-item.active{ background:#fbbf24; color:#111827; }

  .auth { margin-left:auto; display:flex; gap:10px; }

  .btn {
    display:inline-flex;
    align-items:center;
    justify-content:center;
    padding:8px 16px;
    border-radius:999px;
    text-decoration:none;
    font-weight:600;
    font-size:14px;
    cursor:pointer;
    border:1px solid #374151;
    background:transparent;
    color:#e5e7eb;
    transition:background .15s, border-color .15s, color .15s;
  }
  .btn:hover {
    background:#1f2937;
    border-color:#4b5563;
  }

  .btn-signup {
    background:#fbbf24;
    border-color:#d97706;
    color:#111827;
  }
  .btn-signup:hover {
    background:#f59e0b;
    border-color:#d97706;
    color:#111827;
  }

  .btn-logout {
    text-decoration:none;
  }

  /* ===== Header: saldo + klokke + profil ===== */
  .profile-wrap {
    position: relative;
    display: flex;
    align-items: center;
    gap: 10px;
  }

  /* Freecash-style balance pill – gul $ + hvidt tal */
  .balance-pill {
    display: flex;
    align-items: center;
    justify-content: center;
    gap: 6px;
    padding: 8px 16px;
    border-radius: 6px;
    background: linear-gradient(
      to bottom,
      rgba(251, 191, 36, 0.15) 0%,
      rgba(251, 191, 36, 0.05) 100%
    );
    border: none; /* ingen outline */
    height: 38px;
  }

  .balance-symbol {
    color: #fbbf24;
    font-weight: 900;
    font-size: 20px;
    margin-top: -1px;
  }

  .balance-amount {
    color: #ffffff;
    font-weight: 700;
    font-size: 15px; /* lidt mindre end før */
  }

  /* Profil-chip — fade ligesom balance pill */
  .profile-chip {
    display: flex;
    align-items: center;
    gap: 10px;
    padding: 6px 14px;
    border-radius: 12px;
    background: linear-gradient(
      to bottom,
      rgba(251, 191, 36, 0.15) 0%,
      rgba(251, 191, 36, 0.05) 100%
    );
    border: none;
    box-shadow: 0 4px 14px rgba(0,0,0,0.25);
    cursor: pointer;
    user-select: none;
    transition: background 0.15s ease, box-shadow 0.15s ease, transform 0.1s ease;
  }

  .profile-chip:hover {
    background: #25314e;
    transform: translateY(-1px);
    box-shadow: 0 8px 20px rgba(0,0,0,0.35);
  }

  /* Avatar — ren gul cirkel */
  .profile-avatar {
    width: 32px;
    height: 32px;
    border-radius: 50%;
    background: #fbbf24;
    display: flex;
    align-items: center;
    justify-content: center;
    user-select: none;
    cursor: pointer;
    box-shadow: none;
  }

  .profile-avatar span {
    font-weight: 800;
    font-size: 17px;
    color: #ffffff;
  }

  /* Username */
  .profile-name {
    font-size: 14px;
    font-weight: 600;
    color: #e5e7eb;
    user-select: none;
    cursor: pointer;
    white-space: nowrap;
    max-width: 180px;
    overflow: hidden;
    text-overflow: ellipsis;
  }

  /* Freecash-style grå klokke med SVG */
  .notif-bell {
    border: none;
    background: transparent;
    display: flex;
    align-items: center;
    justify-content: center;
    cursor: pointer;
    padding: 0;
    width: 42px;
    height: 42px;
    transform: translateY(3px); /* lidt ned i headeren */
  }

  .notif-bell svg {
    width: 32px;
    height: 32px;
    fill: #9ca3af;
    opacity: 0.95;
    transition: fill 0.15s ease;
  }

  .notif-bell:hover svg {
    fill: #d5d9e6;
  }

  .profile-menu {
    position: absolute;
    right: 0;
    top: 46px;
    background: #1a1f2b;
    border: 1px solid #2a3240;
    border-radius: 10px;
    padding: 4px 0; /* mindre */
    min-width: 120px; /* mindre */
    display: none;
    z-index: 40;
  }
  .profile-menu a {
    display:block;
    padding:7px 12px;
    text-decoration:none;
    color:#e5e7eb;
    font-size:13px;
  }
  .profile-menu a:hover {
    background:#111827;
  }

  main { max-width: 1100px; margin: 0 auto; padding: 40px 20px 60px; }

  .btn-ghost{
    display:inline-block;
    padding:10px 16px;
    border-radius:10px;
    border:1px solid #374151;
    text-decoration:none;
    color:#e5e7eb;
  }
  .btn-ghost:hover{ background:#111827; }

  pre{
    background:#020617;
    padding:12px;
    border-radius:10px;
    overflow:auto;
  }

/* Landing hero */
.hero-wrap{
  max-width:900px;
  margin:45px auto 0;
  text-align:center;
}

.hero-title{
  font-size:44px;
  font-weight:900;
  line-height:1.15;
  margin-bottom:10px;
}
.hero-title .green{ color:#fbbf24; }

.hero-sub{
  color:#cbd5e1;
  margin-bottom:18px;
  font-size:15px;
}

.hero-cta{
  display:flex;
  justify-content:center;
  gap:10px;
}

.hero-cta .btn{
  padding:10px 26px;
  border-radius:18px;
}


/* ===== Landing: How it works + Trustpilot (DARK BLUE / NO SHADOW / NO OUTLINE) ===== */
:root{
  /* ✅ mørkeblå cards (ikke grå) - kun lidt mørkere end baggrund */
  --bg-card: rgba(8, 12, 22, .55);
  --bg-card-hover: rgba(8, 12, 22, .68);

  /* ❌ ingen kant */
  --card-border: transparent;

  /* ❌ ingen shadow */
  --card-shadow: none;
}

/* ===== Landing: How it works ===== */
.hiw-wrap{
  margin-top: 78px;
  max-width: 1050px;
  margin-left: auto;
  margin-right: auto;
  text-align: center;
  padding: 0 10px;
}

.hiw-title{
  margin: 0 0 18px;
  font-size: 32px;
  font-weight: 900;
  color: #ffffff;
  letter-spacing: .2px;
}

.hiw-grid{
  display: grid;
  grid-template-columns: repeat(3, minmax(0, 1fr));
  gap: 16px;
  margin-top: 14px;
}

/* ✅ Cards: ingen outline / ingen hover outline */
.hiw-card{
  text-align:left;
  padding: 18px 18px 16px;
  border-radius: 18px;
  min-height: 108px;

  background: var(--bg-card);
  border: 0 !important;
  outline: none !important;
  box-shadow: none;

  transition: transform .15s ease, background .15s ease;
}

.hiw-card:hover{
  transform: translateY(-2px);
  background: var(--bg-card-hover);
}

.hiw-num{
  font-size: 28px;
  font-weight: 900;
  color: #fbbf24;
  line-height: 1;
  margin-bottom: 10px;
}

.hiw-head{
  font-size: 15px;
  font-weight: 850;
  color: #ffffff;
  margin-bottom: 5px;
}

.hiw-text{
  font-size: 12.5px;
  color: rgba(203,213,225,.92);
  line-height: 1.5;
}


/* ===== Landing: Trustpilot footer strip ===== */
.tp-wrap{
  margin-top: 55px;
  max-width: 1050px;
  margin-left: auto;
  margin-right: auto;
  padding-bottom: 30px;
  padding-left: 10px;
  padding-right: 10px;
}

.tp-card{
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 14px;

  border-radius: 18px;
  padding: 14px 16px;

  background: var(--bg-card);
  border: 0 !important;
  outline: none !important;
  box-shadow: none;

  transition: transform .15s ease, background .15s ease;
}

.tp-card:hover{
  transform: translateY(-1px);
  background: var(--bg-card-hover);
}

.tp-left{
  display: flex;
  align-items: center;
  gap: 14px;
}

.tp-logo{
  width: 130px;
  height: auto;
  opacity: .95;
}

.tp-title{
  font-weight: 900;
  color: #ffffff;
  margin-bottom: 2px;
}

.tp-sub{
  font-size: 12px;
  color: rgba(203,213,225,.92);
}

.tp-btn{
  border-radius: 14px;
  padding: 10px 16px;
}


/* responsive */
@media (max-width: 900px){
  .hiw-grid{ grid-template-columns: 1fr; }
  .tp-card{ flex-direction: column; align-items: flex-start; }
  .tp-btn{ width: 100%; text-align: center; }
}

/* ===== Trustpilot bar (NO STARS / clean layout) ===== */

.tp-wrap{
  margin-top:55px;
  max-width:1050px;
  margin-left:auto;
  margin-right:auto;
  padding:0 10px 30px;
}

.tp-bar{
  display:flex;
  align-items:center;
  justify-content:space-between;
  gap:16px;

  text-decoration:none;
  border-radius:18px;
  padding:18px 20px;

  background: rgba(8,12,22,.55);
  transition: all .15s ease;
}

.tp-bar:hover{
  transform: translateY(-1px);
  background: rgba(8,12,22,.68);
}

/* left area */
.tp-bar-left{
  display:flex;
  align-items:center;
  gap:14px;
}

/* text + logo inline */
.tp-bar-bottom{
  display:flex;
  align-items:center;
  gap:10px;
}

/* større tekst */
.tp-copy{
  font-size:15px;
  color:rgba(203,213,225,.95);
  font-weight:500;
}

/* Trustpilot logo */
.tp-mark-inline{
  width:18px;
  height:18px;
}

/* TRUSTPILOT ord */
.tp-brand{
  font-size:18px;
  font-weight:900;
  color:#ffffff;
  letter-spacing:.2px;
}

/* right button */
.tp-pill{
  background:#22c55e;        /* Trustpilot grøn */
  color:#ffffff;             /* hvid tekst */
  font-weight:800;
  padding:10px 16px;
  border-radius:14px;
  font-size:13px;
  transition: all .15s ease;
}

.tp-pill:hover{
  background:#16a34a;        /* mørkere grøn hover */
  transform: translateY(-1px);
}


/* mobile */
@media (max-width:900px){
  .tp-bar{
    flex-direction:column;
    align-items:flex-start;
  }

  .tp-pill{
    width:100%;
    text-align:center;
  }
}



  /* ===== Account / profil layout ===== */
  .account-wrap {
    margin-top: 40px;
    display: grid;
    grid-template-columns: minmax(0, 2fr) minmax(0, 2fr);
    gap: 24px;
  }

  /* Venstre profilkort – gul/premium */
  .account-main-card {
    background:
      radial-gradient(circle at 0 0, rgba(251, 191, 36, 0.16), transparent 55%),
      #121826;
    border-radius: 18px;
    border: 1px solid rgba(251, 191, 36, 0.10);
    padding: 24px 24px 20px;
    display: flex;
    align-items: center;
    gap: 20px;
    box-shadow: 0 22px 60px rgba(0,0,0,0.55);
  }

  .account-avatar-big {
    width: 110px;
    height: 110px;
    border-radius: 999px;
    background: radial-gradient(circle at 30% 20%, #fef9c3 0, #facc15 35%, #f59e0b 100%);
    display: flex;
    align-items: center;
    justify-content: center;
    flex-shrink: 0;
  }

  .account-avatar-big span {
    font-size: 56px;
    font-weight: 700;
    color: #ffffff;
  }

  .account-main-info {
    display: flex;
    flex-direction: column;
    gap: 6px;
  }

  .account-main-name {
    font-size: 24px;
    font-weight: 700;
  }

  .account-main-joined {
    font-size: 13px;
    color: #9ca3af;
  }

  .account-main-email {
    font-size: 13px;
    color: #cbd5e1;
  }

  /* Stats til højre */
  .account-stat-grid {
    display: grid;
    grid-template-columns: 1fr;
    gap: 16px;
  }

  .account-stat-card {
    background:
      radial-gradient(circle at 0 0, rgba(251, 191, 36, 0.10), transparent 55%),
      #121826;
    border-radius: 18px;
    border: 1px solid rgba(15, 23, 42, 0.9);
    padding: 18px 20px;
    box-shadow: 0 18px 50px rgba(0,0,0,0.5);
  }

/* === Stats: IKONER + TEKST === */
.account-stat-label-row {
  display: flex;
  align-items: center;
  gap: 10px;
  margin-bottom: 8px;
  font-size: 13px;
  color: #ffffff; /* TEKST → HVID */
}


/* Tal → Gul */
.account-stat-value {
  font-size: 22px;
  font-weight: 800;
  color: #ffcf3a;
  letter-spacing: 0.01em;
}

  @media (max-width: 900px) {
    .account-wrap {
      grid-template-columns: minmax(0, 1fr);
    }
  }

  /* Auth modal */
  .auth-backdrop{
    position:fixed;
    inset:0;
    background:rgba(12,16,28,.82);
    display:none;
    align-items:center;
    justify-content:center;
    z-index:50;
  }
  .auth-backdrop.open{ display:flex; }

  .auth-modal{
    width:100%;
    max-width:420px;
    background:#1a1f2b;
    border-radius:24px;
    border:1px solid #1f2937;
    padding:32px 28px 28px;
    box-shadow:0 32px 90px rgba(0,0,0,.75);
    position:relative;
    min-height:360px;
  }

  .auth-title{
    font-size:24px;
    font-weight:700;
    text-align:center;
    margin-bottom:16px;
  }

  .auth-close{
    position:absolute;
    right:18px;
    top:16px;
    width:28px;
    height:28px;
    border-radius:999px;
    border:1px solid #4b5563;
    background:#111827;
    color:#e5e7eb;
    display:flex;
    align-items:center;
    justify-content:center;
    font-size:18px;
    cursor:pointer;
  }

  .auth-error{
    display:none;
    background:#7f1d1d;
    color:#fecaca;
    padding:8px 12px;
    font-size:13px;
    border-radius:8px;
    margin-bottom:12px;
    border:1px solid #b91c1c;
    text-align:center;
  }

/* ===== Verify your email overlay (DARK, taller, not wide) ===== */
.verify-backdrop{
  position:fixed;
  inset:0;
  background: rgba(0,0,0,.72);
  backdrop-filter: blur(6px);
  -webkit-backdrop-filter: blur(6px);
  display:none;
  align-items:center;
  justify-content:center;
  z-index:9999;
}
.verify-backdrop.open{ display:flex; }

.verify-modal{
  width:100%;
  max-width:520px;              /* ✅ normal bredde */
  min-height:260px;             /* ✅ gør den højere */
  background: #1a1f2b;          /* ✅ dark design */
  color: #e5e7eb;
  border-radius: 22px;
  padding: 40px 32px;           /* ✅ mere vertical space */
  text-align:center;
  border: 1px solid rgba(255,255,255,.08);
  box-shadow: 0 40px 120px rgba(0,0,0,.70);
  position:relative;
}

/* titel */
.verify-modal h2{
  margin:0 0 14px;
  font-size:28px;
  font-weight:900;
  color:#ffffff;
}

/* tekst */
.verify-modal p{
  margin:0 auto 26px;
  font-size:14px;
  line-height:1.6;
  color:#cbd5e1;
  max-width:420px;
}

/* knapper */
.verify-actions{
  display:flex;
  flex-direction:column;
  gap:10px;
  justify-content:center;
  align-items:center;
  margin-top: 6px;
}

.verify-note{
  margin-top:10px;
  font-size:12px;
  color:#9ca3af;
}


.verify-btn{
  min-width: 210px;
  border-radius:999px;
  padding:11px 18px;
  font-weight:800;
  font-size:14px;
  cursor:pointer;
  border: 1px solid rgba(255,255,255,.12);
  background: rgba(255,255,255,.06);
  color:#e5e7eb;
  transition: transform .12s ease, background .12s ease, border-color .12s ease;
}


.verify-btn:hover{
  transform: translateY(-1px);
  background: rgba(255,255,255,.10);
  border-color: rgba(255,255,255,.20);
}

/* primary = gul SurveyCash vibe */
.verify-btn.primary{
  background:#fbbf24;
  border-color:#d97706;
  color:#111827;
}

.verify-btn.primary:hover{
  background:#f59e0b;
}

.verify-btn.primary:disabled{
  opacity:.55;
  cursor:not-allowed;
  transform:none;
}
.verify-btn.primary:disabled:hover{
  background:#fbbf24; /* hold samme farve */
}


/* close icon */
.verify-close{
  position:absolute;
  right:16px;
  top:16px;
  width:34px;
  height:34px;
  border-radius:999px;
  border:1px solid rgba(255,255,255,.12);
  background: rgba(15,23,42,.55);
  color:#ffffff;
  font-size:18px;
  line-height:1;
  cursor:pointer;
}

.verify-close:hover{
  background: rgba(15,23,42,.80);
}


  .field input{
    width:100%;
    padding:12px 14px;
    border-radius:10px;
    border:1px solid #2a3240;
    background:#131822;
    color:#e5e7eb;
    font-size:14px;
    margin-bottom:14px;

    /* input må gerne kunne markeres/kopieres */
    -webkit-user-select: text;
    -ms-user-select: text;
    user-select: text;
  }
  .field input::placeholder{ color:#6b7280; }
  .field input:focus{
    border-color:#4b5563;
    outline:none;
  }

  /* 18+ checkbox */
  .age-check {
    display:flex;
    align-items:center;
    gap:10px;
    margin: 4px 0 14px;
    font-size:13px;
    color:#e5e7eb;
  }
  .age-check input[type="checkbox"] {
    width:18px;
    height:18px;
    cursor:pointer;
  }
  .age-check label {
    cursor:pointer;
    user-select:none;
    color:#d1d5db;
  }

  .cta-main{
    width:100%;
    padding:12px 14px;
    border-radius:10px;
    border:1px solid #d97706;
    background:#fbbf24;
    font-weight:700;
    color:#111827;
    cursor:pointer;
    margin-top:6px;
  }
  .cta-main:hover{
    background:#f59e0b;
  }

  .top-links{
    display:flex;
    justify-content:space-between;
    font-size:12px;
    margin-top:18px;
  }
  .top-links a{ color:#fbbf24; text-decoration:none; }

  .fineprint{
    margin-top:18px;
    font-size:11px;
    color:#6b7280;
    text-align:center;
  }
  .fineprint a{ color:#fbbf24; text-decoration:none; }

  @media (max-width:768px){
    nav{ display:none; }
    .hero-title{ font-size:34px; }
    .auth-modal{ margin:0 10px; }
  }

  /* ===== Cashout UI (notice + card) ===== */
  .notice{
    margin: 14px 0 14px;
    padding: 12px 14px;
    border-radius: 12px;
    font-weight: 700;
    border: 1px solid rgba(255,255,255,.10);
    background: rgba(15,23,42,.55);
  }
  .notice.success{
    border-color: rgba(34,197,94,.35);
    background: rgba(34,197,94,.10);
  }
  .notice.error{
    border-color: rgba(239,68,68,.35);
    background: rgba(239,68,68,.10);
  }

  .card{
    margin-top: 14px;
    padding: 16px;
    border-radius: 16px;
    border: 1px solid rgba(255,255,255,.08);
    background: rgba(15,23,42,.45);
  }

  .card input{
    width: 100%;
    padding: 12px 12px;
    border-radius: 10px;
    border: 1px solid #2a3240;
    background: #131822;
    color: #e5e7eb;
    margin-bottom: 10px;
    -webkit-user-select: text;
    user-select: text;
  }

  .card button{
    width: 100%;
    padding: 12px 14px;
    border-radius: 10px;
    border: 1px solid #d97706;
    background: #fbbf24;
    color: #111827;
    font-weight: 800;
    cursor: pointer;
  }
  .card button:disabled{
    opacity: .55;
    cursor: not-allowed;
  }
</style>
</head>
<body>
  <header>
    <div class="logo">Survey<span class="accent">Cash</span></div>

    ${user ? `
      <nav>
        ${tab('/', 'Home')}
        ${tab('/surveys', 'Surveys')}
        ${tab('/games', 'Games')}
        ${tab('/cashout', 'Cash Out')}
        ${tab('/support', 'Support')}
      </nav>
    ` : `<div style="flex:1"></div>`}

    <div class="auth">
      ${user
        ? `
          <div class="profile-wrap">
            <div class="balance-pill">
              <span class="balance-symbol">$</span>
              <span class="balance-amount">${balanceAmountText}</span>
            </div>

            <button class="notif-bell" type="button" aria-label="Notifications">
              <svg viewBox="0 0 24 24" aria-hidden="true" focusable="false">
                <circle cx="12" cy="4" r="1.8" />
                <path d="M6 10a6 6 0 0112 0v3.2l1.2 2A1 1 0 0118.4 17H5.6a1 1 0 01-.8-1.8l1.2-2V10z"/>
                <circle cx="12" cy="18.3" r="1.2" />
              </svg>
            </button>

            <div class="profile-chip" onclick="toggleProfileMenu()">
              <div class="profile-avatar">
                <span>${userInitial}</span>
              </div>
              <div class="profile-name">${displayName ? escapeHtml(displayName) : ''}</div>
            </div>

            <div id="profile-menu" class="profile-menu">
              <a href="/account">Account</a>
              <a href="/logout">Log out</a>
            </div>
          </div>
        `
        : `
          <button type="button" class="btn" onclick="openAuth('login')">Log in</button>
          <button type="button" class="btn btn-signup" onclick="openAuth('signup')">Sign up</button>
        `}
    </div>
  </header>

  <main>${bodyHtml}</main>


  <!-- Verify Email Overlay -->
  <div id="verify-backdrop" class="verify-backdrop">
    <div class="verify-modal">
      <button class="verify-close" type="button" onclick="closeVerify()">×</button>

      <h2>Verify your email</h2>
      <p>
        We’ve sent you a verification email.<br/>
        Please open your inbox and click the link to confirm your account.
      </p>

<div class="verify-actions">
  <button
    type="button"
    id="verify-resend-btn"
    class="verify-btn primary"
    onclick="resendVerifyEmail()"
  >
    Resend email
  </button>

  <div class="verify-note">
    It can take up to 15 minutes to receive the email.
  </div>
</div>

    </div>
  </div>

  <!-- Auth modal -->
  <div id="auth-backdrop" class="auth-backdrop">
    <div class="auth-modal">
      <button id="auth-close" class="auth-close" type="button">×</button>
      <div id="auth-title" class="auth-title">Log in</div>

      <div id="auth-error" class="auth-error"></div>



<!-- ✅ BIG popup (email verification) -->

      <form id="auth-form" action="/login" method="POST">
        <input type="hidden" id="auth-mode" name="_mode" value="login"/>

        <!-- Username (kun synlig i signup-mode) -->
        <div class="field" id="field-username">
          <input type="text" name="username" placeholder="Username" minlength="2" maxlength="24"/>
        </div>

        <div class="field">
          <input type="email" name="email" placeholder="E-mail address" required/>
        </div>

        <div class="field">
          <input type="password" name="password" placeholder="Password" minlength="6" required/>
        </div>

        <!-- 18+ checkbox -->
        <div class="age-check">
          <input type="checkbox" id="ageConfirm" />
          <label for="ageConfirm">I confirm that I am at least 18 years old</label>
        </div>

        <button id="auth-submit-label" class="cta-main" type="submit">Log in</button>
      </form>

      <div class="top-links">
        <a href="#">Forgot your password?</a>
        <span><span id="auth-switch-text">Don't have an account?</span><a href="#" id="auth-switch-link"> Sign up</a></span>
      </div>

<div class="fineprint">
  By using SurveyCash you agree to our
  <a href="/terms" target="_blank">Terms</a>
  and
  <a href="/privacy" target="_blank">Privacy Policy</a>.
</div>


  ${clientScript}
</body>
</html>`;
}

const page = (req, title, active, inner) =>
  layout({ title, active, bodyHtml: inner, loggedIn: getUserFromReq(req) });

const escapeHtml = (s) =>
  String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');

// ---------- Landing (for guests) ----------
function landingHtml() {
  return `
  <section class="hero-wrap">
    <h1 class="hero-title">
      Get <span class="green">paid</span> for testing games, apps<br/>
      and answering surveys
    </h1>
    <p class="hero-sub">
      Earn rewards quickly by completing fun tasks and surveys — start earning today.
    </p>
    <div class="hero-cta">
      <button type="button" class="btn" onclick="openAuth('login')">Log in</button>
      <button type="button" class="btn btn-signup" onclick="openAuth('signup')">Sign up</button>
    </div>

    <!-- How it works -->
    <div class="hiw-wrap">
      <h2 class="hiw-title">How it works</h2>

      <div class="hiw-grid">
        <div class="hiw-card">
          <div class="hiw-num">1</div>
          <div class="hiw-head">Sign up</div>
          <div class="hiw-text">Create your free account.</div>
        </div>

        <div class="hiw-card">
          <div class="hiw-num">2</div>
          <div class="hiw-head">Complete tasks</div>
          <div class="hiw-text">Earn money by completing surveys & offers.</div>
        </div>

        <div class="hiw-card">
          <div class="hiw-num">3</div>
          <div class="hiw-head">Cash out</div>
          <div class="hiw-text">Withdraw your earnings via PayPal.</div>
        </div>
      </div>
    </div>

<!-- Trustpilot (custom bar) -->
<div class="tp-wrap">
  <a class="tp-bar" href="https://www.trustpilot.com/review/surveycash.website" target="_blank" rel="noopener">

    <div class="tp-bar-left">

      <div class="tp-bar-text">
        <div class="tp-bar-bottom">
          <span class="tp-copy">See our reviews on</span>
          <img src="/trustpilot-mark.svg" alt="Trustpilot" class="tp-mark-inline" />
          <span class="tp-brand">Trustpilot</span>
        </div>
      </div>

    </div>

    <span class="tp-pill">View on Trustpilot</span>

  </a>
</div>

<!-- End Trustpilot -->
  </section>
  `;
}



// ---------- Routes ----------
app.get('/', async (req, res) => {
  // Ikke logget ind -> vis landing
  if (!isLoggedIn(req)) {
    return res.send(
      layout({
        title: 'SurveyCash — Earn by testing apps, games & surveys',
        active: null,
        bodyHtml: landingHtml(),
       loggedIn: null,
      }),
    );
  }

  const user = getUserFromReq(req) || null;

// ✅ Community stats fra Supabase
let totalUsers = 0;
let totalEarnedUsd = '0.00';

try {
  const { data, error } = await supabaseAdmin.rpc('get_community_stats');
  if (error) throw error;

  const row = Array.isArray(data) ? data[0] : data;

  totalUsers = Number(row?.all_time_users || 0);
  const communityCents = Number(row?.community_earnings_cents || 0);
  totalEarnedUsd = formatUsdFromCents(communityCents);
} catch (e) {
  console.error('Home stats error:', e);
}


  const bodyHtml = `
  <div style="
    padding:10px 40px 60px;
    width:100%;
    margin:0;
    position:relative;
  ">

    <div style="max-width:900px;margin:0 auto;text-align:center;">
      <h1 style="margin-bottom:6px;font-size:28px;font-weight:700;">
        Welcome back 👋
      </h1>

      <p style="
        max-width:750px;
        margin:auto;
        opacity:0.85;
        font-size:15px;
        line-height:1.6;
        margin-bottom:35px;
      ">
        SurveyCash allows you to earn real money by completing surveys, testing apps
        and sharing your experiences. Each completed survey increases both your personal
        balance and the platform's total earnings.
        <br><br>
        All tasks shown are verified and come from trusted partners — ensuring fair
        and honest payouts for users.
      </p>

      <div style="display:flex;gap:20px;justify-content:center;margin-top:0;">

        <div style="
          width:240px;
          padding:14px 16px;
          border-radius:10px;
          background:#111827;
          border:1px solid rgba(255,255,255,0.12);
          text-align:center;
        ">
          <div style="font-size:13px;opacity:.85;margin-bottom:4px;">
            Community Earnings
          </div>
          <div style="font-size:26px;font-weight:700;">
            $${totalEarnedUsd}
          </div>
        </div>

        <div style="
          width:240px;
          padding:14px 16px;
          border-radius:10px;
          background:#111827;
          border:1px solid rgba(255,255,255,0.12);
          text-align:center;
        ">
          <div style="font-size:13px;opacity:.85;margin-bottom:4px;">
            All Time Users
          </div>
          <div style="font-size:26px;font-weight:700;">
            ${totalUsers}
          </div>
        </div>

      </div>

      <div style="
        margin-top:45px;
        max-width:770px;
        margin-left:auto;
        margin-right:auto;
        font-size:15px;
        opacity:.85;
        line-height:1.6;
      ">
        If you ever have questions or experience any problems, our support team is here to help you. 
        You can also rate your experience with SurveyCash on Trustpilot right now and tell others what you think. 
        Your feedback helps us improve and build a better platform for all users.
      </div>

      <div style="margin-top:22px;">
        <img src="/trustpilot-logo.png"
          alt="Trustpilot"
          style="width:160px;opacity:0.9;" />
      </div>
    </div>

    <!-- HØJRE SIDE: Why SurveyCash -->
 <aside style="
  width:300px;
  position:absolute;
  right:-220px;
  top:60px;
  text-align:left;
">
  <div style="
  font-size:18px;
  font-weight:600;
  letter-spacing:0;
  text-transform:none;
  color:#ffffff;
  margin-bottom:18px;
">
  Why SurveyCash?
</div>


  <div style="display:flex;flex-direction:column;gap:20px;font-size:16px;color:#ffffff;">

    <div>
      <div style="font-weight:700;">Trusted payouts</div>
      <div style="line-height:1.45;color:#bfc3c9;">
        Withdraw safely using trusted providers such as PayPal.
        Your balance is handled securely when you’re ready.
      </div>
    </div>

    <div>
      <div style="font-weight:700;">Verified partners</div>
      <div style="line-height:1.45;color:#bfc3c9;">
        Surveys come from trusted providers — ensuring real payouts and fair rewards on every completed activity.
      </div>
    </div>

    <div>
      <div style="font-weight:700;">Global users</div>
      <div style="line-height:1.45;color:#bfc3c9;">
        SurveyCash is used worldwide, letting you earn alongside many other users daily.
      </div>
    </div>

  </div>
</aside>
  </div>
  `;

  return res.send(
    page(
      req,
      'Home — SurveyCash',
      '/',
      bodyHtml,
    ),
  );
});



// --------- Account / profil-side (ny version) ----------
app.get('/account', (req, res) => {
  const user = getUserFromReq(req);
  if (!user) return res.redirect('/');

  // sikre felter
  user.username =
    user.username || (user.email ? user.email.split('@')[0] : 'User');
  user.usernameChangedAt = user.usernameChangedAt || 0;
  user.passwordChangedAt = user.passwordChangedAt || 0;

  const displayName = String(user.username);
  const avatarInitial = displayName.trim().charAt(0).toUpperCase();

  const created = user.createdAt ? new Date(user.createdAt) : new Date();
  const joinedDate = created.toLocaleDateString('en-US', {
    day: '2-digit',
    month: 'short',
    year: 'numeric',
  });

  const totalEarnedCents =
    typeof user.totalEarnedCents === 'number'
      ? user.totalEarnedCents
      : user.balanceCents || 0;
  const lifetimeEarned = (totalEarnedCents / 100).toFixed(2);
  const completedSurveys =
    typeof user.completedSurveys === 'number' ? user.completedSurveys : 0;
  const completedOffers =
    typeof user.completedOffers === 'number' ? user.completedOffers : 0;

  // 7-dages regel for brugernavn
  const MS_PER_DAY = 24 * 60 * 60 * 1000;
  const SEVEN_DAYS_MS = 7 * MS_PER_DAY;
  const now = Date.now();
  const sinceUsernameChange = now - (user.usernameChangedAt || 0);
  const canChangeUsername =
    user.usernameChangedAt === 0 || sinceUsernameChange >= SEVEN_DAYS_MS;
  const daysLeftToChange = canChangeUsername
    ? 0
    : Math.ceil((SEVEN_DAYS_MS - sinceUsernameChange) / MS_PER_DAY);

const nameNoteText = canChangeUsername
  ? 'You can change your username every 7 days.'
  : `You cannot change your username right now. You can change it again in ${daysLeftToChange} day${daysLeftToChange !== 1 ? 's' : ''}.`;

// 7-dages regel for password (samme logik)
const sincePasswordChange = now - (user.passwordChangedAt || 0);
const canChangePassword =
  user.passwordChangedAt === 0 || sincePasswordChange >= SEVEN_DAYS_MS;
const daysLeftPassword = canChangePassword
  ? 0
  : Math.ceil((SEVEN_DAYS_MS - sincePasswordChange) / MS_PER_DAY);

const passwordNoteText = canChangePassword
  ? 'You can change your password every 7 days.'
  : `You cannot change your password right now. You can change it again in ${daysLeftPassword} day${daysLeftPassword !== 1 ? 's' : ''}.`;

  // icons
  const svgDollar = `<svg viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg" aria-hidden="true"><path d="M12 1v2m0 18v2M17 5.5c-1-1-2.5-1.5-5-1.5s-4 .5-5 1.5M7 18.5c1 1 2.5 1.5 5 1.5s4-.5 5-1.5M12 7v10" fill="currentColor"/></svg>`;
  const svgCheck = `<svg viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg" aria-hidden="true"><path d="M20.3 6.3l-11 11-5.6-5.6L6 10l4.7 4.7L18.6 5.9z" fill="currentColor"/></svg>`;
  const svgStar = `<svg viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg" aria-hidden="true"><path d="M12 2.6l2.6 5.3 5.9.9-4.3 4.2 1 5.9L12 16.9 6.8 19.8l1-5.9L3.6 9.7l5.9-.9z" fill="currentColor"/></svg>`;

const accountClientScript = `
<script>
(function () {
window.toggleAccountSection = function (kind) {
  var card = document.getElementById(kind + '-settings-card');
  if (!card) return;
  card.classList.toggle('open');

  // hvis vi lukker password-menuen → fjern fejl/klar input
  if (kind === 'password' && !card.classList.contains('open')) {
    clearPwError(); // sørger for at "Wrong password" bliver væk
  }
};


  var pwErrorEl = document.getElementById('acct-password-error');

  function showPwError(msg) {
    if (!pwErrorEl) return;
    pwErrorEl.textContent = msg;
    pwErrorEl.style.display = 'block';
  }

  function clearPwError() {
    if (!pwErrorEl) return;
    pwErrorEl.textContent = '';
    pwErrorEl.style.display = 'none';
  }

  // frontend password-validering
var pwForm = document.getElementById('form-change-password');
if (pwForm) {
  pwForm.addEventListener('submit', function (e) {
    clearPwError();

    var oldp = document.getElementById('old-password').value || '';
    var newp = document.getElementById('new-password').value || '';
    var newp2 = document.getElementById('new-password-2').value || '';

    // UDEN old password → stop her
    if (!oldp) {
      e.preventDefault();
      showPwError('Please enter your current password.');
      return;
    }

    // UDEN gyldigt nyt password → stop her
    if (newp.length < 6) {
      e.preventDefault();
      showPwError('New password must be at least 6 characters.');
      return;
    }

    // ⚠️ Vi TJEKKER IKKE MISMATCH HER!
    // Mismatch håndteres på serveren → der kan vi prioritere "Wrong password"

  });
}

  // læs evt. server-fejl fra URL (?pwError=...)
  var params = new URLSearchParams(window.location.search);
  var pwErr = params.get('pwError');
  if (pwErr) {
    var msg = '';
    if (pwErr === 'badpass') {
      msg = 'Wrong password.';
    } else if (pwErr === 'mismatch') {
      msg = 'The new passwords do not match.';
    } else if (pwErr === 'short') {
      msg = 'New password must be at least 6 characters.';
    } else if (pwErr === 'cooldown') {
      msg = 'You can only change your password once every 7 days.';
    } else if (pwErr === 'missingold') {
      msg = 'Please enter your current password.';
    } else if (pwErr === 'unknown') {
      msg = 'Something went wrong. Please try again.';
    }

    if (msg) {
      // sørg for at password-kortet er åbent
      var pwCard = document.getElementById('password-settings-card');
      if (pwCard) pwCard.classList.add('open');
      showPwError(msg);
    }

    // fjern pwError fra URL så den ikke bliver hængende ved refresh
    window.history.replaceState(null, '', window.location.pathname);
  }
})();
</script>
`;


  const extraCss = `
<style>
  /* LIFT WHOLE ACCOUNT PAGE A BIT UP */
  main, .page-main, .page-inner {
    margin-top: -20px !important; /* move everything up a bit */
  }

  h1 {
    margin-top: 8px; /* title closer to navbar */
  }

  .account-wrap {
    margin-top: 4px; /* profile card closer to "Account" */
  }

  /* ------------ SETTINGS CARDS (under profile) ------------ */
  .account-settings {
    max-width: 1100px;
    margin: 28px auto 20px; /* some space above, less at bottom so less scrolling */
    display: flex;
    flex-direction: column;
    gap: 14px;
  }

  .account-settings-card {
    background:
      linear-gradient(
        145deg,
        rgba(35, 43, 61, 0.55) 0%,
        rgba(20, 26, 40, 0.60) 60%,
        rgba(12, 16, 26, 0.70) 100%
      ),
      radial-gradient(
        circle at 0% 0%,
        rgba(251, 191, 36, 0.06),
        transparent 55%
      );
    border-radius: 16px;
    border: 1px solid rgba(255, 255, 255, 0.04);
    box-shadow: 0 18px 50px rgba(0,0,0,0.60);
    padding: 18px 24px;
    transition: box-shadow 0.2s ease, transform 0.15s ease, background 0.2s ease;
  }

  .account-settings-card:hover {
    background:
      linear-gradient(
        145deg,
        rgba(45, 55, 78, 0.65) 0%,
        rgba(25, 32, 48, 0.68) 60%,
        rgba(15, 20, 32, 0.75) 100%
      ),
      radial-gradient(
        circle at 0% 0%,
        rgba(251, 191, 36, 0.08),
        transparent 55%
      );
    transform: translateY(-2px);
    box-shadow: 0 22px 60px rgba(0,0,0,0.70);
  }

  .account-settings-row {
    display: flex;
    align-items: center;
    gap: 18px;
  }

  .settings-label {
    width: 110px;
    font-size: 13px;
    color: #9ca3af;
  }

  .settings-main {
    flex: 1;
    display: flex;
    flex-direction: column;
    gap: 2px;
  }

  .settings-value {
    font-size: 15px;
    font-weight: 600;
    color: #e5e7eb;
  }

  .settings-note {
    font-size: 12px;
    color: #9ca3af;
  }

  .settings-error {
    font-size: 12px;
    color: #fca5a5;      /* rødlig tekst */
    margin-top: 4px;
  }


  .settings-right {
    display: flex;
    align-items: center;
    gap: 12px;
  }

  .settings-right span {
    font-size: 12px;
    color: #9ca3af;
  }

.settings-btn {
    background: none !important;
    border: none !important;
    box-shadow: none !important;
    color: #ffffff !important;
    font-weight: 700;
    font-size: 14px;
    cursor: pointer;
    padding: 0; /* ingen knap-padding → ren tekst */
}
.settings-btn:hover {
    text-decoration: underline; /* valgfrit når man hover */
}

  .settings-btn:disabled {
    opacity: 0.45;
    cursor: not-allowed;
    box-shadow: 0 0 0 1px rgba(148,163,184,0.4);
    background: #4b5563;
    color: #e5e7eb;
    border-color: #4b5563;
  }

  .settings-form {
    display: none;
    margin-top: 12px;
    padding-top: 12px;
    border-top: 1px solid #1f2937;
    flex-wrap: wrap;
    gap: 10px;
  }

  .account-settings-card.open .settings-form {
    display: flex;
  }

 .settings-form-group {
    min-width: 220px;
    flex: 1;
    display: flex;
    flex-direction: column;
    gap: 4px;
    margin-right: 38px; /* større spacing */
}

.settings-form-group:last-of-type {
    margin-right: 0;
}

  .settings-form-label {
    font-size: 12px;
    color: #9ca3af;
  }

 .settings-form .field-input {
    width: 260px; /* kortere og pænere */
    padding: 8px 12px;
    border-radius: 6px;
    border: 1px solid #1f2937; 
    background: #2c3443;
    color: #e5e7eb;
    font-size: 14px;
    outline: none;
}

.settings-form .field-input:hover {
    border-color: #374151;
}

.settings-form .field-input:focus {
    border-color: #facc15; 
    background: #323a4c;
}

 .settings-form-actions {
    flex: 1;                    /* skub mod højre */
    display: flex;
    align-items: center;        /* vertikal midt */
    justify-content: flex-end;  /* helt ude til højre */
    margin-top: 0;
}

  @media (max-width: 900px) {
    .account-settings-row {
      flex-direction: column;
      align-items: flex-start;
    }
    .settings-label {
      width: auto;
    }
    .settings-right {
      width: 100%;
      justify-content: space-between;
    }
  }
</style>
  `;

  const accountHtml = `
    <h1>Account</h1>

    <!-- TOP: profile + stats -->
    <section class="account-wrap">
      <div class="account-main-card">
        <div class="account-avatar-big">
          <span>${avatarInitial}</span>
        </div>
        <div class="account-main-info">
          <div class="account-main-name">${escapeHtml(displayName)}</div>
          <div class="account-main-joined">Joined ${escapeHtml(joinedDate)}</div>
          <div class="account-main-email">${escapeHtml(user.email || '')}</div>
        </div>
      </div>

      <div class="account-stat-grid">
        <div class="account-stat-card">
          <div class="account-stat-label-row">
            <div class="account-stat-icon">${svgDollar}</div>
            <span>Total earnings</span>
          </div>
          <div class="account-stat-value">$ ${lifetimeEarned}</div>
        </div>

        <div class="account-stat-card">
          <div class="account-stat-label-row">
            <div class="account-stat-icon account-stat-icon-alt">${svgCheck}</div>
            <span>Completed surveys</span>
          </div>
          <div class="account-stat-value">${completedSurveys}</div>
        </div>

        <div class="account-stat-card">
          <div class="account-stat-label-row">
            <div class="account-stat-icon account-stat-icon-alt">${svgStar}</div>
            <span>Completed offers</span>
          </div>
          <div class="account-stat-value">${completedOffers}</div>
        </div>
      </div>
    </section>

    <!-- BOTTOM: three separate settings cards -->
    <section class="account-settings">

      <!-- Name card -->
      <div class="account-settings-card" id="name-settings-card">
        <div class="account-settings-row">
          <div class="settings-label">Name</div>
          <div class="settings-main">
            <div class="settings-value">${escapeHtml(displayName)}</div>
            <div class="settings-note" id="acct-username-note">${escapeHtml(nameNoteText)}</div>
          </div>
          <div class="settings-right">
            <button
              class="settings-btn"
              type="button"
              id="acct-username-btn"
              ${canChangeUsername ? '' : 'disabled'}
              onclick="toggleAccountSection('name')"
            >
              Change name
            </button>
          </div>
        </div>

        <form
          id="form-change-username"
          class="settings-form"
          action="/account/change-username"
          method="POST"
        >
          <div class="settings-form-group">
            <label class="settings-form-label" for="acct-username-input">New username</label>
            <input
              id="acct-username-input"
              name="newUsername"
              type="text"
              minlength="2"
              maxlength="24"
              placeholder="New username"
              class="field-input"
              value="${escapeHtml(displayName)}"
            />
          </div>
          <div class="settings-form-actions">
            <button class="settings-btn" type="submit">Save name</button>
          </div>
        </form>
      </div>

      <!-- Password card -->
      <div class="account-settings-card" id="password-settings-card">
        <div class="account-settings-row">
          <div class="settings-label">Password</div>
          <div class="settings-main">
  <div class="settings-value">********</div>
  <div class="settings-note">${escapeHtml(passwordNoteText)}</div>
  <div class="settings-error" id="acct-password-error" style="display:none;"></div>
</div>
<div class="settings-right">
  <button
    class="settings-btn"
    type="button"
    id="acct-password-btn"
    ${canChangePassword ? '' : 'disabled'}
    onclick="toggleAccountSection('password')"
  >
    Change password
  </button>
</div>

        </div>

        <form
          id="form-change-password"
          class="settings-form"
          action="/account/change-password"
          method="POST"
        >
          <div class="settings-form-group">
            <label class="settings-form-label" for="old-password">Current password</label>
            <input
              id="old-password"
              name="oldPassword"
              type="password"
              class="field-input"
              placeholder="Current password"
            />
          </div>
          <div class="settings-form-group">
            <label class="settings-form-label" for="new-password">
              New password (min. 6 characters)
            </label>
            <input
              id="new-password"
              name="newPassword"
              type="password"
              class="field-input"
              placeholder="New password"
            />
          </div>
          <div class="settings-form-group">
            <label class="settings-form-label" for="new-password-2">Repeat new password</label>
            <input
              id="new-password-2"
              name="newPassword2"
              type="password"
              class="field-input"
              placeholder="Repeat new password"
            />
          </div>
          <div class="settings-form-actions">
            <button class="settings-btn" type="submit">Save password</button>
          </div>
        </form>
      </div>

      <!-- Email card (info only) -->
      <div class="account-settings-card" id="email-settings-card">
        <div class="account-settings-row">
          <div class="settings-label">Email</div>
          <div class="settings-main">
            <div class="settings-value">${escapeHtml(user.email || '')}</div>
            <div class="settings-note">Registered email address.</div>
          </div>
        </div>
      </div>

    </section>

    ${accountClientScript}
  `;

  res.send(
    page(
      req,
      'Account — SurveyCash',
      '/account',
      extraCss + accountHtml
    )
  );
});



// ---------- Privacy Policy ----------
app.get('/privacy', (req, res) => {
  res.send(`
    <html>
      <head>
        <title>Privacy Policy - SurveyCash</title>
        <style>
          body { font-family: Arial; padding: 40px; background:#0f172a; color:#e5e7eb; }
          h1 { color:#facc15; }
        </style>
      </head>
      <body>
        <h1>Privacy Policy</h1>

        <p>SurveyCash respects your privacy.</p>

        <p>
          We may collect basic information such as IP address, device data,
          and usage data to prevent fraud and ensure proper reward attribution.
        </p>

        <p>
          SurveyCash uses third-party survey and offer providers.
          These partners may collect additional data according to their own privacy policies.
        </p>

        <p>We do not sell personal data.</p>

        <p>By using SurveyCash, you agree to this Privacy Policy.</p>

        <p>Contact: surveycashweb@gmail.com</p>
      </body>
    </html>
  `);
});

// ---------- Terms of Service ----------
app.get('/terms', (req, res) => {
  res.send(`
    <html>
      <head>
        <title>Terms of Service - SurveyCash</title>
        <style>
          body { font-family: Arial; padding: 40px; background:#0f172a; color:#e5e7eb; }
          h1 { color:#facc15; }
        </style>
      </head>
      <body>
        <h1>Terms of Service</h1>

        <p>By using SurveyCash, you agree to use the platform fairly and honestly.</p>

        <p>
          Rewards are granted only after confirmation from our partners.
        </p>

        <p>
          Fraud, abuse, or manipulation may result in account suspension
          and loss of rewards.
        </p>

        <p>
          SurveyCash is not responsible for third-party survey availability
          or disqualifications.
        </p>

        <p>Terms may be updated at any time.</p>

        <p>Contact: surveycashweb@gmail.com</p>
      </body>
    </html>
  `);
});

// ---------- Email verified landing (auto-login) ----------
app.get('/verified', (req, res) => {
  res.send(
    page(
      req,
      'Email verified — SurveyCash',
      '/',
      `
      <div style="max-width:720px;margin:40px auto;text-align:center;">
        <h1>Email verified ✅</h1>
        <p class="muted" id="status" style="opacity:.85;">Logging you in…</p>
        <p class="muted" id="hint" style="display:none;opacity:.85;">If nothing happens, go to the homepage and log in.</p>
        <button type="button" class="btn btn-signup" id="goHome" style="display:none;" onclick="location.href='/'">
          Go to Home
        </button>
      </div>

      <script src="https://cdn.jsdelivr.net/npm/@supabase/supabase-js@2"></script>
      <script>
        (async function () {
          const statusEl = document.getElementById('status');
          const hintEl = document.getElementById('hint');
          const btnEl = document.getElementById('goHome');

          try {
            const supabase = window.supabase.createClient(
              ${JSON.stringify(process.env.SUPABASE_URL || '')},
              ${JSON.stringify(process.env.SUPABASE_ANON_KEY || '')}
            );

            const url = window.location.href;

            if (url.includes('code=')) {
              await supabase.auth.exchangeCodeForSession(url);
            } else if (supabase.auth.getSessionFromUrl) {
              await supabase.auth.getSessionFromUrl({ storeSession: true });
            }

            const { data } = await supabase.auth.getSession();
            const access_token = data?.session?.access_token;
            if (!access_token) throw new Error('No session token after verify');

            const r = await fetch('/auth/finish', {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              credentials: 'same-origin',
              body: JSON.stringify({ access_token })
            });

            const j = await r.json().catch(() => null);
            if (!r.ok || !j?.ok) throw new Error('Server finish failed');

           statusEl.textContent = 'Done! Redirecting…';
localStorage.setItem('surveycash:login', String(Date.now())); // 👈 HER
location.href = '/';
          } catch (e) {
            console.error(e);
            statusEl.textContent = 'Verified, but could not auto-log in.';
            hintEl.style.display = 'block';
            btnEl.style.display = 'inline-flex';
          }
        })();
      </script>
      `
    )
  );
});



app.get('/surveys', (req, res) => {
  if (!isLoggedIn(req)) return res.redirect('/');

  res.send(
    page(
      req,
      'Surveys — SurveyCash',
      '/surveys',
      `
      <h1>Surveys</h1>
      <p>Choose a survey partner to start earning.</p>

      <!-- 5 kolonner -->
      <div style="
        margin-top:16px;
        display:grid;
        grid-template-columns:repeat(5, minmax(0, 1fr));
        gap:14px;
      ">

        <!-- CPX Research -->
        <a href="/surveys/cpx"
           style="
             border:1px solid rgba(255,255,255,.08);
             border-radius:16px;
             padding:18px;
             min-height:100px;

             display:flex;
             align-items:center;
             justify-content:center;
             text-decoration:none;
             overflow:hidden;

             background-color: rgba(15,23,42,.55);
             background-image: linear-gradient(
               to top,
               rgba(34,197,94,.28) 0%,
               rgba(34,197,94,.14) 18%,
               rgba(15,23,42,0) 55%
             );
             background-repeat:no-repeat;
             background-size:100% 100%;
             background-position:0 0;

             box-shadow:
               inset 0 1px 0 rgba(15,23,42,.90),
               inset 0 -1px 0 rgba(34,197,94,.18);
           ">
          <img
            src="/partners/cpx.png"
            alt="CPX Research"
            style="height:32px;width:auto;display:block;"
          />
        </a>

        <!-- Placeholder -->
        <div style="border:1px solid rgba(255,255,255,.08);border-radius:16px;padding:14px;background:rgba(15,23,42,.35);opacity:.75;">
          <div style="font-weight:700;font-size:15px;">More partners</div>
          <div style="opacity:.85;margin-top:6px;font-size:13px;">Coming soon…</div>
          <div style="margin-top:10px;">
            <span class="btn-ghost" style="pointer-events:none;opacity:.6;">Soon</span>
          </div>
        </div>

        <div style="border:1px solid rgba(255,255,255,.08);border-radius:16px;padding:14px;background:rgba(15,23,42,.35);opacity:.75;">
          <div style="font-weight:700;font-size:15px;">More partners</div>
          <div style="opacity:.85;margin-top:6px;font-size:13px;">Coming soon…</div>
          <div style="margin-top:10px;">
            <span class="btn-ghost" style="pointer-events:none;opacity:.6;">Soon</span>
          </div>
        </div>

        <div style="border:1px solid rgba(255,255,255,.08);border-radius:16px;padding:14px;background:rgba(15,23,42,.35);opacity:.75;">
          <div style="font-weight:700;font-size:15px;">More partners</div>
          <div style="opacity:.85;margin-top:6px;font-size:13px;">Coming soon…</div>
          <div style="margin-top:10px;">
            <span class="btn-ghost" style="pointer-events:none;opacity:.6;">Soon</span>
          </div>
        </div>

        <div style="border:1px solid rgba(255,255,255,.08);border-radius:16px;padding:14px;background:rgba(15,23,42,.35);opacity:.75;">
          <div style="font-weight:700;font-size:15px;">More partners</div>
          <div style="opacity:.85;margin-top:6px;font-size:13px;">Coming soon…</div>
          <div style="margin-top:10px;">
            <span class="btn-ghost" style="pointer-events:none;opacity:.6;">Soon</span>
          </div>
        </div>

      </div>
      `
    )
  );
});



app.get('/surveys/cpx', (req, res) => {
  if (!isLoggedIn(req)) return res.redirect('/');

  const user = getUserFromReq(req);
  if (!user) return res.redirect('/');

  const extUserId = String(user.id || user.email);

  const secureHash = CPX_APP_SECURE_HASH
    ? md5(`${extUserId}-${CPX_APP_SECURE_HASH}`)
    : '';

  const qs = new URLSearchParams({
    app_id: CPX_APP_ID,
    ext_user_id: extUserId,
  });

  if (secureHash) qs.set('secure_hash', secureHash);
  if (user.username) qs.set('username', String(user.username));
  if (user.email) qs.set('email', String(user.email));

  const iframeUrl = `https://offers.cpx-research.com/index.php?${qs.toString()}`;

  res.send(
    page(
      req,
      'CPX Surveys — SurveyCash',
      '/surveys',
      `
<style>
  /* Ingen scroll */
  html, body {
    margin: 0;
    padding: 0;
    height: 100%;
    overflow: hidden !important;
  }

  /* Fjern page()-containers */
  main, .container, .wrap, .content, .page, .inner {
    margin: 0 !important;
    padding: 0 !important;
    max-width: none !important;
    width: 100% !important;
  }

  /* Fullscreen CPX med luft top + bund */
  .cpx-fullscreen {
    position: fixed;
    top: calc(var(--header-height, 64px) + 16px);   /* luft under header */
    left: 16px;                                     /* luft i siderne */
    right: 16px;
    bottom: 16px;                                   /* 👈 LUFT I BUND */
    background: #0b1020;
    border-radius: 16px;                            /* matcher dit design */
    overflow: hidden;
  }

  .cpx-fullscreen iframe {
    width: 100%;
    height: 100%;
    border: 0;
    display: block;
    background: #fff;
  }
</style>

<div class="cpx-fullscreen">
  <iframe
    src="${iframeUrl}"
    allow="clipboard-read; clipboard-write"
  ></iframe>
</div>
      `
    )
  );
});



app.get('/games', (req, res) => {
  if (!isLoggedIn(req)) return res.redirect('/');

  res.send(
    page(
      req,
      'Games — SurveyCash',
      '/games',
      `
      <div class="wrap">
        <h1>Games</h1>

        <div class="card">
          <h2 style="margin:0 0 8px;">Wannads Offerwall</h2>
          <div class="muted">Play & complete offers to earn coins.</div>
          <div style="margin-top:14px;">
            <a class="btn" href="/games/wannads">Open Offerwall</a>
          </div>
        </div>
      </div>

      <style>
        .wrap{
          max-width:980px;
          margin:40px auto;
          padding:0 16px;
        }

        .card{
          background:rgba(255,255,255,.04);
          border:1px solid rgba(255,255,255,.08);
          border-radius:18px;
          padding:18px;
        }

        .btn{
          display:inline-block;
          padding:12px 18px;
          border-radius:14px;
          background:#fbbf24;
          color:#111827;
          font-weight:800;
          text-decoration:none;
        }

        .muted{
          color:#94a3b8;
          margin-top:6px;
        }
      </style>
      `
    )
  );
});



// ===== WANNADS GAME OFFERS =====
app.get('/games/wannads', (req, res) => {
  if (!isLoggedIn(req)) return res.redirect('/');

  const user = getUserFromReq(req);
  if (!user) return res.redirect('/');

  const userId = String(user.id || user.email || '').trim();
  if (!userId) return res.redirect('/');

  const wannadsUrl =
    `https://earn.wannads.com/wall?apiKey=${process.env.WANNADS_API_KEY}&userId=${encodeURIComponent(userId)}`;

  res.setHeader(
    "Content-Security-Policy",
    [
      "default-src 'self' https: data:;",
      "script-src 'self' 'unsafe-inline' 'unsafe-eval' https:;",
      "style-src 'self' 'unsafe-inline' https:;",
      "img-src 'self' https: data:;",
      "connect-src 'self' https:;",
      "frame-src https://earn.wannads.com https:;",
    ].join(" ")
  );

  res.send(`<!doctype html>
<html>
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
  <title>Wannads Offerwall</title>
  <style>
    body{ margin:0; background:#0f172a; }
    .top{
      position:fixed; top:0; left:0; right:0; height:56px;
      display:flex; align-items:center; gap:12px;
      padding:0 14px; background:rgba(15,23,42,.92);
      border-bottom:1px solid rgba(255,255,255,.08);
      color:#e5e7eb; font-family:system-ui; z-index:10;
      backdrop-filter: blur(8px);
    }
    .back{ color:#fbbf24; text-decoration:none; font-weight:800; }
    iframe{ position:fixed; top:56px; left:0; width:100%; height:calc(100vh - 56px); border:0; }
  </style>
</head>
<body>
  <div class="top">
    <a class="back" href="/games">← Back</a>
    <div style="font-weight:800">Wannads Offerwall</div>
  </div>

  <iframe
    src="${wannadsUrl}"
    scrolling="yes"
    allow="clipboard-write; fullscreen"
  ></iframe>
</body>
</html>`);
});




// --- CPX anti-duplicate log (trans_id + type) ---
async function findProfileByUserIdOrEmailSupabase(userIdOrEmail) {
  const key = String(userIdOrEmail || '').trim().toLowerCase();
  if (!key) return null;

  // 1) prøv som user_id (CPX ext_user_id)
  let { data, error } = await supabaseAdmin
    .from('profiles')
    .select('user_id, email, username, balance_cents, total_earned_cents, completed_surveys, completed_offers')
    .eq('user_id', key)
    .maybeSingle();

  if (!error && data) return data;

  // 2) fallback: prøv som email
  ({ data, error } = await supabaseAdmin
    .from('profiles')
    .select('user_id, email, username, balance_cents, total_earned_cents, completed_surveys, completed_offers')
    .eq('email', key)
    .maybeSingle());

  if (!error && data) return data;

  return null;
}



app.get('/cpx/postback', async (req, res) => {
  try {
 const token = String(req.query.token || '');
    if (token !== process.env.CPX_POSTBACK_TOKEN) {
      return res.status(200).send('ok'); // svar altid ok så angribere ikke kan se noget
    }
    const q = req.query || {};

    const statusRaw = String(q.status || q.state || '').toLowerCase();
    const transId = String(q.trans_id || q.transaction_id || q.sid || q.subid || '').trim();
    const userId = String(q.user_id || q.ext_user_id || q.uid || '').trim();
    const type = String(q.type || 'complete').toLowerCase().trim();

    const amountRaw = q.amount_local ?? q.amount ?? q.reward ?? q.payout ?? q.value ?? '0';
    const amount = Number(String(amountRaw).replace(',', '.')) || 0;

    if (!transId || !userId) return res.status(200).send('ok');

    const isCredit =
      statusRaw === '1' || statusRaw === 'approved' || statusRaw === 'completed' || statusRaw === 'ok';

    const isReversal =
      statusRaw === '2' || statusRaw === 'reversed' || statusRaw === 'chargeback' ||
      statusRaw === 'canceled' || statusRaw === 'cancelled';

    const profile = await findProfileByUserIdOrEmailSupabase(userId);
    if (!profile) return res.status(200).send('ok');

    const cents = Math.round(Math.max(0, amount) * 100);

    const currentBalance = Number(profile.balance_cents || 0);
    const currentTotal   = Number(profile.total_earned_cents || 0);
    const currentSurveys = Number(profile.completed_surveys || 0);

    if (isCredit) {
      // insert hvis ikke allerede (UNIQUE trans_id+type stopper dupes)
      const { error: insErr } = await supabaseAdmin
        .from('cpx_transactions')
        .insert({
          user_id: profile.user_id,
          trans_id: transId,
          type,
          cents,
          status: 1,
        });

      // hvis duplicate → ignorer
      if (insErr && insErr.code !== '23505') {
        console.error('cpx_transactions insert error:', insErr);
        return res.status(200).send('ok');
      }

      // kun credit hvis insert lykkedes (ikke duplicate)
      if (!insErr && cents > 0) {
        const next = {
          balance_cents: currentBalance + cents,
          total_earned_cents: currentTotal + cents,
        };

        if (type.includes('complete')) {
          next.completed_surveys = currentSurveys + 1;
        }

        const { error: upErr } = await supabaseAdmin
          .from('profiles')
          .update(next)
          .eq('user_id', profile.user_id);

        if (upErr) console.error('CPX credit update error:', upErr);
      }

      return res.status(200).send('ok');
    }

    if (isReversal) {
      // find transaction, og kun reverse 1 gang
      const { data: tx } = await supabaseAdmin
        .from('cpx_transactions')
        .select('id, cents, status')
        .eq('trans_id', transId)
        .eq('type', type)
        .maybeSingle();

      if (tx && Number(tx.status) === 1) {
        await supabaseAdmin
          .from('cpx_transactions')
          .update({ status: 2 })
          .eq('id', tx.id);

        const revCents = Number(tx.cents || 0);
        if (revCents > 0) {
          const newBalance = Math.max(0, currentBalance - revCents);

          const { error: upErr } = await supabaseAdmin
            .from('profiles')
            .update({ balance_cents: newBalance })
            .eq('user_id', profile.user_id);

          if (upErr) console.error('CPX reversal update error:', upErr);
        }
      }

      return res.status(200).send('ok');
    }

    return res.status(200).send('ok');
  } catch (e) {
    console.error('CPX postback handler error:', e);
    return res.status(200).send('ok');
  }
});



// ===== WANNADS POSTBACK =====
app.get('/postback/wannads', async (req, res) => {
  try {
    console.log('Wannads postback:', req.query);

    const userId = req.query.userId;
    const amount = Number(req.query.amount || req.query.payout || 0);
    const status = req.query.status || 'completed';

    if (!userId) {
      console.log('No userId in postback');
      return res.status(200).send('Missing userId');
    }

    if (amount <= 0) {
      console.log('Zero payout, skipping');
      return res.status(200).send('No reward');
    }

    // Hent bruger
    const { data: profile, error: profErr } = await supabaseAdmin
      .from('profiles')
      .select('balance_cents')
      .eq('user_id', userId)
      .single();

    if (profErr || !profile) {
      console.log('User not found:', userId);
      return res.status(200).send('User not found');
    }

    const newBalance = Number(profile.balance_cents || 0) + Math.round(amount * 100);

    // Opdater balance
    await supabaseAdmin
      .from('profiles')
      .update({ balance_cents: newBalance })
      .eq('user_id', userId);

    console.log('Credited user:', userId, 'amount:', amount);

    return res.status(200).send('OK');
  } catch (err) {
    console.error('Wannads postback error:', err);
    return res.status(200).send('Error handled');
  }
});




app.get('/cashout', async (req, res) => {
  if (!isLoggedIn(req)) return res.redirect('/');

  const user = req.user;
  if (!user?.id) return res.redirect('/');

  const ok = req.query.ok === '1';
  const paid = req.query.paid === '1';
  const err = String(req.query.err || '');
  const wIdFromQuery = Number(req.query.w || 0);

  // 1) Hent profil (balance + pending)
  let profile;
  try {
    profile = await getProfileByUserId(user.id);
  } catch (e) {
    console.error('getProfileByUserId error:', e);
    return res.redirect('/');
  }

  const balanceCents = Number(profile.balance_cents || 0);
  const pendingCents = Number(profile.pending_cents || 0);

  // 2) Tjek om der allerede er en aktiv cashout (pending/processing)
  let hasOpenWithdrawal = false;
  let openWithdrawalId = 0;

  try {
    const { data, error } = await supabaseAdmin
      .from('withdrawals')
      .select('id,status')
      .eq('user_id', user.id)
      .in('status', ['pending', 'processing'])
      .order('id', { ascending: false })
      .limit(1);

    if (!error && Array.isArray(data) && data.length > 0) {
      hasOpenWithdrawal = true;
      openWithdrawalId = Number(data[0].id || 0);
    }
  } catch (e) {
    console.error('open withdrawal check (GET /cashout) failed:', e);
  }

  // 3) Find hvilket withdrawal-id vi skal auto-checke
  const wId = wIdFromQuery || openWithdrawalId;

  const autoCheckScript = wId
    ? `
    <script>
    (async function () {
      const id = ${wId};
      const maxTries = 20;
      const delayMs = 2000;

      for (let i = 0; i < maxTries; i++) {
        try {
          const r = await fetch('/withdrawals/' + id + '/check', { method: 'POST' });
          const data = await r.json();

          if (data && data.status === 'paid') {
            window.location.href = '/cashout?paid=1';
            return;
          }
          if (data && data.status === 'failed') {
            window.location.href = '/cashout?err=server';
            return;
          }
        } catch (e) {}

        await new Promise(r => setTimeout(r, delayMs));
      }
    })();
    </script>
    `
    : '';

  // 4) Beskeder
  let msg = '';
  if (paid) {
    msg = `<div class="notice success">Cash out status: <b>PAID</b> ✅</div>`;
  } else if (err === 'open') {
    msg = `<div class="notice error">You already have a cashout in progress. Please wait until it is paid.</div>`;
  } else if (ok || wId || hasOpenWithdrawal) {
    msg = `<div class="notice success">Cash out status: <b>PROCESSING</b>…</div>`;
  } else if (err) {
    msg = `<div class="notice error">Cash out failed.</div>`;
  }

  // PayPal logo path (public/img/paypal.png)
  const paypalImg = '/img/paypal.png';


// progress bar data til PayPal card
const minCashoutCents = CASHOUT_ALLOWED_CENTS[0] || 500;

const progressPct = Math.max(
  0,
  Math.min(100, (balanceCents / minCashoutCents) * 100)
);

const progressRightText =
  '$' + formatUsdFromCents(balanceCents) + ' / $' + (minCashoutCents/100).toFixed(0);


  // Amount cards HTML (bygges udenfor bodyHtml)
  const amountCardsHtml = CASHOUT_ALLOWED_CENTS.map((cents) => {
    const usd = (cents / 100).toFixed(2);
    const can = !hasOpenWithdrawal && balanceCents >= cents;
    const needUsd = ((cents - balanceCents) / 100).toFixed(2);

    return `
      <button
        type="button"
        class="amount-card ${can ? '' : 'disabled'}"
        data-cents="${cents}"
        data-usd="${usd}"
        ${can ? '' : 'disabled'}
      >
        <div class="amt">$${usd}</div>

        <div class="brand">
          <img src="${paypalImg}" alt="PayPal" />
        </div>

        <div class="bar"><div class="fill" style="width:0%"></div></div>
        <div class="need">${can ? 'Available' : ('Need $' + needUsd)}</div>
      </button>
    `;
  }).join('');

  return res.send(
    layout({
      title: 'Cash Out — SurveyCash',
      active: '/cashout',
      loggedIn: user,
      bodyHtml: `
        <style>
          /* ===== Page ===== */
          .cashout-page{ max-width:1100px; margin:40px auto 0; padding:0 18px 60px; }
          .cashout-head h1{ font-size:40px; margin:0 0 8px; }
          .cashout-head p{ margin:0; color:#b8c4d6; }

          .cashout-section{ margin-top:22px; }
          .section-title{ display:flex; align-items:center; gap:12px; margin:0 0 14px; }
          .section-title h2{ margin:0; font-size:18px; }
          .pill{
            font-size:12px; padding:6px 10px; border-radius:999px;
            background:rgba(34,197,94,.12); color:#22c55e; border:1px solid rgba(34,197,94,.18);
          }

          .balance-row{
            margin-top:14px;
            max-width:820px;
            display:flex; gap:16px; flex-wrap:wrap;
            color:#cbd5e1;
          }

/* ===== Freecash-style payout methods (smaller + rectangle cards) ===== */
.methods-grid{
  margin-top:12px;
  display:grid;
  grid-template-columns:repeat(3, 220px);
  justify-content:flex-start;
  gap:18px;
}

/* Card */
.method-card{
  width:220px;
  aspect-ratio:3.5 / 3;
  cursor:pointer;

  border-radius:22px;
  padding:14px 16px;

  background:linear-gradient(180deg, rgba(255,255,255,.045), rgba(255,255,255,.02));
  border:1px solid rgba(255,255,255,.08);
  box-shadow:0 18px 60px rgba(0,0,0,.28);

  color:#fff;
  transition:transform .12s ease, border-color .12s ease, box-shadow .12s ease;

  display:flex;
  flex-direction:column;
  justify-content:flex-start;
  align-items:center;
  text-align:center;

  position:relative;
  overflow:hidden;
}

.method-card:hover{
  transform:translateY(-2px);
  border-color:rgba(255,255,255,.16);
}

/* PayPal hover grøn */
.method-card.paypal:hover{
  border-color:rgba(34,197,94,.85);
  box-shadow:0 18px 60px rgba(34,197,94,.12), 0 18px 60px rgba(0,0,0,.28);
}

/* Placeholder */
.method-card.placeholder{
  opacity:.6;
  cursor:not-allowed;
}
.method-card.placeholder:hover{
  transform:none;
}

/* 🔥 PayPal tekst større + højere */
.method-title{
  font-weight:900;
  font-size:18px;
  margin-bottom:6px;
  margin-top:-4px;
}

/* Default logo (coming soon cards) */
.method-logo-tile{
  height:90px;
  display:flex;
  align-items:center;
  justify-content:center;
}

.method-logo-tile img{
  max-width:100px;
  max-height:60px;
}

/* 🔥 PayPal logo med lys baggrund igen */
.method-card.paypal .method-logo-tile{
  background:#f1f5f9;
  border-radius:12px;
  padding:14px 18px;
  height:auto;
  width:100%;
  max-width:200px;
  margin:4px auto 12px;
  box-shadow:0 10px 22px rgba(0,0,0,.12);
}

/* PayPal logo størrelse */
.method-card.paypal .method-logo-tile img{
  max-width:190px;
  max-height:85px;
  width:auto;
  height:auto;
  display:block;
}

/* Coming soon */
.soon-wrap{
  margin-top:8px;
}

.soon-pill{
  display:inline-block;
  font-size:12px;
  padding:7px 12px;
  border-radius:999px;
  background:rgba(255,255,255,.05);
  border:1px solid rgba(255,255,255,.10);
  color:#cbd5e1;
}

/* skjul gamle progress */
.method-bar,
.method-foot{
  display:none !important;
}

/* Responsive */
@media (max-width: 900px){
  .methods-grid{
    grid-template-columns:repeat(2, 220px);
  }
}
@media (max-width: 640px){
  .methods-grid{
    grid-template-columns:1fr;
  }
}
          /* ===== Modal ===== */
          .co-backdrop{
            position:fixed; inset:0;
            background:rgba(0,0,0,.55);
            display:none; align-items:center; justify-content:center;
            z-index:9999;
            padding:16px;
          }
          .co-backdrop.open{ display:flex; }

.co-backdrop.open{ display:flex; }

/* ===== Compact Freecash-style modal ===== */
.co-modal{
  width:min(640px, 100%);
  background:#0b1220;
  border:1px solid rgba(255,255,255,.08);
  border-radius:18px;
  padding:14px 14px 10px;   /* mindre bund-padding */
  box-shadow:0 40px 140px rgba(0,0,0,.65);
  position:relative;
}

.co-close{
  position:absolute; top:10px; right:10px;
  width:36px; height:36px;
  border-radius:999px;
  background:rgba(255,255,255,.06);
  border:1px solid rgba(255,255,255,.10);
  color:#fff; cursor:pointer;
}

.co-header{
  display:flex; gap:10px; align-items:center;
  padding:4px 4px 8px;   /* mindre luft */
}

.co-icon{
  width:32px; height:32px;
  display:flex; align-items:center; justify-content:center;
}
.co-icon img{ width:32px; height:auto; display:block; }

.co-title{ font-weight:900; font-size:17px; }

.co-divider{
  height:1px;
  background:rgba(255,255,255,.08);
  margin:8px 0;   /* mindre spacing */
}

.co-block-title{
  font-weight:800;
  margin:2px 0 8px;
}

/* ===== Amount grid tighter ===== */
.amount-grid{
  display:grid;
  grid-template-columns:repeat(3, minmax(0, 1fr));
  gap:10px;
}

@media (max-width: 760px){
  .amount-grid{ grid-template-columns:repeat(2,minmax(0,1fr)); }
}

/* ===== Card ===== */
.amount-card{
  position:relative;
  text-align:left;
  cursor:pointer;
  border-radius:16px;
  padding:10px;
  background:rgba(255,255,255,.03);
  border:1px solid rgba(255,255,255,.08);
  color:#fff;
  transition:.15s ease;
  min-height:124px;
}

/* hover = grøn outline */
.amount-card:hover{
  border-color:#22c55e;
  box-shadow:0 0 0 1px #22c55e;
}

/* valgt kort */
.amount-card.active{
  border-color:#22c55e;
  box-shadow:0 0 0 2px #22c55e;
}

/* grøn check */
.amount-card.active::after{
  content:"✓";
  position:absolute;
  top:8px;
  right:8px;
  width:22px;
  height:22px;
  border-radius:50%;
  background:#22c55e;
  color:#0b1220;
  font-weight:900;
  font-size:14px;
  display:flex;
  align-items:center;
  justify-content:center;
}

/* disabled */
.amount-card.disabled{
  opacity:.45;
  cursor:not-allowed;
  transform:none !important;
}

/* amount text */
.amount-card .amt{
  font-weight:900;
  font-size:15px;
}

/* logo */
.amount-card .brand{
  margin-top:6px;
  display:flex;
  align-items:center;
  justify-content:center;
  min-height:64px;
}

.amount-card .brand img{
  width:190px;
  max-width:100%;
  height:auto;
  display:block;
  opacity:.98;
}

/* progress bar */
.bar{
  margin-top:8px;
  height:6px;
  border-radius:999px;
  background:rgba(255,255,255,.08);
  overflow:hidden;
}

.fill{
  height:100%;
  border-radius:999px;
  background:#22c55e;
  width:0%;
}

.need{
  margin-top:6px;
  color:#b8c4d6;
  font-size:12px;
}

/* ===== FIX: input + button perfectly aligned (same row) ===== */
.co-actions{
  display:grid;
  grid-template-columns: 1fr 210px;
  gap:12px;
  align-items:end;                /* begge “lander” samme bundlinje */
}

/* label over input, men input-højden fast */
.field{
  margin:0;
}

.field label{
  display:block;
  margin:0 0 6px;
  line-height:1.1;
}

/* input = knap-højde */
.field input{
  width:100%;
  height:48px;
  padding:0 14px;
  border-radius:14px;
  background:rgba(255,255,255,.04);
  border:1px solid rgba(255,255,255,.10);
  color:#fff;
  outline:none;
  margin:0;
  box-sizing:border-box;
}

/* knap = input-højde + samme baseline */
.withdraw-btn{
  height:48px;
  margin:0;
  align-self:end;
  box-sizing:border-box;
}

/* hint under begge */
.co-small{
  grid-column:1 / -1;
  margin-top:6px;
}

/* Mobile stacks */
@media (max-width:520px){
  .co-actions{ grid-template-columns:1fr; }
  .withdraw-btn{ width:100%; }
}

          .field label{ display:block; font-size:12px; color:#b8c4d6; margin-bottom:6px; }
          .field input{
            width:100%;
            padding:11px 12px;
            border-radius:14px;
            background:rgba(255,255,255,.04);
            border:1px solid rgba(255,255,255,.10);
            color:#fff;
            outline:none;
          }
          .field input:focus{ border-color:rgba(251,191,36,.45); box-shadow:0 0 0 3px rgba(251,191,36,.12); }

          .withdraw-btn{
            height:42px;
            border-radius:14px;
            border:1px solid rgba(251,191,36,.25);
            background:#fbbf24;
            color:#0b1220;
            font-weight:900;
            cursor:pointer;
          }
          .withdraw-btn:disabled{
            opacity:.45; cursor:not-allowed;
            background:rgba(251,191,36,.18);
            color:#fbbf24;
          }

          .co-small{ grid-column:1 / -1; color:#b8c4d6; font-size:12px; min-height:16px; }
        </style>

        <script>
          window.AVAILABLE_USD = ${formatUsdFromCents(balanceCents)};
          window.HAS_OPEN_WITHDRAWAL = ${hasOpenWithdrawal ? 'true' : 'false'};
        </script>

        <div class="cashout-page">
          <div class="cashout-head">
            <h1>Cash Out</h1>
            <p>Choose a method, then pick an amount.</p>
          </div>

          ${msg}

          <div class="balance-row">
            <div><b>Available:</b> $${formatUsdFromCents(balanceCents)}</div>
            <div><b>Pending:</b> $${formatUsdFromCents(pendingCents)}</div>
          </div>

          <div class="cashout-section">
            <div class="section-title">
              <h2>Most popular</h2>
              <span class="pill">Fast payouts</span>
            </div>

            <div class="methods-grid">

<!-- TOP ROW (2 cards) -->
<button class="method-card paypal top ${hasOpenWithdrawal ? 'disabled' : ''}"
        id="openPayPal"
        type="button"
        ${hasOpenWithdrawal ? 'disabled' : ''}>

  <div class="method-title">PayPal</div>

  <div class="method-logo-tile">
    <img src="${paypalImg}" alt="PayPal" />
  </div>

</button>

  <div class="method-card placeholder top">
    <div class="method-title">More payout methods</div>

    <div class="method-logo-tile">
      <div class="soon-wrap">
        <div class="soon-top">Soon</div>
        <span class="soon-pill">Coming soon</span>
      </div>
    </div>

    <div class="method-bar"><div class="method-fill" style="width:0%"></div></div>
    <div class="method-foot"><span>&nbsp;</span><b>&nbsp;</b></div>
  </div>

  <!-- SPACER så top bliver 2 og bunden 3 (på desktop) -->
  <span class="spacer"></span>

  <!-- BOTTOM ROW (3 cards) -->
  <div class="method-card placeholder">
    <div class="method-title">More payout methods</div>
    <div class="method-logo-tile">
      <div class="soon-wrap">
        <div class="soon-top">Soon</div>
        <span class="soon-pill">Coming soon</span>
      </div>
    </div>
    <div class="method-bar"><div class="method-fill" style="width:0%"></div></div>
    <div class="method-foot"><span>&nbsp;</span><b>&nbsp;</b></div>
  </div>

  <div class="method-card placeholder">
    <div class="method-title">More payout methods</div>
    <div class="method-logo-tile">
      <div class="soon-wrap">
        <div class="soon-top">Soon</div>
        <span class="soon-pill">Coming soon</span>
      </div>
    </div>
    <div class="method-bar"><div class="method-fill" style="width:0%"></div></div>
    <div class="method-foot"><span>&nbsp;</span><b>&nbsp;</b></div>
  </div>

  <div class="method-card placeholder">
    <div class="method-title">More payout methods</div>
    <div class="method-logo-tile">
      <div class="soon-wrap">
        <div class="soon-top">Soon</div>
        <span class="soon-pill">Coming soon</span>
      </div>
    </div>
    <div class="method-bar"><div class="method-fill" style="width:0%"></div></div>
    <div class="method-foot"><span>&nbsp;</span><b>&nbsp;</b></div>
  </div>

</div>

        <!-- ===== PayPal Modal ===== -->
        <div class="co-backdrop" id="coBackdrop" aria-hidden="true">
          <div class="co-modal" role="dialog" aria-modal="true" aria-labelledby="coTitle">
            <button class="co-close" id="coClose" type="button" aria-label="Close">✕</button>

            <div class="co-header">
              <div class="co-icon"><img src="${paypalImg}" alt="PayPal" /></div>
              <div><div class="co-title" id="coTitle">PayPal</div></div>
            </div>

            <div class="co-divider"></div>

            <div class="co-block">
              <div class="co-block-title">Choose amount</div>
              <div class="amount-grid" id="amountGrid">
                ${amountCardsHtml}
              </div>
            </div>

            <div class="co-divider"></div>

            <form id="cashout-form" method="POST" action="/cashout/paypal">
              <input type="hidden" name="amountCents" id="amountCents" value="" />

              <div class="co-actions">
                <div class="field">
                  <label>PayPal email</label>
                  <input id="paypalEmail" name="paypalEmail" type="email" placeholder="you@example.com" autocomplete="email" required />
                </div>

                <button class="withdraw-btn" id="withdrawBtn" type="submit" disabled>
                  Choose an amount
                </button>

                <div class="co-small" id="coHint"></div>
              </div>
            </form>
          </div>
        </div>

        <script>
          (function(){
            const availableUsd = Number(window.AVAILABLE_USD || 0);
            const hasOpen = !!window.HAS_OPEN_WITHDRAWAL;

            const openBtn = document.getElementById('openPayPal');
            const backdrop = document.getElementById('coBackdrop');
            const closeBtn = document.getElementById('coClose');

            const amountGrid = document.getElementById('amountGrid');
            const amountInp = document.getElementById('amountCents');
            const emailInp = document.getElementById('paypalEmail');
            const withdrawBtn = document.getElementById('withdrawBtn');
            const hint = document.getElementById('coHint');

            let selectedCents = 0;

            function openModal(){
              if(hasOpen) return;
              backdrop.classList.add('open');
              backdrop.setAttribute('aria-hidden','false');
              selectedCents = 0;
              amountInp.value = '';
              withdrawBtn.disabled = true;
              withdrawBtn.textContent = 'Choose an amount';
              hint.textContent = '';
              Array.from(amountGrid.querySelectorAll('.amount-card.active')).forEach(x => x.classList.remove('active'));
              refreshBars();
            }

            function closeModal(){
              backdrop.classList.remove('open');
              backdrop.setAttribute('aria-hidden','true');
            }

            function refreshBars(){
              const cards = Array.from(amountGrid.querySelectorAll('.amount-card'));
              cards.forEach(card => {
                const cents = Number(card.getAttribute('data-cents') || 0);
                const usd = cents / 100;
                const pct = Math.max(0, Math.min(100, (availableUsd / usd) * 100));
                const fill = card.querySelector('.fill');
                if(fill) fill.style.width = pct + '%';
              });
            }

            function validate(){
              const email = (emailInp.value || '').trim();
              const emailOk = email.includes('@') && email.includes('.');
              const amountOk = selectedCents > 0;

              if(!amountOk){
                withdrawBtn.disabled = true;
                withdrawBtn.textContent = 'Choose an amount';
                hint.textContent = 'Choose an amount.';
                return;
              }

              const selectedUsd = (selectedCents / 100);
              if(availableUsd < selectedUsd){
                withdrawBtn.disabled = true;
                withdrawBtn.textContent = 'Insufficient balance';
                hint.textContent = 'Insufficient balance for this amount.';
                return;
              }

              if(!emailOk){
                withdrawBtn.disabled = true;
                withdrawBtn.textContent = 'Enter email';
                hint.textContent = 'Enter a valid PayPal email.';
                return;
              }

              withdrawBtn.disabled = false;
              withdrawBtn.textContent = 'Cash out $' + selectedUsd.toFixed(2);
              hint.textContent = '';
            }

            if(openBtn) openBtn.addEventListener('click', openModal);
            if(closeBtn) closeBtn.addEventListener('click', closeModal);
            if(backdrop) backdrop.addEventListener('click', (e) => { if(e.target === backdrop) closeModal(); });
            window.addEventListener('keydown', (e) => { if(e.key === 'Escape') closeModal(); });

            if(amountGrid){
              amountGrid.addEventListener('click', (e) => {
                const card = e.target.closest('.amount-card');
                if(!card) return;
                if(card.disabled) return;

                Array.from(amountGrid.querySelectorAll('.amount-card.active')).forEach(x => x.classList.remove('active'));
                card.classList.add('active');

                selectedCents = Number(card.getAttribute('data-cents') || 0);
                amountInp.value = String(selectedCents);
                validate();
              });
            }

            if(emailInp) emailInp.addEventListener('input', validate);

            refreshBars();
            validate();
          })();
        </script>

        ${autoCheckScript}
      `,
    })
  );
});

app.get('/support', (req, res) => {
  if (!isLoggedIn(req)) return res.redirect('/');

  res.send(
    page(
      req,
      'Support — SurveyCash',
      '/support',
      ``
    )
  );
});


// ---------- Auth: finish login after email verification ----------
app.post('/auth/finish', async (req, res) => {
  try {
    const accessToken = String(req.body.access_token || '').trim();
    if (!accessToken) return res.status(400).json({ ok: false });

    const { data, error } = await supabaseAdmin.auth.getUser(accessToken);
    if (error || !data?.user?.id) {
      return res.status(401).json({ ok: false });
    }

    const userId = data.user.id;

    // Lav din egen cookie-session
    const { token, expiresAt } = await createSession(userId);

    res.cookie('session', token, {
      httpOnly: true,
      secure: IS_PROD,
      sameSite: 'Lax',
      expires: expiresAt,
      path: '/',
    });

    // ✅ HER: ryd pending email når user er verified/logged in
    res.clearCookie('pending_email', {
      httpOnly: true,
      secure: IS_PROD,
      sameSite: 'Lax',
      path: '/',
    });

    return res.json({ ok: true });
  } catch (e) {
    console.error('auth finish error:', e);
    return res.status(500).json({ ok: false });
  }
});



// ---------- Auth: resend verification email ----------
app.post('/auth/resend-verify', authLimiter, async (req, res) => {
  try {
    const pendingEmail = String(req.cookies.pending_email || '').trim().toLowerCase();

    if (!pendingEmail) {
      return res.status(400).json({ ok: false, error: 'missing_email' });
    }

    const { error } = await supabasePublic.auth.resend({
      type: 'signup',
      email: pendingEmail,
      options: {
        emailRedirectTo: 'https://surveycash.website/verified',
      },
    });

    if (error) {
      console.error('resend verify error:', error);
      return res.status(500).json({ ok: false });
    }

    return res.json({ ok: true });
  } catch (e) {
    console.error('resend fatal:', e);
    return res.status(500).json({ ok: false });
  }
});



// --- Auth handlers (modal) — Signup with email verification ---
app.post('/signup', authLimiter, async (req, res) => {
  let createdUserId = null;

  try {
    const email = String(req.body.email || '').trim().toLowerCase();
    const password = String(req.body.password || '');
    const usernameRaw = String(req.body.username || '').trim();
    const username = usernameRaw.toLowerCase();

    if (!isValidEmail(email) || password.length < 6 || !username) {
      return res.redirect('/?authError=invalid&mode=signup');
    }

    // 1️⃣ Pre-check username (vi gemmer lowercase)
    const { data: existing } = await supabaseAdmin
      .from('profiles')
      .select('user_id')
      .eq('username', username)
      .maybeSingle();

    if (existing) {
      return res.redirect('/?authError=username_taken&mode=signup');
    }

    // 2️⃣ Sign up via PUBLIC client → Supabase sender verify-mail
    const { data: signData, error: signErr } = await supabasePublic.auth.signUp({
      email,
      password,
      options: {
        emailRedirectTo: 'https://surveycash.website/verified',
      },
    });

    if (signErr) {
      const msg = String(signErr.message || '').toLowerCase();
      if (msg.includes('already') || msg.includes('registered')) {
        return res.redirect('/?authError=exists&mode=signup');
      }
      console.error('Signup signUp error:', signErr);
      return res.redirect('/?authError=unknown&mode=signup');
    }

    if (!signData?.user?.id) {
      return res.redirect('/?authError=unknown&mode=signup');
    }

    createdUserId = signData.user.id;

    // 3️⃣ Update profile username (trigger laver typisk row når auth user oprettes)
    const { error: upErr } = await supabaseAdmin
      .from('profiles')
      .update({ username })
      .eq('user_id', createdUserId);

    if (upErr) {
      if (upErr.code === '23505') {
        await supabaseAdmin.auth.admin.deleteUser(createdUserId);
        return res.redirect('/?authError=username_taken&mode=signup');
      }
      console.error('Signup profile update error:', upErr);
      await supabaseAdmin.auth.admin.deleteUser(createdUserId);
      return res.redirect('/?authError=unknown&mode=signup');
    }

    // 4️⃣ IKKE log ind – bed brugeren tjekke mail

// ✅ gem email midlertidigt så resend-knappen ved hvilken email den skal sende til
res.cookie('pending_email', email, {
  httpOnly: true,
  secure: IS_PROD,
  sameSite: 'Lax',
  maxAge: 1000 * 60 * 30, // 30 min
  path: '/',
});

    return res.redirect('/?authError=checkemail&mode=login');
  } catch (err) {
    console.error('Signup fatal:', err);

    try {
      if (createdUserId) {
        await supabaseAdmin.auth.admin.deleteUser(createdUserId);
      }
    } catch {}

    return res.redirect('/?authError=unknown&mode=signup');
  }
});


// --- Auth handlers (modal) — Supabase login ---
app.post('/login', loginLimiter, async (req, res) => {
  try {
    const email = String(req.body.email || '').trim().toLowerCase();
    const password = String(req.body.password || '');

    if (!email || !email.includes('@') || password.length < 6) {
      return res.redirect('/?authError=invalid&mode=login');
    }

    // 1️⃣ TJEK: findes account i vores DB? (profiles)
    const { data: profile, error: pErr } = await supabaseAdmin
      .from('profiles')
      .select('user_id')
      .eq('email', email)
      .maybeSingle();

    if (pErr) {
      console.error('Login profile lookup error:', pErr);
      return res.redirect('/?authError=unknown&mode=login');
    }

    if (!profile) {
      // ❌ Account findes ikke
      return res.redirect('/?authError=nouser&mode=login');
    }

    const { error: signErr } = await supabasePublic.auth.signInWithPassword({
  email,
  password,
});

if (signErr) {
  const msg = String(signErr.message || '').toLowerCase();

  if (
    msg.includes('not confirmed') ||
    msg.includes('email not confirmed') ||
    msg.includes('confirm') ||
    msg.includes('verified')
  ) {
return res.redirect('/?authError=checkemail&mode=login');
      }

  return res.redirect('/?authError=badpass&mode=login');
}


    // ✅ Login OK (samme cookie-flow som før)
const { token, expiresAt } = await createSession(profile.user_id);

res.cookie('session', token, {
  httpOnly: true,
  secure: IS_PROD,
  sameSite: 'Lax',
  expires: expiresAt,
  path: '/',
});



        return res.redirect('/');
  } catch (err) {
    console.error('Login fejl:', err);
    return res.redirect('/?authError=unknown&mode=login');
  }
});

// ---------- Account: change username (Supabase + 7-day cooldown + unique) ----------
app.post('/account/change-username', async (req, res) => {
  const user = getUserFromReq(req);
  if (!user) return res.redirect('/');

  try {
    const raw = String(req.body.newUsername || '').trim();

    // simpelt tjek: 2–24 tegn
    if (raw.length < 2 || raw.length > 24) {
      return res.redirect('/account?unError=length');
    }

    const email = String(user.email || '').toLowerCase();
    if (!email) return res.redirect('/account?unError=unknown');

    // find profile (inkl. cooldown)
    const { data: profile, error: pErr } = await supabaseAdmin
      .from('profiles')
      .select('user_id, username_changed_at')
      .eq('email', email)
      .single();

    if (pErr || !profile) {
      console.error('profile fetch error:', pErr);
      return res.redirect('/account?unError=unknown');
    }

    // 7-dages cooldown
    const MS_PER_DAY = 24 * 60 * 60 * 1000;
    const SEVEN_DAYS_MS = 7 * MS_PER_DAY;
    const now = Date.now();

    if (
      profile.username_changed_at &&
      now - profile.username_changed_at < SEVEN_DAYS_MS
    ) {
      return res.redirect('/account?unError=cooldown');
    }

    // vi gemmer lowercase, og DB håndhæver unikhed (case-insensitive index)
    const username = raw.toLowerCase();

    const { error: upErr } = await supabaseAdmin
      .from('profiles')
      .update({
        username,
        username_changed_at: now,
      })
      .eq('user_id', profile.user_id);

    if (upErr) {
      // username taget (unique index)
      if (upErr.code === '23505') {
        return res.redirect('/account?unError=taken');
      }
      console.error('username update error:', upErr);
      return res.redirect('/account?unError=unknown');
    }

    return res.redirect('/account');
  } catch (err) {
    console.error('Username change error:', err);
    return res.redirect('/account?unError=unknown');
  }
});



// ---------- Account: change password (Supabase Auth + 7-day cooldown) ----------
app.post('/account/change-password', async (req, res) => {
  const user = getUserFromReq(req);
  if (!user) return res.redirect('/');

  try {
    const oldp  = String(req.body.oldPassword  || '');
    const newp  = String(req.body.newPassword  || '');
    const newp2 = String(req.body.newPassword2 || '');

    if (!oldp) return res.redirect('/account?pwError=missingold');
    if (newp.length < 6) return res.redirect('/account?pwError=short');
    if (newp !== newp2) return res.redirect('/account?pwError=mismatch');

    const email = String(user.email || '').toLowerCase();
    if (!email) return res.redirect('/account?pwError=unknown');

    // 1) Find profile + cooldown info
    const { data: profile, error: pErr } = await supabaseAdmin
      .from('profiles')
      .select('user_id, password_changed_at')
      .eq('email', email)
      .single();

    if (pErr || !profile) {
      console.error('profile fetch error:', pErr);
      return res.redirect('/account?pwError=unknown');
    }

    // 7-dages cooldown
    const MS_PER_DAY = 24 * 60 * 60 * 1000;
    const SEVEN_DAYS_MS = 7 * MS_PER_DAY;
    const now = Date.now();

    if (
      profile.password_changed_at &&
      now - profile.password_changed_at < SEVEN_DAYS_MS
    ) {
      return res.redirect('/account?pwError=cooldown');
    }

    // 2) Verificér gammelt password via sign-in
    const { createClient } = require('@supabase/supabase-js');
    const supabasePublic = createClient(
      process.env.SUPABASE_URL,
      process.env.SUPABASE_ANON_KEY
    );

    const { error: signErr } = await supabasePublic.auth.signInWithPassword({
      email,
      password: oldp,
    });

    if (signErr) {
      return res.redirect('/account?pwError=badpass');
    }

    // 3) Opdatér password i Supabase Auth
    const { error: upErr } = await supabaseAdmin.auth.admin.updateUserById(
      profile.user_id,
      { password: newp }
    );

    if (upErr) {
      console.error('update password error:', upErr);
      return res.redirect('/account?pwError=unknown');
    }

    // 4) Opdatér cooldown timestamp i profiles
    await supabaseAdmin
      .from('profiles')
      .update({ password_changed_at: now })
      .eq('user_id', profile.user_id);

    return res.redirect('/account');
  } catch (err) {
    console.error('Password change error:', err);
    return res.redirect('/account?pwError=unknown');
  }
});


// ---------- Cashout (POST) ----------
app.post('/cashout/paypal', async (req, res) => {
  if (!isLoggedIn(req)) return res.redirect('/');

  try {
    const user = req.user;
    if (!user?.id) return res.redirect('/');

   const amountCents = Number(req.body.amountCents || 0);
if (!CASHOUT_ALLOWED_SET.has(amountCents)) {
  return res.redirect('/cashout?err=amount');
}

    const paypalEmail = String(req.body.paypalEmail || '').trim().toLowerCase();
    if (!isValidEmail(paypalEmail)) {
      return res.redirect('/cashout?err=email');
    }

    // ✅ 0) STOP hvis der allerede er en åben cashout (pending/processing)
    const { data: openWs, error: openErr } = await supabaseAdmin
      .from('withdrawals')
      .select('id,status')
      .eq('user_id', user.id)
      .in('status', ['pending', 'processing'])
      .order('id', { ascending: false })
      .limit(1);

    if (openErr) {
      console.error('open withdrawal check error:', openErr);
      return res.redirect('/cashout?err=server');
    }

    if (Array.isArray(openWs) && openWs.length > 0) {
      // allerede en igang
      return res.redirect(`/cashout?err=open&w=${openWs[0].id}`);
    }

    // 1) Lav withdrawal + flyt balance -> pending (DB/RPC)
    const { error } = await supabaseAdmin.rpc('request_cashout', {
      p_user_id: user.id,
      p_amount_cents: amountCents,
      p_paypal_email: paypalEmail,
    });

    if (error) {
      console.error('cashout rpc error:', error);
      return res.redirect('/cashout?err=balance');
    }

    // 2) Find PRÆCIS den nyeste pending withdrawal for denne request
    const { data: newestW, error: newestErr } = await supabaseAdmin
      .from('withdrawals')
      .select('*')
      .eq('user_id', user.id)
      .eq('status', 'pending')
      .eq('amount_cents', amountCents)
      .eq('paypal_email', paypalEmail)
      .order('id', { ascending: false })
      .limit(1)
      .maybeSingle();

    if (newestErr || !newestW) {
      console.error('Could not find pending withdrawal after request:', newestErr);
      return res.redirect('/cashout?err=server');
    }

    // 3) Send PayPal payout nu (pending -> processing + batch id)
    try {
      const amountUsd = Number(newestW.amount_cents || 0) / 100;

      const payoutBatchId = await paypalCreatePayout({
        receiverEmail: newestW.paypal_email,
        amountUsd,
        withdrawalId: newestW.id,
      });

      await supabaseAdmin
        .from('withdrawals')
        .update({ paypal_batch_id: payoutBatchId, status: 'processing' })
        .eq('id', newestW.id);
    } catch (e) {
      console.error('paypal payout failed right after request:', e);

      await supabaseAdmin
        .from('withdrawals')
        .update({ status: 'failed', error_text: String(e.message || e) })
        .eq('id', newestW.id);

      await supabaseAdmin.rpc('fail_cashout_return_funds', {
        p_withdrawal_id: newestW.id,
      });

      return res.redirect('/cashout?err=server');
    }

    return res.redirect(`/cashout?w=${newestW.id}`);
  } catch (e) {
    console.error('cashout error:', e);
    return res.redirect('/cashout?err=server');
  }
});


app.post('/withdrawals/:id/check', async (req, res) => {
  if (!isLoggedIn(req)) return res.sendStatus(401);

  const id = Number(req.params.id);
  const userId = req.user.id;

  // 1) hent withdrawal
  const { data: w, error: wErr } = await supabaseAdmin
    .from('withdrawals')
    .select('*')
    .eq('id', id)
    .single();

  if (wErr || !w) return res.sendStatus(404);
  if (w.user_id !== userId) return res.sendStatus(403);

  // skal have batch_id for at kunne checke
  if (!w.paypal_batch_id) {
    return res.status(400).json({ ok: false, error: 'missing_paypal_batch_id' });
  }

  // hvis allerede færdig, gør intet
  if (w.status === 'paid' || w.status === 'failed') {
    return res.json({ ok: true, status: w.status, note: 'already_final' });
  }

  try {
    // 2) spørg PayPal
    const batch = await paypalGetPayoutBatch(w.paypal_batch_id);
    const nextStatus = mapPayPalBatchStatus(batch);

if (nextStatus === 'paid') {
  // 1) markér kun som paid hvis den ikke allerede er paid (idempotent)
  const { data: upd, error: updErr } = await supabaseAdmin
    .from('withdrawals')
    .update({ status: 'paid', error_text: null })
    .eq('id', w.id)
    .neq('status', 'paid')
    .select('id')
    .maybeSingle();

  if (updErr) {
    return res.status(500).json({ ok: false, error: String(updErr.message || updErr) });
  }

  // 2) træk kun pending ned hvis vi faktisk ændrede status til paid
  if (upd) {
    const { data: prof, error: pErr } = await supabaseAdmin
      .from('profiles')
      .select('pending_cents')
      .eq('user_id', w.user_id)
      .single();

    if (!pErr && prof) {
      const pendingNow = Number(prof.pending_cents || 0);
      const amount = Number(w.amount_cents || 0);

      await supabaseAdmin
        .from('profiles')
        .update({
          pending_cents: Math.max(0, pendingNow - amount),
        })
        .eq('user_id', w.user_id);
    }
  }

  return res.json({ ok: true, status: 'paid' });
}


    if (nextStatus === 'failed') {
      await supabaseAdmin
        .from('withdrawals')
        .update({ status: 'failed', error_text: 'PayPal payout failed/denied' })
        .eq('id', w.id);

      // refund pending -> balance
      await supabaseAdmin.rpc('fail_cashout_return_funds', {
        p_withdrawal_id: w.id,
      });

      return res.json({ ok: true, status: 'failed' });
    }

    // stadig processing
    await supabaseAdmin
      .from('withdrawals')
      .update({ status: 'processing' })
      .eq('id', w.id);

    return res.json({ ok: true, status: 'processing' });
  } catch (e) {
    console.error('check payout error:', e);
    return res.status(500).json({ ok: false, error: String(e.message || e) });
  }
});


// ---------- Health API ----------
app.get('/api/health', (req, res) => {
  res.json({ ok: true, app: 'SurveyCash Web', ts: Date.now(), loggedIn: isLoggedIn(req) });
});

app.get('/logout', async (req, res) => {
  const token = req.cookies.session;

  if (token) {
    await supabaseAdmin
      .from('sessions')
      .delete()
      .eq('token', token);
  }

  res.clearCookie('session', {
    httpOnly: true,
    secure: IS_PROD,
    sameSite: 'Lax',
    path: '/',
  });

  // 🔔 fortæl ALLE faner at logout skete
  return res.send(`
    <script>
      localStorage.setItem('surveycash:logout', Date.now());
      location.href = '/';
    </script>
  `);
});


// ---------- Start ----------
app.listen(PORT, () => {
  console.log('SurveyCash (web) kører på ' + BASE_URL);
});
