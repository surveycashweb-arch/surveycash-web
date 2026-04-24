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

var forgotBackdrop = document.getElementById('forgot-backdrop');
var forgotOpen = document.getElementById('forgotPasswordOpen');
var forgotClose = document.getElementById('forgot-close');
var forgotForm = document.getElementById('forgot-form');
var forgotEmail = document.getElementById('forgot-email');
var forgotSubmit = document.getElementById('forgot-submit');
var forgotMessage = document.getElementById('forgot-message');

function setForgotMessage(text, isError) {
  forgotMessage.textContent = text || '';
  forgotMessage.style.color = isError ? '#fca5a5' : '#86efac';
}

function openForgotPassword() {
  forgotBackdrop.hidden = false;
  setForgotMessage('', false);
  setTimeout(function () {
    if (forgotEmail) forgotEmail.focus();
  }, 20);
}

function closeForgotPassword() {
  forgotBackdrop.hidden = true;
  if (forgotForm) forgotForm.reset();
  setForgotMessage('', false);
  if (forgotSubmit) forgotSubmit.disabled = false;
}

if (forgotOpen) {
  forgotOpen.addEventListener('click', function (e) {
    e.preventDefault();
    openForgotPassword();
  });
}

if (forgotClose) {
  forgotClose.addEventListener('click', function () {
    closeForgotPassword();
  });
}

if (forgotBackdrop) {
  forgotBackdrop.addEventListener('click', function (e) {
    if (e.target === forgotBackdrop) closeForgotPassword();
  });
}

if (forgotForm) {
  forgotForm.addEventListener('submit', async function (e) {
    e.preventDefault();

    var email = (forgotEmail.value || '').trim();
    if (!email) {
      setForgotMessage('Enter your email.', true);
      return;
    }

    forgotSubmit.disabled = true;
    setForgotMessage('Sending reset link...', false);

    try {
      var res = await fetch('/auth/forgot-password', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email: email })
      });

      var data = await res.json();

      if (!res.ok) {
        throw new Error(data.error || 'Something went wrong.');
      }

      setForgotMessage('If the account exists, a reset link has been sent to your email.', false);
    } catch (err) {
      setForgotMessage(err.message || 'Could not send reset email.', true);
    } finally {
      forgotSubmit.disabled = false;
    }
  });
}
 
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



    var notifWrap = document.getElementById('notifWrap');
  var notifBtn = document.getElementById('notifBtn');
  var notifDot = document.getElementById('notifDot');
  var notifPanel = document.getElementById('notifPanel');
  var notifList = document.getElementById('notifList');
  var notifMarkRead = document.getElementById('notifMarkRead');

  var notifications = [];

  function escapeNotifHtml(str) {
    return String(str || '')
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#039;');
  }

  function formatNotifDate(value) {
    try {
      var d = new Date(value);
      return d.toLocaleString();
    } catch (e) {
      return '';
    }
  }

  function hasUnreadNotifications(list) {
    return Array.isArray(list) && list.some(function (n) { return !n.is_read; });
  }

  function renderNotifications(list) {
    if (!notifList) return;

    if (!Array.isArray(list) || list.length === 0) {
      notifList.innerHTML = '<div class="notif-empty">No notifications yet.</div>';
      return;
    }

    notifList.innerHTML = list.map(function (item) {
      var unreadClass = item.is_read ? '' : ' unread';
      return '' +
        '<div class="notif-item' + unreadClass + '">' +
          '<div class="notif-item-top">' +
            '<div class="notif-item-title">' + escapeNotifHtml(item.title) + '</div>' +
            '<button class="notif-remove" type="button" data-id="' + Number(item.id) + '">Remove</button>' +
          '</div>' +
          '<div class="notif-item-date">' + escapeNotifHtml(formatNotifDate(item.created_at)) + '</div>' +
          '<div class="notif-item-body">' + escapeNotifHtml(item.body) + '</div>' +
        '</div>';
    }).join('');

    var removeBtns = notifList.querySelectorAll('.notif-remove');
    removeBtns.forEach(function (btn) {
      btn.addEventListener('click', async function (e) {
        e.stopPropagation();
        var id = Number(btn.getAttribute('data-id') || 0);
        if (!id) return;
        await removeNotification(id);
      });
    });
  }

  function updateNotifBell(list) {
    if (!notifBtn || !notifDot) return;
    var unread = hasUnreadNotifications(list);
    notifBtn.classList.toggle('has-unread', unread);
    notifDot.hidden = !unread;
  }

  async function loadNotifications() {
    try {
      if (!notifBtn) return;

      var r = await fetch('/api/notifications', {
        credentials: 'same-origin'
      });

      var data = await r.json();
      notifications = Array.isArray(data) ? data : [];
      renderNotifications(notifications);
      updateNotifBell(notifications);
    } catch (err) {
      console.error('loadNotifications error:', err);
    }
  }

  async function markNotificationsRead() {
    try {
      if (!hasUnreadNotifications(notifications)) return;

      await fetch('/api/notifications/read', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'same-origin'
      });

      notifications = notifications.map(function (item) {
        return Object.assign({}, item, { is_read: true });
      });

      renderNotifications(notifications);
      updateNotifBell(notifications);
    } catch (err) {
      console.error('markNotificationsRead error:', err);
    }
  }

  async function removeNotification(id) {
    try {
      var r = await fetch('/api/notifications/remove', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'same-origin',
        body: JSON.stringify({ id: id })
      });

      var j = await r.json();
      if (!j || !j.ok) return;

      notifications = notifications.filter(function (item) {
        return Number(item.id) !== Number(id);
      });

      renderNotifications(notifications);
      updateNotifBell(notifications);
    } catch (err) {
      console.error('removeNotification error:', err);
    }
  }

  function openNotifPanel() {
    if (!notifPanel) return;
    notifPanel.hidden = false;
    markNotificationsRead();
  }

  function closeNotifPanel() {
    if (!notifPanel) return;
    notifPanel.hidden = true;
  }

  if (notifBtn && notifPanel && notifWrap) {
    notifBtn.addEventListener('click', function (e) {
      e.stopPropagation();

      if (notifPanel.hidden) {
        openNotifPanel();
      } else {
        closeNotifPanel();
      }
    });

    if (notifMarkRead) {
      notifMarkRead.addEventListener('click', function (e) {
        e.stopPropagation();
        markNotificationsRead();
      });
    }

    document.addEventListener('click', function (e) {
      if (!notifWrap.contains(e.target)) {
        closeNotifPanel();
      }
    });

    loadNotifications();
    setInterval(loadNotifications, 15000);
  }

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

  .profile-wrap {
    position: relative;
    display: flex;
    align-items: center;
    gap: 10px;
  }

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


.notif-wrap{
  position:relative;
}

.notif-bell{
  position:relative;
  border:none;
  background:transparent;
  display:flex;
  align-items:center;
  justify-content:center;
  cursor:pointer;
  padding:0;
  width:42px;
  height:42px;
  transform:translateY(3px);
}

.notif-bell svg{
  width:32px;
  height:32px;
  fill:#9ca3af;
  opacity:.95;
  transition:fill .15s ease;
}

.notif-bell:hover svg{
  fill:#d5d9e6;
}

/* unread = samme design, bare gul klokke */
.notif-bell.has-unread svg{
  fill:#fbbf24;
}

.notif-bell.has-unread:hover svg{
  fill:#f59e0b;
}

/* rød dot */
.notif-dot{
  position:absolute;
  top:7px;
  right:4px;
  width:9px;
  height:9px;
  border-radius:999px;
  background:#ef4444;
  box-shadow:0 0 0 2px #151c2e;
}

.notif-panel{
  position:absolute;
  top:48px;
  right:0;
  width:370px;
  max-height:430px;
  overflow:hidden;
  border-radius:16px;
  border:1px solid rgba(255,255,255,.08);
  background:#151c2e;
  box-shadow:0 24px 60px rgba(0,0,0,.45);
  z-index:300;
}

.notif-panel-head{
  display:flex;
  align-items:center;
  justify-content:space-between;
  gap:12px;
  padding:14px 14px 12px;
  border-bottom:1px solid rgba(255,255,255,.06);
}

.notif-panel-title{
  font-size:20px;
  font-weight:800;
  color:#fff;
}

.notif-mark-read{
  border:0;
  background:transparent;
  color:#fbbf24;
  font-size:14px;
  font-weight:800;
  cursor:pointer;
}

.notif-mark-read:hover{
  color:#f59e0b;
}

.notif-list{
  max-height:360px;
  overflow:auto;
  padding:12px;
}

.notif-item{
  position:relative;
  border-radius:14px;
  background:rgba(255,255,255,.03);
  border:1px solid rgba(255,255,255,.05);
  padding:14px 14px 14px;
  margin-bottom:12px;
}

.notif-item:last-child{
  margin-bottom:0;
}

.notif-item.unread{
  border-color:rgba(239,68,68,.28);
  box-shadow:inset 0 0 0 1px rgba(239,68,68,.08);
}

.notif-item-top{
  display:flex;
  align-items:flex-start;
  justify-content:space-between;
  gap:12px;
  margin-bottom:6px;
}

.notif-item-title{
  font-size:14px;
  font-weight:800;
  color:#fff;
}

.notif-remove{
  border:0;
  background:transparent;
  color:#94a3b8;
  font-size:13px;
  font-weight:700;
  cursor:pointer;
  padding:0;
  line-height:1;
}

.notif-remove:hover{
  color:#ef4444;
}

.notif-item-date{
  font-size:12px;
  color:#94a3b8;
  margin-bottom:8px;
}

.notif-item-body{
  font-size:14px;
  line-height:1.5;
  color:#dbe4f0;
}

.notif-empty{
  color:#94a3b8;
  font-size:14px;
  padding:10px 4px;
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


@media (max-width:760px){

  header{
    padding:8px 10px;
    gap:8px;
    flex-wrap:wrap;
    align-items:center;
  }

  .logo{
    font-size:18px;
    margin-right:0;
    order:1;
  }

  .auth{
    margin-left:auto;
    order:2;
    display:flex;
    align-items:center;
    gap:8px;
  }

  nav{
    display:flex !important;
    justify-content:center;
    gap:10px;
    width:100%;
    flex:0 0 100%;
    order:3;
    margin-top:4px;
  }

  .nav-item{
    font-size:13px;
    padding:6px 10px;
  }

  .profile-name{
    display:none;
  }

  .balance-pill{
    padding:6px 10px;
    height:34px;
  }

  .balance-symbol{
    font-size:17px;
  }

  .balance-amount{
    font-size:13px;
  }

  .notif-bell{
    width:34px;
    height:34px;
    transform:none;
  }

  .notif-bell svg{
    width:24px;
    height:24px;
  }

  .profile-chip{
    padding:4px 8px;
    gap:6px;
  }

  .profile-avatar{
    width:28px;
    height:28px;
  }

  .profile-avatar span{
    font-size:15px;
  }
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

.forgot-backdrop{
  position:fixed;
  inset:0;
  background:rgba(12,16,28,.82);   /* samme backdrop som auth */
  display:flex;
  align-items:center;
  justify-content:center;
  padding:20px;
  z-index:99999;
}

.forgot-backdrop[hidden]{
  display:none !important;
}

.forgot-modal{
  position:relative;
  width:100%;
  max-width:420px;

  background:#1a1f2b;              /* samme som signup */
  border:1px solid #1f2937;        /* samme border */
  border-radius:24px;

  padding:32px 28px 28px;

  box-shadow:0 32px 90px rgba(0,0,0,.75);

  color:#fff;
}

.forgot-modal h2{
  margin:0 0 14px;
  font-size:24px;
  font-weight:700;                 /* samme som signup */
  text-align:center;
  color:#ffffff;
}

.forgot-modal p{
  margin:0 0 18px;
  color:#cbd5e1;
  font-size:14px;
  line-height:1.5;
}

#forgot-form{
  display:flex;
  flex-direction:column;
  gap:14px;
}

#forgot-email{
  width:100%;
  padding:12px 14px;
  border-radius:10px;

  border:1px solid #2a3240;   /* samme som signup */
  background:#131822;         /* samme som signup */

  color:#e5e7eb;
  font-size:14px;
  margin-bottom:14px;

  outline:none;
  box-sizing:border-box;
}

#forgot-email::placeholder{
  color:#9ca3af;
}

#forgot-email:focus{
  border-color:#4b5563;   
  box-shadow:none;
}

#forgot-submit{
  width:100%;
  height:42px;

  border:none;
  border-radius:12px;

  background:#fbbf24;
  color:#111827;

  font-size:14px;
  font-weight:600;                 /* mindre tyk (signup style) */

  cursor:pointer;
}

#forgot-submit:disabled{
  opacity:0.65;
  cursor:not-allowed;
}

.forgot-message{
  margin-top:6px;
  min-height:18px;
  font-size:13px;
  color:#9ca3af;
}

.forgot-close{
  position:absolute;
  right:18px;
  top:16px;

  width:28px;
  height:28px;

  border-radius:999px;
  border:1px solid #4b5563;
  background:#111827;

  color:#e5e7eb;
  font-size:18px;

  display:flex;
  align-items:center;
  justify-content:center;

  cursor:pointer;
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
  ${tab('/', 'Earn')}
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

<div class="notif-wrap" id="notifWrap">
  <button class="notif-bell" id="notifBtn" type="button" aria-label="Notifications">
    <svg viewBox="0 0 24 24" aria-hidden="true" focusable="false">
      <circle cx="12" cy="4" r="1.8" />
      <path d="M6 10a6 6 0 0112 0v3.2l1.2 2A1 1 0 0118.4 17H5.6a1 1 0 01-.8-1.8l1.2-2V10z"/>
      <circle cx="12" cy="18.3" r="1.2" />
    </svg>
    <span class="notif-dot" id="notifDot" hidden></span>
  </button>

  <div class="notif-panel" id="notifPanel" hidden>
    <div class="notif-panel-head">
      <div class="notif-panel-title">Notifications</div>
      <button class="notif-mark-read" id="notifMarkRead" type="button">Mark all as read</button>
    </div>

    <div class="notif-list" id="notifList">
      <div class="notif-empty">No notifications yet.</div>
    </div>
  </div>
</div>

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
  <a href="#" id="forgotPasswordOpen">Forgot your password?</a>
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

<div id="forgot-backdrop" class="forgot-backdrop" hidden>
  <div class="forgot-modal">
    <button type="button" id="forgot-close" class="forgot-close">×</button>
    <h2>Forgot password?</h2>
    <p>Enter your email and we’ll send you a reset link.</p>

    <form id="forgot-form">
      <input
        id="forgot-email"
        type="email"
        placeholder="Email address"
        autocomplete="email"
        required
      />
      <button type="submit" id="forgot-submit">Send reset link</button>
    </form>

    <div id="forgot-message" class="forgot-message"></div>
  </div>
</div>
  `;
}



// ---------- Routes ----------
app.get('/', async (req, res) => {
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

  const bodyHtml = `
  <style>

    html, body{
      min-height:100%;
      margin:0;
      overflow-x:hidden;
      background:#111827;
    }

    main{
      position:relative;
      max-width:none !important;
      margin:0 !important;
      padding:0 !important;
      background:#111827;
    }

    .earn-page{
      position:relative;
      width:100%;
      box-sizing:border-box;
      background:#111827;
    }

    .earn-area{
      background:#111827;
      padding:24px 0 220px;
    }

    .earn-wrap{
      width:1080px;
      max-width:1080px;
      margin:0 auto;
      padding:0 14px;
    }

    .earn-section{
      margin-bottom:26px;
    }

    .earn-section:last-child{
      margin-bottom:0;
    }

    .earn-head{
      display:flex;
      align-items:center;
      justify-content:space-between;
      gap:12px;
      margin-bottom:10px;
    }

    .earn-section-title{
      margin:0;
      font-size:26px;
      font-weight:800;
      color:#ffffff;
      letter-spacing:-0.01em;
    }

    .earn-grid{
      display:grid;
      grid-template-columns:repeat(6, 1fr);
      gap:10px;
    }

    .earn-card{
      position:relative;
      aspect-ratio:1 / 1.40;
      border-radius:13px;
      border:1px solid rgba(255,255,255,.06);
      background:
        radial-gradient(circle at top left, rgba(255,255,255,.04), transparent 45%),
        rgba(18,24,40,.92);
      padding:10px 8px;
      overflow:hidden;
      text-decoration:none;
      display:flex;
      flex-direction:column;
      justify-content:center;
      align-items:center;
      transition:transform .15s ease, border-color .15s ease, background .15s ease;
    }

    .earn-card:hover{
      transform:translateY(-2px);
      border-color:rgba(255,255,255,.11);
      background:
        radial-gradient(circle at top left, rgba(255,255,255,.06), transparent 45%),
        rgba(24,32,52,.98);
    }

    .earn-card.clickable{
      cursor:pointer;
    }

    .earn-card-top{
      position:relative;
      z-index:2;
      display:flex;
      align-items:center;
      justify-content:center;
      text-align:center;
      min-height:58px;
      width:100%;
    }

    .earn-card-top img{
      max-width:92px;
      max-height:24px;
      width:auto;
      height:auto;
      display:block;
    }

    .earn-card-brand{
      margin:0;
      font-size:19px;
      line-height:1.15;
      font-weight:900;
      color:#ffffff;
    }

    .earn-soon{
      display:inline-flex;
      align-items:center;
      justify-content:center;
      min-height:28px;
      padding:0 10px;
      border-radius:9px;
      font-size:11px;
      font-weight:800;
      color:#9ca3af;
      border:1px solid rgba(255,255,255,.06);
      background:rgba(255,255,255,.03);
    }

    .cpx-card{
      overflow:hidden;
    }

    .cpx-bg{
      position:absolute;
      inset:0;
      background:
        linear-gradient(
          to top,
          rgba(34,197,94,.25) 0%,
          rgba(34,197,94,.10) 30%,
          rgba(34,197,94,.04) 55%,
          transparent 75%
        );
      pointer-events:none;
    }

    .cpx-card img{
      max-width:120px;
      max-height:36px;
      margin-bottom:12px;
    }

    .partner-glow{
      position:absolute;
      inset:auto 0 0 0;
      height:42px;
      pointer-events:none;
      z-index:1;
    }

    .glow-green{
      background:linear-gradient(to top, rgba(34,197,94,.18) 0%, rgba(34,197,94,.06) 40%, rgba(34,197,94,0) 100%);
    }

    .glow-orange{
      background:linear-gradient(to top, rgba(249,115,22,.18) 0%, rgba(249,115,22,.06) 40%, rgba(249,115,22,0) 100%);
    }

    .earn-bottom-fill{
      position:fixed;
      left:50%;
      transform:translateX(-50%);
      bottom:0;
      width:100vw;
      height:220px;
      background:#151c2e;
      border-top:1px solid rgba(255,255,255,.04);
      z-index:0;
      pointer-events:none;
    }

    .earn-footer-content{
      position:fixed;
      left:50%;
      transform:translateX(-50%);
      bottom:0;
      width:100vw;
      height:220px;
      z-index:1;
      display:flex;
      justify-content:center;
      box-sizing:border-box;
      pointer-events:none;
    }

    .earn-footer-inner{
      width:100%;
      max-width:1280px;
      padding:26px 36px 0;
      display:grid;
      grid-template-columns:1.7fr 1fr 1fr 1fr 1fr;
      gap:36px;
      box-sizing:border-box;
      pointer-events:auto;
    }

    .footer-brand{
      display:flex;
      flex-direction:column;
      align-items:flex-start;
    }

    .footer-logo{
      font-size:22px;
      font-weight:900;
      line-height:1;
      color:#fff;
      margin-bottom:18px;
    }

    .footer-logo .white{
      color:#ffffff;
    }

    .footer-logo .accent{
      color:#fbbf24;
    }

    .footer-brand-text{
      max-width:380px;
      color:rgba(255,255,255,.62);
      font-size:14px;
      line-height:1.55;
      margin-bottom:18px;
    }

    .footer-trust{
      display:flex;
      align-items:center;
    }

    .footer-trust-link{
      display:flex;
      align-items:center;
      gap:10px;
      color:#ffffff;
      text-decoration:none;
      font-size:12px;
      font-weight:700;
    }

    .footer-trust-img{
      height:42px;
      width:auto;
      display:block;
    }

    .footer-trust-link:hover{
      text-decoration:underline;
    }

    .footer-trust-link span{
      font-size:14px;
    }

    .footer-col-title{
      color:#fbbf24;
      font-size:16px;
      font-weight:900;
      margin:0 0 22px;
    }

    .footer-link{
      display:block;
      color:#ffffff;
      text-decoration:none;
      font-size:15px;
      font-weight:700;
      margin-bottom:22px;
      opacity:.95;
    }

    .footer-link:hover{
      opacity:1;
    }


@media (min-width:1101px){
  .earn-wrap{
    margin-left:24px;
    margin-right:0;
  }
}

    @media (min-width:761px){
      html, body{
        overflow:hidden;
      }

      main{
        height:calc(100vh - 64px);
        overflow:hidden;
      }
    }

    @media (max-width:1200px){
      .earn-footer-inner{
        grid-template-columns:1.7fr 1fr 1fr 1fr;
        gap:28px;
      }

      .footer-col.social{
        display:none;
      }
    }

    @media (max-width:1100px){
      .earn-wrap{
        width:100%;
        max-width:100%;
      }

      .earn-grid{
        grid-template-columns:repeat(4, 1fr);
      }

      .earn-footer-inner{
        grid-template-columns:1.5fr 1fr 1fr;
        gap:28px;
      }

      .footer-col.legal{
        display:none;
      }
    }

    @media (max-width:760px){
      html, body, main, .earn-page, .earn-area{
        background:#111827;
      }

      main{
        min-height:auto;
      }

      .earn-area{
        padding:20px 0 0;
      }

      .earn-wrap{
        width:100%;
        max-width:100%;
        padding:0 10px;
        box-sizing:border-box;
      }

      .earn-grid{
        grid-template-columns:repeat(4, 1fr);
        gap:8px;
      }

      .earn-card{
        aspect-ratio:1 / 1.18;
        padding:8px 6px;
      }

      .earn-card-top{
        min-height:42px;
      }

      .earn-card-top img{
        max-width:72px;
        max-height:20px;
      }

      .earn-card-brand{
        font-size:16px;
      }

      .earn-soon{
        min-height:24px;
        padding:0 8px;
        font-size:10px;
      }

      .earn-section-title{
        font-size:22px;
      }

      .earn-bottom-fill{
        display:none;
      }

      .earn-footer-content{
        position:relative;
        left:auto;
        transform:none;
        bottom:auto;
        width:100%;
        height:auto;
        display:block;
        margin-top:18px;
        padding:16px 0 12px;
        background:#151c2e;
        border-top:1px solid rgba(255,255,255,.04);
      }

      .earn-footer-inner{
        width:100%;
        max-width:100%;
        padding:0 14px 8px;
        grid-template-columns:1fr 1fr 1fr;
        gap:18px;
        box-sizing:border-box;
        align-items:start;
      }

      .footer-brand{
        grid-column:1 / -1;
      }

      .footer-logo{
        font-size:18px;
        margin-bottom:10px;
      }

      .footer-brand-text{
        max-width:none;
        font-size:12px;
        line-height:1.45;
        margin-bottom:10px;
      }

      .footer-trust-link{
        gap:8px;
      }

      .footer-trust-link span{
        font-size:12px;
      }

      .footer-trust-img{
        height:24px;
      }

      .footer-col-title{
        font-size:14px;
        margin:0 0 10px;
      }

      .footer-link{
        font-size:13px;
        margin-bottom:10px;
      }

      .footer-col:nth-of-type(2){
        display:none;
      }

      .footer-col.legal,
      .footer-col.social{
        display:block;
      }
    }

    @media (max-width:560px){
      .earn-wrap{
        padding:0 10px;
      }

      .earn-grid{
        grid-template-columns:repeat(4, 1fr);
        gap:8px;
      }

      .earn-card{
        aspect-ratio:1 / 1.12;
        padding:7px 6px;
      }

      .earn-card-top{
        min-height:38px;
      }

      .earn-card-top img{
        max-width:64px;
        max-height:18px;
      }

      .earn-card-brand{
        font-size:15px;
      }

      .earn-footer-inner{
        grid-template-columns:1fr 1fr 1fr;
        gap:14px;
        padding:0 12px 8px;
      }

      .footer-brand{
        grid-column:1 / -1;
      }

      .footer-logo{
        font-size:17px;
      }

      .footer-brand-text{
        font-size:11px;
        line-height:1.4;
      }

      .footer-col-title{
        font-size:13px;
      }

      .footer-link{
        font-size:12px;
        margin-bottom:8px;
      }

      .footer-trust-link span{
        font-size:11px;
      }

      .footer-trust-img{
        height:22px;
      }

      .footer-col:nth-of-type(2){
        display:none;
      }

      .footer-col.legal,
      .footer-col.social{
        display:block;
      }
    }

  </style>

  <div class="earn-page">
    <div class="earn-area">
      <div class="earn-wrap">

        <section class="earn-section">
          <div class="earn-head">
            <h2 class="earn-section-title">Offers</h2>
          </div>

          <div class="earn-grid">

            <a href="/games/wannads" class="earn-card clickable">
              <div class="partner-glow glow-orange"></div>
              <div class="earn-card-top">
                <div class="earn-card-brand">Wannads</div>
              </div>
            </a>

            <div class="earn-card"><span class="earn-soon">Coming soon</span></div>
            <div class="earn-card"><span class="earn-soon">Coming soon</span></div>
            <div class="earn-card"><span class="earn-soon">Coming soon</span></div>
            <div class="earn-card"><span class="earn-soon">Coming soon</span></div>
            <div class="earn-card"><span class="earn-soon">Coming soon</span></div>

          </div>
        </section>

        <section class="earn-section">
          <div class="earn-head">
            <h2 class="earn-section-title">Surveys</h2>
          </div>

          <div class="earn-grid">

            <a href="/surveys/cpx" class="earn-card clickable cpx-card">
              <div class="cpx-bg"></div>
              <div class="earn-card-top">
                <img src="/partners/cpx.png" alt="CPX Research" />
              </div>
            </a>

            <div class="earn-card"><span class="earn-soon">Coming soon</span></div>
            <div class="earn-card"><span class="earn-soon">Coming soon</span></div>
            <div class="earn-card"><span class="earn-soon">Coming soon</span></div>

          </div>
        </section>

      </div>
    </div>

    <div class="earn-bottom-fill"></div>

    <div class="earn-footer-content">
      <div class="earn-footer-inner">

        <div class="footer-brand">
          <div class="footer-logo"><span class="white">Survey</span><span class="accent">Cash</span></div>

          <div class="footer-brand-text">
            SurveyCash is built to make earning simple. Complete surveys, explore offers and turn your time online into real rewards with quick payouts.
          </div>

          <div class="footer-trust">
            <a href="https://www.trustpilot.com/review/surveycash.website" target="_blank" class="footer-trust-link">
              <span>Rate us on Trustpilot</span>
              <img src="/img/trustpilot-mission.png" class="footer-trust-img">
            </a>
          </div>
        </div>

        <div class="footer-col">
          <div class="footer-col-title">SurveyCash</div>
          <a href="/" class="footer-link">Earn</a>
          <a href="/cashout" class="footer-link">Cash Out</a>
          <a href="/support" class="footer-link">Support</a>
        </div>

        <div class="footer-col">
          <div class="footer-col-title">Help</div>
          <a href="/support" class="footer-link">FAQ</a>
          <a href="/support" class="footer-link">Contact</a>
        </div>

        <div class="footer-col legal">
          <div class="footer-col-title">Info</div>
          <a href="/terms" class="footer-link">Terms</a>
          <a href="/privacy" class="footer-link">Privacy</a>
        </div>

        <div class="footer-col social">
          <div class="footer-col-title">Social</div>
          <a href="https://www.tiktok.com/@surveycashh?lang=da" target="_blank" rel="noopener noreferrer" class="footer-link">TikTok</a>
          <a href="https://x.com/SurveyCashh" target="_blank" rel="noopener noreferrer" class="footer-link">X</a>
        </div>

      </div>
    </div>
  </div>
  `;

  return res.send(
    page(
      req,
      'Earn — SurveyCash',
      '/',
      bodyHtml,
    ),
  );
});

app.get('/ping', (req, res) => {
  res.send('ok');
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
          body { font-family: Arial; padding: 40px; background:#0f172a; color:#e5e7eb; line-height:1.6; }
          h1 { color:#facc15; }
          h3 { color:#facc15; margin-top:28px; }
          p { max-width:800px; }
        </style>
      </head>
      <body>
        <h1>Privacy Policy</h1>

        <p><strong>Last updated: March 2026</strong></p>

        <p>
        SurveyCash respects your privacy and is committed to protecting your personal information.
        </p>

        <h3>Information We Collect</h3>
        <p>
        We may collect basic information such as email address, IP address, device information,
        browser information, and usage data to operate the platform, prevent fraud, and ensure
        proper reward attribution.
        </p>

        <h3>How We Use Information</h3>
        <p>
        The information collected may be used to operate the SurveyCash platform,
        verify user activity, prevent fraudulent behavior, process rewards and payouts,
        and communicate with users regarding their accounts.
        </p>

        <h3>Third-Party Services</h3>
        <p>
        SurveyCash works with third-party survey and offer providers. These partners may
        collect additional data according to their own privacy policies when users
        participate in surveys or offers.
        </p>

        <h3>Data Protection</h3>
        <p>
        We take reasonable measures to protect user data from unauthorized access,
        misuse, or disclosure.
        </p>

        <h3>Data Sharing</h3>
        <p>
        SurveyCash does not sell personal information. Limited information may be shared
        with trusted partners only when necessary to provide surveys, offers, or rewards.
        </p>

        <h3>Cookies</h3>
        <p>
        SurveyCash may use cookies or similar technologies to improve user experience,
        analyze platform usage, and prevent fraudulent activity.
        </p>

        <h3>Policy Updates</h3>
        <p>
        This Privacy Policy may be updated from time to time. Continued use of the
        platform after updates indicates acceptance of the revised policy.
        </p>

        <h3>Contact</h3>
        <p>
        contact@surveycash.website
        </p>
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
          body { font-family: Arial; padding: 40px; background:#0f172a; color:#e5e7eb; line-height:1.6; }
          h1 { color:#facc15; }
          h3 { color:#facc15; margin-top:28px; }
          p { max-width:800px; }
        </style>
      </head>
      <body>
        <h1>Terms of Service</h1>

        <p><strong>Last updated: March 2026</strong></p>

        <p>
        By accessing or using SurveyCash, you agree to comply with these Terms of Service.
        </p>

        <h3>Use of the Platform</h3>
        <p>
        SurveyCash allows users to earn rewards by completing surveys and partner offers.
        Users must provide accurate information and use the platform fairly and honestly.
        </p>

        <h3>Eligibility</h3>
        <p>
        Users must be at least 18 years old to use SurveyCash. Only one account per person
        is allowed. The use of VPNs, proxies, bots, or multiple accounts to manipulate
        rewards is strictly prohibited.
        </p>

        <h3>Rewards and Credits</h3>
        <p>
        Rewards are granted only after confirmation from our survey and offer partners.
        SurveyCash reserves the right to adjust or revoke rewards if partner validation
        fails or suspicious activity is detected.
        </p>

        <h3>Fraud and Abuse</h3>
        <p>
        Any attempt to manipulate surveys, offers, or the reward system may result in
        account suspension, termination, and loss of rewards. This includes the use of
        VPNs, bots, multiple accounts, or other fraudulent methods.
        </p>

        <h3>Third-Party Providers</h3>
        <p>
        SurveyCash works with third-party survey and offer providers. We are not responsible
        for survey availability, qualification decisions, offer availability, or technical
        issues originating from these partners.
        </p>

        <h3>Account Responsibility</h3>
        <p>
        Users are responsible for maintaining the security of their accounts and login
        credentials.
        </p>

        <h3>Changes to Terms</h3>
        <p>
        SurveyCash may update these Terms at any time. Continued use of the platform
        constitutes acceptance of the updated Terms.
        </p>

        <h3>Contact</h3>
        <p>
        contact@surveycash.website
        </p>
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

  const extUserId = String(user.id || user.email || '').trim();
  if (!extUserId) return res.redirect('/');

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

  res.setHeader(
    'Content-Security-Policy',
    [
      "default-src 'self' https: data:;",
      "script-src 'self' 'unsafe-inline' 'unsafe-eval' https:;",
      "style-src 'self' 'unsafe-inline' https:;",
      "img-src 'self' https: data:;",
      "connect-src 'self' https:;",
      "frame-src https://offers.cpx-research.com https:;",
    ].join(' ')
  );

  res.send(`<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>CPX Surveys</title>
  <style>
    :root{
      --header-h:56px;
      --bg:#0f172a;
      --panel:#0b1430;
      --line:rgba(255,255,255,.08);
      --text:#e5e7eb;
      --muted:#94a3b8;
      --accent:#fbbf24;
    }

    *{ box-sizing:border-box; }

    html, body{
      margin:0;
      padding:0;
      width:100%;
      height:100%;
      background:var(--bg);
      overflow:hidden;
      font-family:Inter, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
    }

    .top{
      position:fixed;
      top:0;
      left:0;
      right:0;
      height:var(--header-h);
      display:flex;
      align-items:center;
      gap:12px;
      padding:0 14px;
      background:rgba(11,20,48,.96);
      border-bottom:1px solid var(--line);
      color:var(--text);
      z-index:20;
      backdrop-filter:blur(8px);
    }

    .back{
      color:var(--accent);
      text-decoration:none;
      font-weight:800;
      font-size:14px;
      display:inline-flex;
      align-items:center;
      gap:6px;
    }

    .title{
      font-weight:800;
      font-size:16px;
      color:var(--text);
    }

    .frame-wrap{
      position:fixed;
      top:var(--header-h);
      left:0;
      right:0;
      bottom:0;
      background:var(--bg);
    }

    iframe{
      position:absolute;
      inset:0;
      width:100%;
      height:100%;
      border:0;
      display:block;
      background:#fff;
    }
  </style>
</head>
<body>
  <div class="top">
    <a class="back" href="/">← Back</a>
    <div class="title">CPX Surveys</div>
  </div>

  <div class="frame-wrap">
    <iframe
      src="${iframeUrl}"
      allow="clipboard-read; clipboard-write; fullscreen"
    ></iframe>
  </div>
</body>
</html>`);
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


async function createNotification(userId, kind, title, body) {
  try {
    if (!userId || !title || !body) return;

    const { error } = await supabaseAdmin
      .from('notifications')
      .insert({
        user_id: userId,
        kind,
        title,
        body,
      });

    if (error) {
      console.error('createNotification error:', error);
    }
  } catch (err) {
    console.error('createNotification catch error:', err);
  }
}


app.get('/api/notifications', async (req, res) => {
  try {
    if (!isLoggedIn(req)) return res.json([]);

    const user = getUserFromReq(req);
    if (!user?.id) return res.json([]);

    const { data, error } = await supabaseAdmin
      .from('notifications')
      .select('id, kind, title, body, is_read, created_at')
      .eq('user_id', user.id)
      .order('created_at', { ascending: false })
      .limit(20);

    if (error) {
      console.error('notifications fetch error:', error);
      return res.json([]);
    }

    return res.json(data || []);
  } catch (err) {
    console.error('notifications route error:', err);
    return res.json([]);
  }
});

app.post('/api/notifications/read', async (req, res) => {
  try {
    if (!isLoggedIn(req)) return res.json({ ok: false });

    const user = getUserFromReq(req);
    if (!user?.id) return res.json({ ok: false });

    const { error } = await supabaseAdmin
      .from('notifications')
      .update({ is_read: true })
      .eq('user_id', user.id)
      .eq('is_read', false);

    if (error) {
      console.error('notifications read update error:', error);
      return res.json({ ok: false });
    }

    return res.json({ ok: true });
  } catch (err) {
    console.error('notifications read route error:', err);
    return res.json({ ok: false });
  }
});


app.post('/api/notifications/remove', async (req, res) => {
  try {
    if (!isLoggedIn(req)) return res.json({ ok: false });

    const user = getUserFromReq(req);
    if (!user?.id) return res.json({ ok: false });

    const id = Number(req.body?.id || 0);
    if (!id) return res.json({ ok: false });

    const { error } = await supabaseAdmin
      .from('notifications')
      .delete()
      .eq('id', id)
      .eq('user_id', user.id);

    if (error) {
      console.error('notifications remove error:', error);
      return res.json({ ok: false });
    }

    return res.json({ ok: true });
  } catch (err) {
    console.error('notifications remove route error:', err);
    return res.json({ ok: false });
  }
});

app.get('/cpx/postback', async (req, res) => {
  try {
    const token = String(req.query.token || '');
    if (token !== process.env.CPX_POSTBACK_TOKEN) {
      return res.status(200).send('ok');
    }

    const q = req.query || {};

    const statusRaw = String(q.status || q.state || '').toLowerCase().trim();
    const transId = String(q.trans_id || q.transaction_id || q.sid || q.subid || '').trim();
    const userId = String(q.user_id || q.ext_user_id || q.uid || '').trim();
    const type = String(q.type || 'complete').toLowerCase().trim();

    const amountRaw =
      q.amount_usd ??
      q.amount_local ??
      q.amount ??
      q.reward ??
      q.payout ??
      q.value ??
      '0';

    const amount = Number(String(amountRaw).replace(',', '.')) || 0;

    if (!transId || !userId) {
      return res.status(200).send('ok');
    }

    const isCredit =
      statusRaw === '1' ||
      statusRaw === 'approved' ||
      statusRaw === 'completed' ||
      statusRaw === 'ok';

    const isReversal =
      statusRaw === '2' ||
      statusRaw === 'reversed' ||
      statusRaw === 'chargeback' ||
      statusRaw === 'canceled' ||
      statusRaw === 'cancelled';

    const profile = await findProfileByUserIdOrEmailSupabase(userId);
    if (!profile) {
      return res.status(200).send('ok');
    }

    const cents = Math.round(Math.max(0, amount) * 100);

    const currentBalance = Number(profile.balance_cents || 0);
    const currentTotal = Number(profile.total_earned_cents || 0);
    const currentSurveys = Number(profile.completed_surveys || 0);

    if (isCredit) {
      const { error: insErr } = await supabaseAdmin
        .from('cpx_transactions')
        .insert({
          user_id: profile.user_id,
          trans_id: transId,
          type,
          cents,
          status: 1,
        });

      if (insErr && insErr.code !== '23505') {
        console.error('cpx_transactions insert error:', insErr);
        return res.status(200).send('ok');
      }

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

        if (upErr) {
          console.error('CPX credit update error:', upErr);
        } else {
          let body = `You earned $${(cents / 100).toFixed(2)} from a CPX survey.`;

          if (type === 'out') {
            body = `You earned $${(cents / 100).toFixed(2)} from a CPX screenout.`;
          } else if (type && !type.includes('complete')) {
            body = `You earned $${(cents / 100).toFixed(2)} from CPX (${type}).`;
          }

          await createNotification(
            profile.user_id,
            'reward',
            'Survey reward',
            body
          );
        }
      }

      return res.status(200).send('ok');
    }

    if (isReversal) {
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

          if (upErr) {
            console.error('CPX reversal update error:', upErr);
          } else {
            await createNotification(
              profile.user_id,
              'reward_reversal',
              'Survey reward reversed',
              `A CPX reward of $${(revCents / 100).toFixed(2)} was reversed.`
            );
          }
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

    const userId = String(req.query.userId || '').trim();
    const amount = Number(req.query.amount || req.query.payout || 0);
    const status = String(req.query.status || 'completed').toLowerCase().trim();
    const transId = String(req.query.transactionId || req.query.trans_id || req.query.id || '').trim();

    if (!userId) {
      console.log('No userId in postback');
      return res.status(200).send('Missing userId');
    }

    if (amount <= 0) {
      console.log('Zero payout, skipping');
      return res.status(200).send('No reward');
    }

    const { data: profile, error: profErr } = await supabaseAdmin
      .from('profiles')
      .select('user_id, balance_cents, total_earned_cents, completed_offers')
      .eq('user_id', userId)
      .single();

    if (profErr || !profile) {
      console.log('User not found:', userId);
      return res.status(200).send('User not found');
    }

    const cents = Math.round(amount * 100);
    const currentBalance = Number(profile.balance_cents || 0);
    const currentTotal = Number(profile.total_earned_cents || 0);
    const currentOffers = Number(profile.completed_offers || 0);

    if (transId) {
      const { data: existing } = await supabaseAdmin
        .from('wannads_transactions')
        .select('id')
        .eq('trans_id', transId)
        .maybeSingle();

      if (existing) {
        console.log('Duplicate Wannads transaction:', transId);
        return res.status(200).send('Duplicate ignored');
      }

      const { error: insErr } = await supabaseAdmin
        .from('wannads_transactions')
        .insert({
          user_id: userId,
          trans_id: transId,
          type: status || 'completed',
          cents,
          status: 1,
        });

      if (insErr) {
        console.error('wannads_transactions insert error:', insErr);
        return res.status(200).send('Insert failed');
      }
    }

    const { error: upErr } = await supabaseAdmin
      .from('profiles')
      .update({
        balance_cents: currentBalance + cents,
        total_earned_cents: currentTotal + cents,
        completed_offers: currentOffers + 1,
      })
      .eq('user_id', userId);

    if (upErr) {
      console.error('Wannads balance update error:', upErr);
      return res.status(200).send('Update failed');
    }

    await createNotification(
      userId,
      'reward',
      'Offer reward',
      `You earned $${amount.toFixed(2)} from a Wannads offer.`
    );

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
  const err = String(req.query.err || '');

  let profile;
  try {
    profile = await getProfileByUserId(user.id);
  } catch (e) {
    console.error('getProfileByUserId error:', e);
    return res.redirect('/');
  }

  const balanceCents = Number(profile.balance_cents || 0);
  const pendingCents = Number(profile.pending_cents || 0);

  let hasOpenWithdrawal = false;
  let openWithdrawalEmail = '';

  try {
    const { data, error } = await supabaseAdmin
      .from('withdrawals')
      .select('id,status,paypal_email')
      .eq('user_id', user.id)
      .in('status', ['pending', 'processing'])
      .order('id', { ascending: false })
      .limit(1);

    if (!error && Array.isArray(data) && data.length > 0) {
      hasOpenWithdrawal = true;
      openWithdrawalEmail = data[0].paypal_email || '';
    }
  } catch (e) {
    console.error('open withdrawal check (GET /cashout) failed:', e);
  }

  let msg = '';
  if (ok) {
    msg = `<div class="notice success">Cash out request received. We will process it manually.</div>`;
  } else if (err === 'open') {
    msg = `<div class="notice error">You already have a cashout in progress.</div>`;
  } else if (err) {
    msg = `<div class="notice error">Cash out failed.</div>`;
  } else if (hasOpenWithdrawal) {
    msg = `<div class="notice success">Cash out status: <b>PROCESSING</b>…</div>`;
  }

  const paypalImg = '/img/paypal.png';

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
          html, body{
            min-height:100%;
            margin:0;
            overflow-x:hidden;
            background:#111827;
          }

          body{
            margin:0;
          }

          main,
          .container,
          .page,
          .content{
            margin-left:0 !important;
            margin-right:0 !important;
            max-width:none !important;
          }

          main{
            position:relative;
            max-width:none !important;
            margin:0 !important;
            padding:0 !important;
            background:#111827;
          }

          .cashout-page{
            position:relative;
            width:100%;
            box-sizing:border-box;
            background:#111827;
          }

          .cashout-area{
            background:#111827;
            padding:24px 0 220px;
          }

          .cashout-wrap{
            width:1080px;
            max-width:1080px;
            margin:0 auto;
            padding:0 14px;
            box-sizing:border-box;
          }

          .cashout-head,
          .cashout-section{
            position:relative;
            z-index:2;
          }

          .cashout-head{
            display:flex;
            flex-direction:column;
            align-items:flex-start;
            gap:12px;
            margin-bottom:14px;
          }

          .cashout-head h1{
            font-size:52px;
            font-weight:900;
            margin:0;
            line-height:1;
            letter-spacing:.5px;
            color:#ffffff;
          }

          .cash-accent{
            color:#eab308;
          }

          .my-payments-btn{
            display:inline-flex;
            align-items:center;
            justify-content:center;
            padding:11px 24px;
            border-radius:8px;
            background:#eab308;
            color:#0b1220;
            font-weight:700;
            font-size:14px;
            letter-spacing:.2px;
            text-decoration:none;
            border:1px solid rgba(234,179,8,.6);
            transition:.15s ease;
            cursor:pointer;
          }

          .my-payments-btn:hover{
            background:#d4a006;
            transform:translateY(-1px);
          }

          .my-payments-btn:active{
            transform:translateY(0);
          }

          .cashout-topbar{
            display:flex;
            align-items:center;
            justify-content:flex-start;
            gap:18px;
            width:auto;
            margin-top:0;
            flex-wrap:wrap;
          }

          .cashout-balances{
            display:flex;
            align-items:center;
            gap:24px;
            color:#ffffff;
            font-weight:600;
            font-size:14px;
            opacity:.9;
            flex-wrap:wrap;
          }

          .payout-pending-box{
            position:absolute;
            right:0;
            top:8px;
            width:360px;
            padding:28px;
            border-radius:16px;
            background:rgba(34,197,94,.08);
            border:1px solid rgba(34,197,94,.45);
            color:#e5e7eb;
          }

          .payout-title{
            font-size:18px;
            font-weight:800;
            margin-bottom:10px;
          }

          .payout-text{
            font-size:14px;
            color:#cbd5e1;
            line-height:1.5;
          }

          .cashout-section{
            margin-top:4px;
          }

          .methods-grid{
            margin-top:10px;
            display:grid;
            grid-template-columns:repeat(3, 250px);
            justify-content:flex-start;
            gap:22px;
          }

          .method-card{
            width:250px;
            height:210px;
            cursor:pointer;
            border-radius:20px;
            padding:14px 16px 16px;
            background:#151c2e;
            border:1px solid rgba(255,255,255,.08);
            color:#fff;
            transition:.15s ease;
            display:flex;
            flex-direction:column;
            align-items:center;
            text-align:center;
          }

          .method-card:hover{
            transform:translateY(-3px);
            border-color:rgba(255,255,255,.18);
          }

          .method-card.paypal:hover{
            border-color:rgba(34,197,94,.85);
            box-shadow:0 14px 50px rgba(34,197,94,.16);
          }

          .method-card.placeholder{
            opacity:.6;
            cursor:not-allowed;
          }

          .method-card.placeholder:hover{
            transform:none;
            box-shadow:none;
          }

          .method-title{
            font-weight:800;
            font-size:14px;
            letter-spacing:.3px;
            margin:0 0 8px;
            margin-top:-4px;
            opacity:.9;
          }

          .paypal-dark{
            color:#003087;
          }

          .paypal-light{
            color:#009cde;
          }

          .method-subtext{
            font-size:12px;
            color:#ffffff;
            margin-top:4px;
            font-weight:700;
            opacity:0.9;
          }

          .method-logo-tile{
            background:transparent;
            border:0;
            padding:0;
            display:flex;
            align-items:center;
            justify-content:center;
            margin-top:2px;
            margin-bottom:4px;
          }

          .method-logo-tile img{
            width:240px;
            max-width:100%;
            height:auto;
          }

          .soon-wrap{
            width:100%;
            text-align:center;
          }

          .soon-top{
            font-weight:900;
            margin-bottom:10px;
            font-size:16px;
          }

          .soon-pill{
            display:inline-block;
            font-size:13px;
            padding:7px 16px;
            border-radius:999px;
            background:rgba(255,255,255,.06);
            border:1px solid rgba(255,255,255,.10);
            color:#cbd5e1;
          }

          .cashout-bottom-fill{
            position:fixed;
            left:50%;
            transform:translateX(-50%);
            bottom:0;
            width:100vw;
            height:220px;
            background:#151c2e;
            border-top:1px solid rgba(255,255,255,.04);
            z-index:0;
            pointer-events:none;
          }

          .cashout-footer-content{
            position:fixed;
            left:50%;
            transform:translateX(-50%);
            bottom:0;
            width:100vw;
            height:220px;
            z-index:1;
            display:flex;
            justify-content:center;
            box-sizing:border-box;
            pointer-events:none;
          }

          .cashout-footer-inner{
            width:100%;
            max-width:1280px;
            padding:26px 36px 0;
            display:grid;
            grid-template-columns:1.7fr 1fr 1fr 1fr 1fr;
            gap:36px;
            box-sizing:border-box;
            pointer-events:auto;
          }

          .footer-brand{
            display:flex;
            flex-direction:column;
            align-items:flex-start;
          }

          .footer-logo{
            font-size:22px;
            font-weight:900;
            line-height:1;
            color:#fff;
            margin-bottom:18px;
          }

          .footer-logo .white{
            color:#ffffff;
          }

          .footer-logo .accent{
            color:#fbbf24;
          }

          .footer-brand-text{
            max-width:380px;
            color:rgba(255,255,255,.62);
            font-size:14px;
            line-height:1.55;
            margin-bottom:18px;
          }

          .footer-trust{
            display:flex;
            align-items:center;
          }

          .footer-trust-link{
            display:flex;
            align-items:center;
            gap:10px;
            color:#ffffff;
            text-decoration:none;
            font-size:12px;
            font-weight:700;
          }

          .footer-trust-img{
            height:42px;
            width:auto;
            display:block;
          }

          .footer-trust-link:hover{
            text-decoration:underline;
          }

          .footer-trust-link span{
            font-size:14px;
          }

          .footer-col-title{
            color:#fbbf24;
            font-size:16px;
            font-weight:900;
            margin:0 0 22px;
          }

          .footer-link{
            display:block;
            color:#ffffff;
            text-decoration:none;
            font-size:15px;
            font-weight:700;
            margin-bottom:22px;
            opacity:.95;
          }

          .footer-link:hover{
            opacity:1;
          }

          @media (min-width:1101px){
            .cashout-wrap{
              margin-left:24px;
              margin-right:0;
            }
          }

          @media (min-width:761px){
            html, body{
              overflow:hidden;
            }

            main{
              height:calc(100vh - 64px);
              overflow:hidden;
            }
          }

          @media (max-width:1200px){
            .cashout-footer-inner{
              grid-template-columns:1.7fr 1fr 1fr 1fr;
              gap:28px;
            }

            .footer-col.social{
              display:none;
            }
          }

          @media (max-width:1100px){
            .cashout-wrap{
              width:100%;
              max-width:100%;
            }

            .methods-grid{
              grid-template-columns:repeat(2, 250px);
            }

            .cashout-footer-inner{
              grid-template-columns:1.5fr 1fr 1fr;
              gap:28px;
            }

            .footer-col.legal{
              display:none;
            }

            .payout-pending-box{
              right:14px;
            }
          }

          @media (max-width:760px){
            html, body, main, .cashout-page, .cashout-area{
              background:#111827;
            }

            html, body{
              min-height:0;
              height:auto;
              overflow-x:hidden !important;
              overflow-y:auto !important;
            }

            main{
              min-height:auto !important;
              height:auto !important;
              max-height:none !important;
              overflow:visible !important;
            }

            .cashout-area{
              padding:20px 0 0;
            }

            .cashout-wrap{
              width:100%;
              max-width:100%;
              padding:0 10px;
              box-sizing:border-box;
            }

            .cashout-page{
              min-height:auto !important;
              height:auto !important;
              overflow:visible !important;
              margin:0 !important;
              padding:0 !important;
            }

            .cashout-bottom-fill{
              display:none;
            }

            .cashout-footer-content{
              position:relative;
              left:auto;
              transform:none;
              bottom:auto;
              width:100%;
              height:auto;
              display:block;
              margin-top:18px;
              padding:16px 0 12px;
              background:#151c2e;
              border-top:1px solid rgba(255,255,255,.04);
            }

            .cashout-footer-inner{
              width:100%;
              max-width:100%;
              padding:0 14px 8px;
              display:grid;
              grid-template-columns:1fr 1fr 1fr;
              gap:18px;
              box-sizing:border-box;
              align-items:start;
            }

            .footer-brand{
              grid-column:1 / -1;
            }

            .footer-logo{
              font-size:18px;
              margin-bottom:10px;
            }

            .footer-brand-text{
              max-width:none;
              font-size:12px;
              line-height:1.45;
              margin-bottom:10px;
            }

            .footer-trust-link{
              gap:8px;
            }

            .footer-trust-link span{
              font-size:12px;
            }

            .footer-trust-img{
              height:24px;
            }

            .footer-col-title{
              font-size:14px;
              margin:0 0 10px;
            }

            .footer-link{
              font-size:13px;
              margin-bottom:10px;
            }

            .footer-col:nth-of-type(2){
              display:none;
            }

            .footer-col.legal,
            .footer-col.social{
              display:block;
            }

            .cashout-head h1{
              font-size:40px;
            }

            .cashout-topbar{
              gap:12px;
            }

            .my-payments-btn{
              padding:9px 18px;
              font-size:13px;
              border-radius:8px;
            }

            .cashout-balances{
              gap:14px;
              font-size:13px;
            }

            .payout-pending-box{
              position:relative;
              right:auto;
              top:auto;
              width:100%;
              max-width:none;
              margin:10px 0 16px;
              padding:18px;
            }

            .payout-title{
              font-size:16px;
            }

            .payout-text{
              font-size:13px;
            }

            .methods-grid{
              grid-template-columns:repeat(2, minmax(0, 1fr));
              gap:14px;
              width:100%;
            }

.method-card{
  width:86%;
  height:160px;
  padding:10px 12px 10px;
  border-radius:16px;
  margin:0 auto;
}

            .method-title{
              font-size:13px;
              margin-bottom:6px;
            }

            .method-logo-tile img{
              width:170px;
              max-width:100%;
            }

            .method-subtext{
              font-size:11px;
            }

            .soon-top{
              font-size:15px;
              margin-bottom:8px;
            }

            .soon-pill{
              font-size:11px;
              padding:6px 12px;
            }
          }

          @media (max-width:560px){
            .cashout-wrap{
              padding:0 10px;
            }

            .cashout-footer-inner{
              grid-template-columns:1fr 1fr 1fr;
              gap:14px;
              padding:0 12px 8px;
            }

            .footer-brand{
              grid-column:1 / -1;
            }

            .footer-logo{
              font-size:17px;
            }

            .footer-brand-text{
              font-size:11px;
              line-height:1.4;
            }

            .footer-col-title{
              font-size:13px;
            }

            .footer-link{
              font-size:12px;
              margin-bottom:8px;
            }

            .footer-trust-link span{
              font-size:11px;
            }

            .footer-trust-img{
              height:22px;
            }

            .footer-col:nth-of-type(2){
              display:none;
            }

            .footer-col.legal,
            .footer-col.social{
              display:block;
            }

            .cashout-head h1{
              font-size:34px;
            }

            .my-payments-btn{
              padding:8px 14px;
              font-size:12px;
            }

            .cashout-balances{
              gap:10px;
              font-size:12px;
            }

            .payout-pending-box{
              padding:14px;
            }

            .payout-title{
              font-size:14px;
            }

            .payout-text{
              font-size:12px;
            }

            .methods-grid{
              gap:10px;
            }

.method-card{
  width:86%;
  height:135px;
  padding:8px 10px 8px;
  border-radius:14px;
  margin:0 auto;
}

            .method-title{
              font-size:12px;
            }

            .method-logo-tile img{
              width:125px;
            }

            .method-subtext{
              font-size:10px;
            }

            .soon-top{
              font-size:13px;
            }

            .soon-pill{
              font-size:10px;
              padding:5px 10px;
            }
          }

          /* ===== Backdrops ===== */
          .co-backdrop{
            position:fixed;
            inset:0;
            background:rgba(0,0,0,.55);
            display:none;
            align-items:center;
            justify-content:center;
            padding:16px;
          }

          .co-backdrop.open{ display:flex; }

          #coBackdrop{ z-index:9999; }
          #confirmBackdrop{ z-index:10000; }

          .co-modal{
            width:min(640px, 100%);
            background:#0b1220;
            border:1px solid rgba(255,255,255,.08);
            border-radius:18px;
            padding:14px 14px 10px;
            box-shadow:0 40px 140px rgba(0,0,0,.65);
            position:relative;
          }

          .co-close{
            position:absolute;
            top:10px;
            right:10px;
            width:36px;
            height:36px;
            border-radius:999px;
            background:rgba(255,255,255,.06);
            border:1px solid rgba(255,255,255,.10);
            color:#fff;
            cursor:pointer;
          }

          .co-header{
            display:flex;
            gap:10px;
            align-items:center;
            padding:4px 4px 8px;
          }

          .co-title{
            font-weight:900;
            font-size:17px;
          }

          .co-divider{
            height:1px;
            background:rgba(255,255,255,.08);
            margin:8px 0;
          }

          .co-block-title{
            font-weight:800;
            margin:2px 0 8px;
          }

          .amount-grid{
            display:grid;
            grid-template-columns:repeat(3, minmax(0, 1fr));
            gap:10px;
          }

          @media (max-width:760px){
            .amount-grid{
              grid-template-columns:repeat(2,minmax(0,1fr));
            }
          }

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

          .amount-card:hover{ border-color:#22c55e; box-shadow:0 0 0 1px #22c55e; }
          .amount-card.active{ border-color:#22c55e; box-shadow:0 0 0 2px #22c55e; }

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

          .amount-card.disabled{
            opacity:.45;
            cursor:not-allowed;
            transform:none !important;
          }

          .amount-card .amt{
            font-weight:900;
            font-size:15px;
          }

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

          .co-actions{
            display:flex;
            flex-direction:column;
            align-items:center;
            gap:14px;
            margin-top:14px;
          }

          .withdraw-btn{
            height:48px;
            width:300px;
            max-width:100%;
            margin:0 auto;
            border-radius:15px;
            border:1px solid rgba(251,191,36,.35);
            background:#fbbf24;
            color:#0b1220;
            font-weight:900;
            font-size:14px;
            letter-spacing:.2px;
            cursor:pointer;
            transition:.2s ease;
          }

          .withdraw-btn:hover:not(:disabled){
            transform:translateY(-2px);
            box-shadow:none;
          }

          .withdraw-btn:disabled{
            opacity:.45;
            cursor:not-allowed;
            background:rgba(251,191,36,.18);
            color:#fbbf24;
          }

          @media (max-width:520px){
            .withdraw-btn{ width:100%; }
          }

@media (max-width:520px){
  .co-backdrop{
    padding:10px;
    align-items:flex-start;
    padding-top:72px;
    overflow-y:auto;
  }

  .co-modal{
    width:92%;
    max-width:92%;
    padding:12px 10px 10px;
    border-radius:16px;
  }

  .amount-grid{
    grid-template-columns:repeat(2, minmax(0, 1fr));
    gap:8px;
  }

  .amount-card{
    padding:8px;
    border-radius:14px;
    min-height:116px;
  }

  .amount-card .brand{
    min-height:56px;
  }

  .amount-card .brand img{
    width:135px;
  }
}

          .co-confirm{
            width:min(640px, 100%);
            background:#0b1220;
            border:1px solid rgba(255,255,255,.08);
            border-radius:18px;
            padding:14px 14px 10px;
            box-shadow:0 40px 140px rgba(0,0,0,.65);
            position:relative;
            max-height:calc(100vh - 60px);
            overflow:auto;
          }

          .co-field-label{
            font-weight:800;
            margin:8px 0 6px;
            color:#cbd5e1;
          }

          .co-input{
            width:100%;
            height:44px;
            border-radius:10px;
            border:1px solid rgba(255,255,255,.10);
            background:rgba(255,255,255,.03);
            color:#fff;
            padding:0 12px;
            outline:none;
          }

          .co-help{
            margin-top:10px;
            padding:10px 12px;
            border-radius:10px;
            background:rgba(59,130,246,.08);
            border:1px solid rgba(59,130,246,.22);
            color:#cfe6ff;
            font-size:13px;
          }

          .co-rows{
            margin-top:12px;
            border-top:1px solid rgba(255,255,255,.08);
            padding-top:12px;
            display:flex;
            flex-direction:column;
            gap:10px;
          }

          .co-row{
            display:flex;
            justify-content:space-between;
            align-items:center;
            color:#cbd5e1;
            font-size:14px;
          }

          .co-row strong{ color:#fff; }

          .co-receive{
            margin-top:12px;
            padding-top:12px;
            border-top:1px solid rgba(255,255,255,.08);
            display:flex;
            justify-content:space-between;
            align-items:center;
            font-size:18px;
            font-weight:900;
            color:#fff;
          }

          .co-checks{
            margin-top:14px;
            display:flex;
            flex-direction:column;
            gap:10px;
            color:#cbd5e1;
            font-size:14px;
          }

          .co-checks input{ transform:translateY(1px); }

          .co-confirm-actions{
            margin-top:16px;
            display:flex;
            flex-direction:column;
            gap:10px;
          }

          .btn-confirm{
            height:52px;
            border-radius:14px;
            border:1px solid rgba(251,191,36,.35);
            background:#fbbf24;
            color:#0b1220;
            font-weight:900;
            cursor:pointer;
          }

          .btn-confirm:disabled{
            opacity:.45;
            cursor:not-allowed;
            background:rgba(251,191,36,.18);
            color:#fbbf24;
          }


@media (max-width:520px){
.co-confirm{
  width:92%;
  max-width:92%;
    max-height:calc(100vh - 90px);
    padding:12px 10px 10px;
    border-radius:16px;
    overflow:auto;
  }

  .co-field-label{
    font-size:14px;
  }

.co-input{
  height:40px;
  font-size:16px;
}

  .co-help{
    font-size:12px;
    line-height:1.45;
    max-height:none;
    overflow:hidden;
    white-space:normal;
    word-break:normal;
    overflow-wrap:break-word;
  }

  .co-row{
    font-size:13px;
  }

  .co-receive{
    font-size:15px;
  }

  .co-checks{
    font-size:12px;
    line-height:1.35;
  }

  .btn-confirm{
    height:46px;
    font-size:13px;
  }
}


          .payments-backdrop{
            position:fixed;
            inset:0;
            background:rgba(0,0,0,.55);
            display:none;
            align-items:center;
            justify-content:center;
            padding:16px;
            z-index:10001;
          }

          .payments-backdrop.open{
            display:flex;
          }

          .payments-modal{
            width:min(760px, 100%);
            max-height:calc(100vh - 40px);
            overflow:auto;
            background:#0b1220;
            border:1px solid rgba(255,255,255,.08);
            border-radius:18px;
            padding:16px;
            box-shadow:0 40px 140px rgba(0,0,0,.65);
            position:relative;
          }

          .payments-close{
            position:absolute;
            top:10px;
            right:10px;
            width:36px;
            height:36px;
            border-radius:999px;
            background:rgba(255,255,255,.06);
            border:1px solid rgba(255,255,255,.10);
            color:#fff;
            cursor:pointer;
          }

          .payments-title{
            font-size:24px;
            font-weight:900;
            color:#fff;
            margin:0 0 4px;
          }

          .payments-subtitle{
            color:#94a3b8;
            font-size:14px;
            margin-bottom:14px;
          }

          .payments-tabs{
            display:flex;
            gap:10px;
            flex-wrap:wrap;
            margin-bottom:14px;
          }

          .payments-tab{
            border:1px solid rgba(255,255,255,.10);
            background:rgba(255,255,255,.04);
            color:#fff;
            border-radius:999px;
            padding:10px 14px;
            font-weight:800;
            cursor:pointer;
          }

          .payments-tab.active{
            background:#fbbf24;
            color:#0b1220;
            border-color:rgba(251,191,36,.45);
          }

          .payments-list{
            display:flex;
            flex-direction:column;
            gap:10px;
          }

          .payment-item{
            display:flex;
            justify-content:space-between;
            align-items:center;
            gap:14px;
            padding:14px;
            border-radius:14px;
            background:rgba(255,255,255,.03);
            border:1px solid rgba(255,255,255,.08);
          }

          .payment-left{
            min-width:0;
          }

          .payment-amount{
            color:#fff;
            font-size:18px;
            font-weight:900;
            margin-bottom:4px;
          }

          .payment-meta{
            color:#b8c4d6;
            font-size:13px;
            line-height:1.5;
          }

          .payment-status{
            min-width:100px;
            text-align:center;
            padding:8px 12px;
            border-radius:999px;
            font-size:12px;
            font-weight:900;
            text-transform:uppercase;
          }

          .payment-status.pending{
            background:rgba(251,191,36,.12);
            color:#fbbf24;
            border:1px solid rgba(251,191,36,.22);
          }

          .payment-status.paid{
            background:rgba(34,197,94,.12);
            color:#22c55e;
            border:1px solid rgba(34,197,94,.22);
          }

          .payment-status.failed{
            background:rgba(239,68,68,.12);
            color:#f87171;
            border:1px solid rgba(239,68,68,.22);
          }

          .payments-empty,
          .payments-loading,
          .payments-error{
            padding:16px;
            border-radius:14px;
            background:rgba(255,255,255,.03);
            border:1px solid rgba(255,255,255,.08);
            color:#cbd5e1;
          }


/* ===== Mobile fix for My Payments ===== */
@media (max-width:520px){

  .payments-backdrop{
    padding:10px;
    align-items:flex-start;
    padding-top:72px;
    overflow-y:auto;
  }

  .payments-modal{
    width:92%;
    max-width:92%;
    max-height:calc(100vh - 90px);
    padding:12px 10px 10px;
    border-radius:16px;
    overflow:auto;
  }

  .payments-title{
    font-size:22px;
    padding-right:40px;
  }

  .payments-subtitle{
    font-size:13px;
  }

  .payments-tabs{
    gap:8px;
  }

  .payments-tab{
    padding:8px 12px;
    font-size:13px;
  }

  .payment-item{
    display:block;
    padding:12px;
  }

  .payment-amount{
    font-size:20px;
  }

  .payment-meta{
    font-size:12px;
    word-break:break-word;
  }

  .payment-status{
    display:inline-block;
    margin-top:10px;
    padding:7px 12px;
    font-size:11px;
  }

}

        </style>

        <script>
          window.AVAILABLE_USD = ${formatUsdFromCents(balanceCents)};
          window.HAS_OPEN_WITHDRAWAL = ${hasOpenWithdrawal ? 'true' : 'false'};
        </script>

        <div class="cashout-page">
          <div class="cashout-area">
            <div class="cashout-wrap">

              <div class="cashout-head">
                <h1><span class="cash-accent">Cash</span>Out</h1>

                <div class="cashout-topbar">
                  <button type="button" id="openPaymentsBtn" class="my-payments-btn">My payments</button>

                  <div class="cashout-balances">
                    <span>Available: $${formatUsdFromCents(balanceCents)}</span>
                    <span>Pending: $${formatUsdFromCents(pendingCents)}</span>
                  </div>
                </div>
              </div>

              ${msg}

              ${hasOpenWithdrawal ? `
              <div class="payout-pending-box">
                <div class="payout-title">Payout pending</div>
                <div class="payout-text">
                  Rewards will be sent to <b>${escapeHtml(openWithdrawalEmail)}</b>
                </div>
              </div>
              ` : ``}

              <div class="cashout-section">
                <div class="methods-grid">

                  <button class="method-card paypal top ${hasOpenWithdrawal ? 'disabled' : ''}"
                          id="openPayPal"
                          type="button"
                          ${hasOpenWithdrawal ? 'disabled' : ''}>
                    <div class="method-title">
                      <span class="paypal-dark">Pay</span><span class="paypal-light">Pal</span>
                    </div>
                    <div class="method-logo-tile">
                      <img src="${paypalImg}" alt="PayPal" />
                    </div>

                    <div class="method-subtext">No fees</div>
                  </button>

                  <div class="method-card placeholder top">
                    <div class="method-title">More payout methods</div>
                    <div class="method-logo-tile">
                      <div class="soon-wrap">
                        <div class="soon-top">Soon</div>
                        <span class="soon-pill">Coming soon</span>
                      </div>
                    </div>
                  </div>

                  <div class="method-card placeholder">
                    <div class="method-title">More payout methods</div>
                    <div class="method-logo-tile">
                      <div class="soon-wrap">
                        <div class="soon-top">Soon</div>
                        <span class="soon-pill">Coming soon</span>
                      </div>
                    </div>
                  </div>

                  <div class="method-card placeholder">
                    <div class="method-title">More payout methods</div>
                    <div class="method-logo-tile">
                      <div class="soon-wrap">
                        <div class="soon-top">Soon</div>
                        <span class="soon-pill">Coming soon</span>
                      </div>
                    </div>
                  </div>

                  <div class="method-card placeholder">
                    <div class="method-title">More payout methods</div>
                    <div class="method-logo-tile">
                      <div class="soon-wrap">
                        <div class="soon-top">Soon</div>
                        <span class="soon-pill">Coming soon</span>
                      </div>
                    </div>
                  </div>

                  <div class="method-card placeholder">
                    <div class="method-title">More payout methods</div>
                    <div class="method-logo-tile">
                      <div class="soon-wrap">
                        <div class="soon-top">Soon</div>
                        <span class="soon-pill">Coming soon</span>
                      </div>
                    </div>
                  </div>

                </div>
              </div>

            </div>
          </div>

          <div class="cashout-bottom-fill"></div>

          <div class="cashout-footer-content">
            <div class="cashout-footer-inner">

              <div class="footer-brand">
                <div class="footer-logo"><span class="white">Survey</span><span class="accent">Cash</span></div>

                <div class="footer-brand-text">
                  SurveyCash is built to make earning simple. Complete surveys, explore offers and turn your time online into real rewards with quick payouts.
                </div>

                <div class="footer-trust">
                  <a href="https://www.trustpilot.com/review/surveycash.website" target="_blank" class="footer-trust-link">
                    <span>Rate us on Trustpilot</span>
                    <img src="/img/trustpilot-mission.png" class="footer-trust-img">
                  </a>
                </div>
              </div>

              <div class="footer-col">
                <div class="footer-col-title">SurveyCash</div>
                <a href="/" class="footer-link">Earn</a>
                <a href="/cashout" class="footer-link">Cash Out</a>
                <a href="/support" class="footer-link">Support</a>
              </div>

              <div class="footer-col">
                <div class="footer-col-title">Help</div>
                <a href="/support" class="footer-link">FAQ</a>
                <a href="/support" class="footer-link">Contact</a>
              </div>

              <div class="footer-col legal">
                <div class="footer-col-title">Info</div>
                <a href="/terms" class="footer-link">Terms</a>
                <a href="/privacy" class="footer-link">Privacy</a>
              </div>

              <div class="footer-col social">
                <div class="footer-col-title">Social</div>
                <a href="https://www.tiktok.com/@surveycashh?lang=da" target="_blank" rel="noopener noreferrer" class="footer-link">TikTok</a>
                <a href="https://x.com/SurveyCashh" target="_blank" rel="noopener noreferrer" class="footer-link">X</a>
              </div>

            </div>
          </div>

          <!-- ===== PayPal Amount Modal ===== -->
          <div class="co-backdrop" id="coBackdrop" aria-hidden="true">
            <div class="co-modal" role="dialog" aria-modal="true" aria-labelledby="coTitle">
              <button class="co-close" id="coClose" type="button" aria-label="Close">✕</button>

              <div class="co-header">
                <div>
                  <div class="co-title" id="coTitle">
                    <span class="paypal-dark">Pay</span><span class="paypal-light">Pal</span>
                  </div>
                </div>
              </div>

              <div class="co-divider"></div>

              <div class="co-block">
                <div class="co-block-title">Choose amount</div>
                <div class="amount-grid" id="amountGrid">
                  ${amountCardsHtml}
                </div>
              </div>

              <div class="co-divider"></div>

              <div class="co-actions">
                <button class="withdraw-btn" id="withdrawBtn" type="button" disabled>
                  Choose an amount
                </button>
              </div>
            </div>
          </div>

          <!-- ===== Confirm Modal ===== -->
          <div class="co-backdrop" id="confirmBackdrop" aria-hidden="true">
            <div class="co-confirm" role="dialog" aria-modal="true" aria-labelledby="confirmTitle">
              <button class="co-close" id="confirmClose" type="button" aria-label="Close">✕</button>

              <div class="co-header" style="padding:4px 4px 6px;">
                <div>
                  <div class="co-title" id="confirmTitle">
                    <span class="paypal-dark">Pay</span><span class="paypal-light">Pal</span>
                  </div>
                </div>
              </div>

              <div class="co-divider"></div>

              <div class="co-field-label">PayPal account*</div>

              <input class="co-input" id="paypalEmailInput" type="email"
                     value="" placeholder="Enter PayPal email" autocomplete="email" />

              <div class="co-field-label" style="margin-top:10px;">Confirm PayPal account*</div>

              <input class="co-input" id="paypalEmailConfirmInput" type="email"
                     value="" placeholder="Confirm PayPal email" autocomplete="email" />

              <div class="co-help">
                Your reward will be sent to this address. Make sure this email is linked to your PayPal account.
                <br><br>
                Payments are processed within <b>0-72 hours</b>.
              </div>

              <div class="co-rows">
                <div class="co-row">
                  <strong>Amount</strong>
                  <strong id="confirmAmount">$0.00</strong>
                </div>
              </div>

              <div class="co-receive">
                <span>You receive</span>
                <span id="confirmReceive">$0.00</span>
              </div>

              <div class="co-checks">
                <label><input type="checkbox" id="chk1"> I confirm this PayPal account can receive payments</label>
                <label><input type="checkbox" id="chk2"> I understand this order is non-refundable</label>
              </div>

              <form id="cashout-form" method="POST" action="/withdraw">
                <input type="hidden" name="amountCents" id="amountCents" value="" />
                <input type="hidden" name="paypalEmail" id="paypalEmailHidden" value="" />

                <div class="co-confirm-actions">
                  <button type="submit" class="btn-confirm" id="btnConfirm" disabled>Cash out</button>
                </div>
              </form>
            </div>
          </div>

          <div class="payments-backdrop" id="paymentsBackdrop" aria-hidden="true">
            <div class="payments-modal" role="dialog" aria-modal="true" aria-labelledby="paymentsTitle">
              <button class="payments-close" id="closePaymentsBtn" type="button" aria-label="Close">✕</button>

              <div class="payments-title" id="paymentsTitle">My payments</div>
              <div class="payments-subtitle">View your payout history</div>

              <div class="payments-tabs">
                <button type="button" class="payments-tab active" data-filter="all">All</button>
                <button type="button" class="payments-tab" data-filter="pending">Pending</button>
                <button type="button" class="payments-tab" data-filter="paid">Paid</button>
                <button type="button" class="payments-tab" data-filter="failed">Failed</button>
              </div>

              <div class="payments-list" id="paymentsList">
                <div class="payments-loading">Loading payments...</div>
              </div>
            </div>
          </div>

          <script>
          (function(){
            const availableUsd = Number(window.AVAILABLE_USD || 0);
            const hasOpen = !!window.HAS_OPEN_WITHDRAWAL;

            const openBtn = document.getElementById('openPayPal');
            const openPaymentsBtn = document.getElementById('openPaymentsBtn');
            const paymentsBackdrop = document.getElementById('paymentsBackdrop');
            const closePaymentsBtn = document.getElementById('closePaymentsBtn');
            const paymentsList = document.getElementById('paymentsList');
            const paymentsTabs = Array.from(document.querySelectorAll('.payments-tab'));

            let allPayments = [];
            let currentPaymentsFilter = 'all';

            const backdrop = document.getElementById('coBackdrop');
            const closeBtn = document.getElementById('coClose');
            const amountGrid = document.getElementById('amountGrid');
            const withdrawBtn = document.getElementById('withdrawBtn');

            const confirmBackdrop = document.getElementById('confirmBackdrop');
            const confirmClose = document.getElementById('confirmClose');
            const btnConfirm = document.getElementById('btnConfirm');

            const paypalEmailInput = document.getElementById('paypalEmailInput');
            const paypalEmailConfirmInput = document.getElementById('paypalEmailConfirmInput');
            const paypalEmailHidden = document.getElementById('paypalEmailHidden');
            const amountHidden = document.getElementById('amountCents');

            const confirmAmountEl = document.getElementById('confirmAmount');
            const confirmReceiveEl = document.getElementById('confirmReceive');
            const chk1 = document.getElementById('chk1');
            const chk2 = document.getElementById('chk2');

            let selectedCents = 0;
            const fmt = (n) => '$' + Number(n).toFixed(2);

            function openModal(){
              if(hasOpen) return;
              backdrop.classList.add('open');
              backdrop.setAttribute('aria-hidden','false');

              selectedCents = 0;
              withdrawBtn.disabled = true;
              withdrawBtn.textContent = 'Choose an amount';
              Array.from(amountGrid.querySelectorAll('.amount-card.active'))
                .forEach(x => x.classList.remove('active'));

              refreshBars();
              validateAmount();
            }

            function closeModal(){
              backdrop.classList.remove('open');
              backdrop.setAttribute('aria-hidden','true');
            }

            function openConfirm(){
              const amountUsd = selectedCents / 100;

              confirmAmountEl.textContent = fmt(amountUsd);
              confirmReceiveEl.textContent = fmt(amountUsd);

              amountHidden.value = String(selectedCents);

              paypalEmailInput.value = '';
              paypalEmailConfirmInput.value = '';
              paypalEmailHidden.value = '';

              chk1.checked = false;
              chk2.checked = false;
              btnConfirm.disabled = true;

              confirmBackdrop.classList.add('open');
              confirmBackdrop.setAttribute('aria-hidden','false');

              paypalEmailInput.focus();
            }

            function closeConfirm(){
              confirmBackdrop.classList.remove('open');
              confirmBackdrop.setAttribute('aria-hidden','true');
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

            function validateAmount(){
              if(selectedCents <= 0){
                withdrawBtn.disabled = true;
                withdrawBtn.textContent = 'Choose an amount';
                return;
              }

              const selectedUsd = selectedCents / 100;

              if(availableUsd < selectedUsd){
                withdrawBtn.disabled = true;
                withdrawBtn.textContent = 'Insufficient balance';
                return;
              }

              withdrawBtn.disabled = false;
              withdrawBtn.textContent = 'Cash out $' + selectedUsd.toFixed(2);
            }

            function emailValid(v){
              v = (v || '').trim();
              return /^[^\\s@]+@[^\\s@]+\\.[^\\s@]+$/.test(v);
            }

            function validateConfirm(){
              const e1 = (paypalEmailInput.value || '').trim();
              const e2 = (paypalEmailConfirmInput.value || '').trim();

              paypalEmailHidden.value = e1;

              const emailsMatch = e1 !== '' && e1 === e2;
              const ok = chk1.checked && chk2.checked && emailValid(e1) && emailValid(e2) && emailsMatch;

              btnConfirm.disabled = !ok;
            }

            function fmtDate(value){
              if(!value) return '-';
              const d = new Date(value);
              if (Number.isNaN(d.getTime())) return '-';
              return d.toLocaleString('en-GB');
            }

            function escapeClientHtml(str){
              return String(str || '')
                .replace(/&/g, '&amp;')
                .replace(/</g, '&lt;')
                .replace(/>/g, '&gt;')
                .replace(/"/g, '&quot;')
                .replace(/'/g, '&#39;');
            }

            function renderPayments(){
              let items = allPayments;

              if(currentPaymentsFilter !== 'all'){
                items = items.filter(p => String(p.status || '').toLowerCase() === currentPaymentsFilter);
              }

              if(!items.length){
                paymentsList.innerHTML = '<div class="payments-empty">No payments found.</div>';
                return;
              }

              paymentsList.innerHTML = items.map((p) => {
                const status = String(p.status || 'pending').toLowerCase();
                const amount = '$' + (Number(p.amount_cents || 0) / 100).toFixed(2);

                return ''
                  + '<div class="payment-item">'
                    + '<div class="payment-left">'
                      + '<div class="payment-amount">' + amount + '</div>'
                      + '<div class="payment-meta">'
                        + '<div>PayPal: ' + escapeClientHtml(p.paypal_email || '-') + '</div>'
                        + '<div>Created: ' + escapeClientHtml(fmtDate(p.created_at)) + '</div>'
                      + '</div>'
                    + '</div>'
                    + '<div class="payment-status ' + escapeClientHtml(status) + '">' + escapeClientHtml(status) + '</div>'
                  + '</div>';
              }).join('');
            }

            async function loadPayments(){
              paymentsList.innerHTML = '<div class="payments-loading">Loading payments...</div>';

              try {
                const res = await fetch('/api/payments', {
                  method: 'GET',
                  credentials: 'same-origin'
                });

                const data = await res.json();

                if(!res.ok || !data.ok){
                  paymentsList.innerHTML = '<div class="payments-error">Failed to load payments.</div>';
                  return;
                }

                allPayments = Array.isArray(data.payments) ? data.payments : [];
                renderPayments();
              } catch (err) {
                console.error('loadPayments error:', err);
                paymentsList.innerHTML = '<div class="payments-error">Failed to load payments.</div>';
              }
            }

            function openPaymentsModal(){
              paymentsBackdrop.classList.add('open');
              paymentsBackdrop.setAttribute('aria-hidden', 'false');
              loadPayments();
            }

            function closePaymentsModal(){
              paymentsBackdrop.classList.remove('open');
              paymentsBackdrop.setAttribute('aria-hidden', 'true');
            }

            if(openBtn) openBtn.addEventListener('click', openModal);
            if(closeBtn) closeBtn.addEventListener('click', closeModal);
            if(backdrop) backdrop.addEventListener('click', (e) => { if(e.target === backdrop) closeModal(); });

            if(confirmClose) confirmClose.addEventListener('click', closeConfirm);

            if(openPaymentsBtn) openPaymentsBtn.addEventListener('click', openPaymentsModal);
            if(closePaymentsBtn) closePaymentsBtn.addEventListener('click', closePaymentsModal);

            if(paymentsBackdrop){
              paymentsBackdrop.addEventListener('click', (e) => {
                if(e.target === paymentsBackdrop) closePaymentsModal();
              });
            }

            paymentsTabs.forEach((tab) => {
              tab.addEventListener('click', () => {
                paymentsTabs.forEach(x => x.classList.remove('active'));
                tab.classList.add('active');
                currentPaymentsFilter = String(tab.getAttribute('data-filter') || 'all').toLowerCase();
                renderPayments();
              });
            });

            window.addEventListener('keydown', (e) => {
              if(e.key === 'Escape'){
                if(confirmBackdrop.classList.contains('open')) closeConfirm();
                else if(backdrop.classList.contains('open')) closeModal();
                else if(paymentsBackdrop.classList.contains('open')) closePaymentsModal();
              }
            });

            if(amountGrid){
              amountGrid.addEventListener('click', (e) => {
                const card = e.target.closest('.amount-card');
                if(!card || card.disabled) return;

                Array.from(amountGrid.querySelectorAll('.amount-card.active'))
                  .forEach(x => x.classList.remove('active'));

                card.classList.add('active');
                selectedCents = Number(card.getAttribute('data-cents') || 0);
                validateAmount();
              });
            }

if(withdrawBtn){
  withdrawBtn.addEventListener('click', () => {
    if(withdrawBtn.disabled) return;
    closeModal();
    openConfirm();
  });
}

            if(chk1) chk1.addEventListener('change', validateConfirm);
            if(chk2) chk2.addEventListener('change', validateConfirm);
            if(paypalEmailInput) paypalEmailInput.addEventListener('input', validateConfirm);
            if(paypalEmailConfirmInput) paypalEmailConfirmInput.addEventListener('input', validateConfirm);

            refreshBars();
            validateAmount();
            validateConfirm();
          })();
          </script>
      `,
    })
  );
});


app.get('/api/payments', async (req, res) => {
  try {
    if (!isLoggedIn(req)) {
      return res.status(401).json({ ok: false, error: 'Not logged in' });
    }

    const user = req.user;
    if (!user?.id) {
      return res.status(401).json({ ok: false, error: 'User not found' });
    }

    const { data, error } = await supabaseAdmin
      .from('withdrawals')
      .select('id,status,paypal_email,amount_cents,created_at')
      .eq('user_id', user.id)
      .order('created_at', { ascending: false });

    if (error) {
      console.error('GET /api/payments error:', error);
      return res.status(500).json({ ok: false, error: 'Failed to load payments' });
    }

    return res.json({
      ok: true,
      payments: data || []
    });
  } catch (err) {
    console.error('GET /api/payments crash:', err);
    return res.status(500).json({ ok: false, error: 'Server error' });
  }
});


app.post('/withdraw', async (req, res) => {
  if (!isLoggedIn(req)) return res.redirect('/');

  try {
    const user = req.user;
    if (!user?.id) return res.redirect('/');

    const amountCents = Number(req.body.amountCents || 0);
    const paypalEmail = String(req.body.paypalEmail || '').trim().toLowerCase();

    if (!CASHOUT_ALLOWED_SET.has(amountCents)) {
      return res.redirect('/cashout?err=amount');
    }

    if (!isValidEmail(paypalEmail)) {
      return res.redirect('/cashout?err=email');
    }

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
      return res.redirect('/cashout?err=open');
    }

    const { data: profile, error: pErr } = await supabaseAdmin
      .from('profiles')
      .select('balance_cents, pending_cents')
      .eq('user_id', user.id)
      .single();

    if (pErr || !profile) {
      console.error('profile fetch error:', pErr);
      return res.redirect('/cashout?err=server');
    }

    const balance = Number(profile.balance_cents || 0);
    const pending = Number(profile.pending_cents || 0);

    if (balance < amountCents) {
      return res.redirect('/cashout?err=balance');
    }

    const { error: balErr } = await supabaseAdmin
      .from('profiles')
      .update({
        balance_cents: balance - amountCents,
        pending_cents: pending + amountCents,
      })
      .eq('user_id', user.id);

    if (balErr) {
      console.error('profile update error:', balErr);
      return res.redirect('/cashout?err=server');
    }

    const { error: wErr } = await supabaseAdmin
      .from('withdrawals')
      .insert({
        user_id: user.id,
        amount_cents: amountCents,
        paypal_email: paypalEmail,
        status: 'pending',
        error_text: null,
      });

    if (wErr) {
      console.error('withdraw insert error:', wErr);

      await supabaseAdmin
        .from('profiles')
        .update({
          balance_cents: balance,
          pending_cents: pending,
        })
        .eq('user_id', user.id);

      return res.redirect('/cashout?err=server');
    }

    return res.redirect('/cashout?ok=1');
  } catch (e) {
    console.error('manual withdraw error:', e);
    return res.redirect('/cashout?err=server');
  }
});


const ADMIN_EMAIL = 'surveycashweb@gmail.com';



app.get('/admin/withdrawals', async (req, res) => {
  if (!isLoggedIn(req) || req.user.email !== ADMIN_EMAIL) {
    return res.sendStatus(403);
  }

  const status = String(req.query.status || 'pending').toLowerCase();

  let query = supabaseAdmin
    .from('withdrawals')
    .select('*')
    .order('created_at', { ascending: false });

  if (status === 'pending') {
    query = query.in('status', ['pending', 'processing']);
  } else if (status === 'paid') {
    query = query.eq('status', 'paid');
  } else if (status === 'failed') {
    query = query.eq('status', 'failed');
  } else if (status === 'all') {
    // ingen ekstra filter
  } else {
    query = query.in('status', ['pending', 'processing']);
  }

  const { data, error } = await query;

  if (error) return res.status(500).send(error.message);

  function timeAgo(value) {
    if (!value) return '';
    const then = new Date(value).getTime();
    const now = Date.now();
    const diff = Math.max(0, now - then);

    const mins = Math.floor(diff / 60000);
    const hours = Math.floor(diff / 3600000);
    const days = Math.floor(diff / 86400000);

    if (mins < 1) return 'just now';
    if (mins < 60) return mins + ' min ago';
    if (hours < 24) return hours + ' hour' + (hours !== 1 ? 's' : '') + ' ago';
    return days + ' day' + (days !== 1 ? 's' : '') + ' ago';
  }

  const rows = (data || []).map((w) => `
    <tr>
      <td>${w.id}</td>
      <td>${escapeHtml(w.paypal_email || '')}</td>
      <td>$${formatUsdFromCents(Number(w.amount_cents || 0))}</td>
      <td>${escapeHtml(w.status || '')}</td>
      <td>${escapeHtml(String(w.created_at || ''))}<br><span style="opacity:.7;font-size:12px;">${timeAgo(w.created_at)}</span></td>
      <td>
        ${w.status === 'pending' || w.status === 'processing' ? `
          <form method="POST" action="/admin/withdrawals/${w.id}/paid" style="display:inline">
            <button type="submit">Mark paid</button>
          </form>
          <form method="POST" action="/admin/withdrawals/${w.id}/failed" style="display:inline; margin-left:8px;">
            <button type="submit">Mark failed</button>
          </form>
        ` : '-'}
      </td>
    </tr>
  `).join('');

  const filterLink = (value, label) => {
    const active = status === value ? 'font-weight:900;text-decoration:underline;' : '';
    return `<a href="/admin/withdrawals?status=${value}" style="margin-right:14px;${active}">${label}</a>`;
  };

  res.send(`
    <h1>Withdrawals</h1>

    <div style="margin-bottom:14px;">
      ${filterLink('pending', 'Pending')}
      ${filterLink('paid', 'Paid')}
      ${filterLink('failed', 'Failed')}
      ${filterLink('all', 'All')}
    </div>

    <table border="1" cellpadding="8" cellspacing="0">
      <tr>
        <th>ID</th>
        <th>PayPal email</th>
        <th>Amount</th>
        <th>Status</th>
        <th>Created</th>
        <th>Actions</th>
      </tr>
      ${rows || '<tr><td colspan="6">No withdrawals</td></tr>'}
    </table>
  `);
});


app.post('/admin/withdrawals/:id/paid', async (req, res) => {
  if (!isLoggedIn(req) || req.user.email !== ADMIN_EMAIL) {
    return res.sendStatus(403);
  }

  const id = Number(req.params.id);
  if (!id) return res.sendStatus(400);

  const { data: w, error: wErr } = await supabaseAdmin
    .from('withdrawals')
    .select('*')
    .eq('id', id)
    .single();

  if (wErr || !w) return res.sendStatus(404);

  await supabaseAdmin
    .from('withdrawals')
    .update({ status: 'paid', error_text: null })
    .eq('id', id);

  const { data: prof } = await supabaseAdmin
    .from('profiles')
    .select('pending_cents')
    .eq('user_id', w.user_id)
    .single();

  const pendingNow = Number(prof?.pending_cents || 0);
  const amount = Number(w.amount_cents || 0);

  await supabaseAdmin
    .from('profiles')
    .update({
      pending_cents: Math.max(0, pendingNow - amount),
    })
    .eq('user_id', w.user_id);

  res.redirect('/admin/withdrawals');
});



app.post('/admin/withdrawals/:id/failed', async (req, res) => {
  if (!isLoggedIn(req) || req.user.email !== ADMIN_EMAIL) {
    return res.sendStatus(403);
  }

  const id = Number(req.params.id);
  if (!id) return res.sendStatus(400);

  await supabaseAdmin
    .from('withdrawals')
    .update({
      status: 'failed',
      error_text: 'Manual payout failed',
    })
    .eq('id', id);

  await supabaseAdmin.rpc('fail_cashout_return_funds', {
    p_withdrawal_id: id,
  });

  res.redirect('/admin/withdrawals');
});




app.get('/support', (req, res) => {
  if (!isLoggedIn(req)) return res.redirect('/');

  const bodyHtml = `
  <style>
    html, body{
      height:100%;
      overflow:hidden;
      background:#111827;
    }

    body{
      margin:0;
    }

    main,
    .container,
    .page,
    .content{
      margin-left:0 !important;
      margin-right:0 !important;
      max-width:none !important;
    }

    main{
      position:relative;
      min-height:calc(100vh - 64px);
      padding-top:0 !important;
      background:#111827;
    }

    .support-page{
      position:relative;
      width:100%;
      min-height:calc(100vh - 64px);
      max-width:none;
      margin:0 !important;
      padding:24px 22px 260px;
      box-sizing:border-box;
      overflow:visible;

      display:flex;
      align-items:center;
      justify-content:center;
    }

    .support-shell{
      position:relative;
      z-index:2;
      display:grid;
      grid-template-columns:1.25fr .7fr;
      gap:18px;
      align-items:stretch;
      max-width:1400px;
      width:100%;
    }

    .support-card{
      position:relative;
      border-radius:22px;
      border:1px solid rgba(255,255,255,.06);
      background:#111827;
      box-shadow:0 10px 35px rgba(0,0,0,.25);
      overflow:hidden;
    }

    .support-card::before{
      display:none;
    }

    .faq-card{
      padding:24px;
      display:flex;
      flex-direction:column;
      background:#151c2e;
    }

    .contact-card{
      padding:20px 20px 18px;
      display:flex;
      flex-direction:column;
      justify-content:space-between;
      background:#151c2e;
    }

    .support-kicker{
      display:inline-flex;
      align-items:center;
      gap:8px;
      font-size:12px;
      font-weight:800;
      letter-spacing:.12em;
      text-transform:uppercase;
      color:#fbbf24;
      margin-bottom:10px;
    }

    .support-title{
      margin:0;
      font-size:34px;
      line-height:1.02;
      font-weight:900;
      color:#ffffff;
      letter-spacing:-.02em;
    }

    .faq-grid{
      margin-top:16px;
      display:grid;
      grid-template-columns:repeat(2, 1fr);
      gap:10px;
      flex:1;
    }

    .faq-item{
      border-radius:12px;
      border:1px solid rgba(255,255,255,.06);
      background:#111827;
      padding:12px 14px;
      display:flex;
      align-items:flex-start;
      gap:10px;
    }

    .faq-item:hover{
      transform:translateY(-2px);
      border-color:rgba(255,255,255,.12);
      background:#1b2438;
    }

    .faq-q{
      margin:0 0 6px;
      font-size:16px;
      font-weight:900;
      color:#fbbf24;
      line-height:1.35;
    }

    .faq-a{
      color:#ffffff;
      font-size:15px;
      line-height:1.6;
    }

    .faq-icon{
      flex:0 0 24px;
      width:24px;
      height:24px;
      border-radius:999px;
      display:inline-flex;
      align-items:center;
      justify-content:center;
      background:rgba(251,191,36,.14);
      color:#fbbf24;
      font-size:13px;
      font-weight:900;
      margin-top:1px;
    }

    .contact-top{
      display:flex;
      flex-direction:column;
      gap:14px;
    }

    .contact-title{
      margin:0;
      font-size:31px;
      line-height:1.02;
      font-weight:900;
      color:#ffffff;
      letter-spacing:-.02em;
    }

    .ai-coming{
      text-align:center;
      font-size:28px;
      font-weight:800;
      color:#ffffff;
      padding:40px 0;
      letter-spacing:.5px;
    }

    .cashout-bottom-fill{
      position:fixed;
      left:50%;
      transform:translateX(-50%);
      bottom:0;
      width:100vw;
      height:220px;
      background:#151c2e;
      border-top:1px solid rgba(255,255,255,.04);
      z-index:0;
      pointer-events:none;
    }

    .cashout-footer-content{
      position:fixed;
      left:50%;
      transform:translateX(-50%);
      bottom:0;
      width:100vw;
      height:220px;
      z-index:1;
      display:flex;
      justify-content:center;
      box-sizing:border-box;
      pointer-events:none;
    }

    .cashout-footer-inner{
      width:100%;
      max-width:1280px;
      padding:26px 36px 0;
      display:grid;
      grid-template-columns:1.7fr 1fr 1fr 1fr 1fr;
      gap:36px;
      box-sizing:border-box;
      pointer-events:auto;
    }

    .footer-brand{
      display:flex;
      flex-direction:column;
      align-items:flex-start;
    }

    .footer-logo{
      font-size:22px;
      font-weight:900;
      line-height:1;
      color:#fff;
      margin-bottom:18px;
    }

    .footer-logo .white{
      color:#ffffff;
    }

    .footer-logo .accent{
      color:#fbbf24;
    }

    .footer-brand-text{
      max-width:380px;
      color:rgba(255,255,255,.62);
      font-size:14px;
      line-height:1.55;
      margin-bottom:18px;
    }

    .footer-trust{
      display:flex;
      align-items:center;
    }

    .footer-trust-link{
      display:flex;
      align-items:center;
      gap:10px;
      color:#ffffff;
      text-decoration:none;
      font-size:12px;
      font-weight:700;
    }

    .footer-trust-img{
      height:42px;
      width:auto;
      display:block;
    }

    .footer-trust-link:hover{
      text-decoration:underline;
    }

    .footer-trust-link span{
      font-size:14px;
    }

    .footer-col-title{
      color:#fbbf24;
      font-size:16px;
      font-weight:900;
      margin:0 0 22px;
    }

    .footer-link{
      display:block;
      color:#ffffff;
      text-decoration:none;
      font-size:15px;
      font-weight:700;
      margin-bottom:22px;
      opacity:.95;
    }

    .footer-link:hover{
      opacity:1;
    }

    @media (max-width:1200px){
      .cashout-footer-inner{
        grid-template-columns:1.7fr 1fr 1fr 1fr;
        gap:28px;
      }

      .footer-col.social{
        display:none;
      }
    }

    @media (max-width:1100px){
      .support-shell{
        grid-template-columns:1.25fr .95fr;
      }

      .faq-grid{
        grid-template-columns:1fr;
      }

      .cashout-footer-inner{
        grid-template-columns:1.5fr 1fr 1fr;
        gap:28px;
      }

      .footer-col.legal{
        display:none;
      }
    }

    @media (max-width:768px){

      html, body{
        min-height:100%;
        overflow-x:hidden;
        overflow-y:auto;
      }

      main{
        min-height:calc(100vh - 64px);
        height:auto;
        max-height:none;
        overflow:visible;
      }

      .support-page{
        height:auto;
        min-height:0;
        padding:20px 14px 0;
        overflow:visible;
        display:block;
      }

      .support-shell{
        grid-template-columns:1fr;
        height:auto;
        gap:16px;
      }

      .faq-card,
      .contact-card{
        padding:20px 16px;
      }

      .support-title{
        font-size:32px;
      }

      .contact-title{
        font-size:30px;
      }

      .faq-grid{
        grid-template-columns:1fr;
      }

      .faq-q{
        font-size:17px;
      }

      .faq-a{
        font-size:15.5px;
      }

      .ai-coming{
        font-size:25px;
        padding:30px 0 18px;
      }

      .cashout-bottom-fill{
        display:none;
      }

      .cashout-footer-content{
        position:relative;
        left:auto;
        transform:none;
        bottom:auto;
        width:calc(100% + 28px);
        height:auto;
        display:block;
        margin:18px -14px 0;
        padding:16px 0 12px;
        background:#151c2e;
        border-top:1px solid rgba(255,255,255,.04);
      }

      .cashout-footer-inner{
        width:100%;
        max-width:100%;
        padding:0 14px 8px;
        grid-template-columns:1fr 1fr 1fr;
        gap:18px;
        box-sizing:border-box;
        align-items:start;
      }

      .footer-brand{
        grid-column:1 / -1;
      }

      .footer-logo{
        font-size:18px;
        margin-bottom:10px;
      }

      .footer-brand-text{
        max-width:none;
        font-size:12px;
        line-height:1.45;
        margin-bottom:10px;
      }

      .footer-trust-link{
        gap:8px;
      }

      .footer-trust-link span{
        font-size:12px;
      }

      .footer-trust-img{
        height:24px;
      }

      .footer-col-title{
        font-size:14px;
        margin:0 0 10px;
      }

      .footer-link{
        font-size:13px;
        margin-bottom:10px;
      }

      .footer-col:nth-of-type(2){
        display:none;
      }

      .footer-col.legal,
      .footer-col.social{
        display:block;
      }
    }
  </style>

  <div class="support-page">
    <div class="support-shell">
      <div class="support-card faq-card">
        <div class="support-kicker">Help Center</div>
        <h1 class="support-title">Frequently asked questions</h1>

        <div class="faq-grid">

          <div class="faq-item">
            <span class="faq-icon">?</span>
            <div>
              <div class="faq-q">How do I earn money?</div>
              <div class="faq-a">You can earn by completing surveys, testing apps, playing games and finishing offers from our partners.</div>
            </div>
          </div>

          <div class="faq-item">
            <span class="faq-icon">?</span>
            <div>
              <div class="faq-q">How long do payments take?</div>
              <div class="faq-a">Payments are usually processed within 0-72 hours.</div>
            </div>
          </div>

          <div class="faq-item">
            <span class="faq-icon">?</span>
            <div>
              <div class="faq-q">Why did I not receive a reward for completing my task?</div>
              <div class="faq-a">Rewards may fail if the task was not completed correctly or was already completed before.</div>
            </div>
          </div>

          <div class="faq-item">
            <span class="faq-icon">?</span>
            <div>
              <div class="faq-q">Why was my cashout failed?</div>
              <div class="faq-a">A cashout can fail if the PayPal email is incorrect or cannot receive payments.</div>
            </div>
          </div>

          <div class="faq-item">
            <span class="faq-icon">?</span>
            <div>
              <div class="faq-q">What do I do if I completed a task correctly but didn’t get paid?</div>
              <div class="faq-a">Please contact the offerwall support where you completed the task so they can review the completion.</div>
            </div>
          </div>

          <div class="faq-item">
            <span class="faq-icon">?</span>
            <div>
              <div class="faq-q">Why do I get disqualified from surveys?</div>
              <div class="faq-a">Survey providers look for specific demographics. If you do not match the requirements for a survey, you may be screened out.</div>
            </div>
          </div>

        </div>
      </div>

      <div class="support-card contact-card">
        <div class="contact-top">
          <div>
            <div class="support-kicker">AI Support</div>
            <h2 class="contact-title">AI Chat Support</h2>
          </div>

          <div class="ai-coming">
            AI Chat Support<br>
            Coming soon
          </div>
        </div>
      </div>
    </div>

    <div class="cashout-bottom-fill"></div>

    <div class="cashout-footer-content">
      <div class="cashout-footer-inner">

        <div class="footer-brand">
          <div class="footer-logo"><span class="white">Survey</span><span class="accent">Cash</span></div>

          <div class="footer-brand-text">
            SurveyCash is built to make earning simple. Complete surveys, explore offers and turn your time online into real rewards with quick payouts.
          </div>

          <div class="footer-trust">
            <a href="https://www.trustpilot.com/review/surveycash.website" target="_blank" class="footer-trust-link">
              <span>Rate us on Trustpilot</span>
              <img src="/img/trustpilot-mission.png" class="footer-trust-img">
            </a>
          </div>
        </div>

        <div class="footer-col">
          <div class="footer-col-title">SurveyCash</div>
          <a href="/" class="footer-link">Earn</a>
          <a href="/cashout" class="footer-link">Cash Out</a>
          <a href="/support" class="footer-link">Support</a>
        </div>

        <div class="footer-col">
          <div class="footer-col-title">Help</div>
          <a href="/support" class="footer-link">FAQ</a>
          <a href="/support" class="footer-link">Contact</a>
        </div>

        <div class="footer-col legal">
          <div class="footer-col-title">Info</div>
          <a href="/terms" class="footer-link">Terms</a>
          <a href="/privacy" class="footer-link">Privacy</a>
        </div>

        <div class="footer-col social">
          <div class="footer-col-title">Social</div>
          <a href="https://www.tiktok.com/@surveycashh?lang=da" target="_blank" rel="noopener noreferrer" class="footer-link">TikTok</a>
          <a href="https://x.com/SurveyCashh" target="_blank" rel="noopener noreferrer" class="footer-link">X</a>
        </div>

      </div>
    </div>
  </div>
  `;

  res.send(
    page(
      req,
      'Support — SurveyCash',
      '/support',
      bodyHtml
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


app.post('/auth/forgot-password', async (req, res) => {
  try {
    const email = String(req.body.email || '').trim().toLowerCase();

    if (!email) {
      return res.status(400).json({ error: 'Enter your email.' });
    }

    const { data: profile, error: profileError } = await supabaseAdmin
      .from('profiles')
      .select('user_id, email')
      .ilike('email', email)
      .maybeSingle();

    if (profileError) {
      console.error('Forgot password profile lookup error:', profileError);
      return res.status(500).json({ error: 'Something went wrong. Please try again.' });
    }

    if (profile) {
      const { error: resetError } = await supabaseAdmin.auth.resetPasswordForEmail(email, {
        redirectTo: 'https://surveycash.website/reset-password',
      });

      if (resetError) {
        console.error('Supabase reset email error:', resetError);
        return res.status(500).json({ error: 'Could not send reset email right now.' });
      }
    }

    return res.json({
      ok: true,
      message: 'If an account exists for that email, a reset link has been sent.',
    });
  } catch (err) {
    console.error('Forgot password route error:', err);
    return res.status(500).json({ error: 'Something went wrong. Please try again.' });
  }
});


app.get('/reset-password', (req, res) => {
  return res.send(`
    <!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="UTF-8" />
      <meta name="viewport" content="width=device-width, initial-scale=1.0" />
      <title>Reset password - SurveyCash</title>
      <script src="https://cdn.jsdelivr.net/npm/@supabase/supabase-js@2"></script>
<style>
  *{box-sizing:border-box}

  body{
    margin:0;
    min-height:100vh;
    display:flex;
    align-items:center;
    justify-content:center;
    background:#111827;
    font-family:Arial,sans-serif;
    color:#e5e7eb;
    padding:20px;
  }

  .card{
    width:100%;
    max-width:420px;
    background:#1a1f2b;
    border:1px solid #1f2937;
    border-radius:24px;
    padding:32px 28px 28px;
    box-shadow:0 32px 90px rgba(0,0,0,.75);
  }

  h1{
    margin:0 0 12px;
    font-size:24px;
    font-weight:700;
    color:#ffffff;
  }

  p{
    margin:0 0 18px;
    color:#cbd5e1;
    font-size:14px;
    line-height:1.5;
  }

  form{
    display:flex;
    flex-direction:column;
    gap:0;
  }

  input{
    width:100%;
    padding:12px 14px;
    border-radius:10px;
    border:1px solid #2a3240;
    background:#131822;
    color:#e5e7eb;
    font-size:14px;
    margin-bottom:14px;
    outline:none;
  }

  input::placeholder{
    color:#6b7280;
  }

  input:focus{
    border-color:#4b5563;
    box-shadow:none;
    outline:none;
  }

  button{
    width:100%;
    padding:12px 14px;
    border-radius:10px;
    border:1px solid #d97706;
    background:#fbbf24;
    color:#111827;
    font-size:14px;
    font-weight:700;
    cursor:pointer;
    margin-top:6px;
  }

  button:hover{
    background:#f59e0b;
  }

  button:disabled{
    opacity:0.65;
    cursor:not-allowed;
  }

  #msg{
    margin-top:14px;
    min-height:20px;
    font-size:14px;
    line-height:1.4;
  }
</style>
    </head>
    <body>
      <div class="card">
        <h1>Set new password</h1>
        <p>Enter your new password below.</p>

        <form id="resetForm">
          <input id="password" type="password" placeholder="New password" minlength="6" required />
          <input id="password2" type="password" placeholder="Repeat new password" minlength="6" required />
          <button type="submit" id="submitBtn" disabled>Update password</button>
        </form>

        <div id="msg"></div>
      </div>

      <script>
const supabaseClient = window.supabase.createClient(
  "${process.env.SUPABASE_URL}",
  "${process.env.SUPABASE_ANON_KEY}"
);

  const form = document.getElementById('resetForm');
  const password = document.getElementById('password');
  const password2 = document.getElementById('password2');
  const msg = document.getElementById('msg');
  const submitBtn = document.getElementById('submitBtn');

let recoveryReady = false;

function showMessage(text, isError) {
  msg.textContent = text || '';
  msg.style.color = isError ? '#fca5a5' : '#86efac';
}

function validatePasswords(showErrors) {
  const pass1 = password.value.trim();
  const pass2 = password2.value.trim();

  if (pass1.length < 6 || pass2.length < 6) {
    if (showErrors) showMessage('Password must be at least 6 characters.', true);
    return false;
  }

  if (pass1 !== pass2) {
    if (showErrors) showMessage('Passwords do not match.', true);
    return false;
  }

  showMessage('', false);
  return true;
}

function updateSubmitState() {
  const pass1 = password.value.trim();
  const pass2 = password2.value.trim();

  const validPasswords =
    pass1.length >= 6 &&
    pass2.length >= 6 &&
    pass1 === pass2;

  const canSubmit = recoveryReady && validPasswords;

  submitBtn.disabled = !canSubmit;
  submitBtn.style.opacity = canSubmit ? '1' : '0.65';
  submitBtn.style.cursor = canSubmit ? 'pointer' : 'not-allowed';
}

function setReady(ready) {
  recoveryReady = ready;
  updateSubmitState();
}

setReady(false);
showMessage('Checking reset link...', false);

password.addEventListener('input', function () {
  validatePasswords(false);
  updateSubmitState();
});

password2.addEventListener('input', function () {
  validatePasswords(false);
  updateSubmitState();
});

  supabaseClient.auth.onAuthStateChange((event) => {
    if (event === 'PASSWORD_RECOVERY' || event === 'SIGNED_IN') {
      setReady(true);
      showMessage('Enter your new password.', false);
    }
  });

(async function initRecovery() {
  try {
    console.log('FULL URL:', window.location.href);
    console.log('SEARCH:', window.location.search);
    console.log('HASH:', window.location.hash);

    const url = new URL(window.location.href);
    const code = url.searchParams.get('code');

    if (code) {
      console.log('FOUND CODE:', code);

      const { error } = await supabaseClient.auth.exchangeCodeForSession(code);
      console.log('exchangeCodeForSession error:', error);

      if (error) {
        showMessage('Invalid or expired reset link.', true);
        setReady(false);
        return;
      }

      setReady(true);
      showMessage('Enter your new password.', false);
      return;
    }

    const hash = window.location.hash || '';
    const params = new URLSearchParams(hash.replace(/^#/, ''));
    const accessToken = params.get('access_token');
    const refreshToken = params.get('refresh_token');
    const type = params.get('type');

    if (type === 'recovery' && accessToken && refreshToken) {
      console.log('FOUND HASH RECOVERY TOKENS');

      const { error } = await supabaseClient.auth.setSession({
        access_token: accessToken,
        refresh_token: refreshToken
      });

      console.log('setSession error:', error);

      if (error) {
        showMessage('Invalid or expired reset link.', true);
        setReady(false);
        return;
      }

      setReady(true);
      showMessage('Enter your new password.', false);
      return;
    }

    const { data, error } = await supabaseClient.auth.getSession();
    console.log('getSession data:', data);
    console.log('getSession error:', error);

    if (data && data.session) {
      setReady(true);
      showMessage('Enter your new password.', false);
      return;
    }

    showMessage('Invalid or expired reset link.', true);
    setReady(false);
  } catch (err) {
    console.log('initRecovery error:', err);
    showMessage('Invalid or expired reset link.', true);
    setReady(false);
  }
})();

form.addEventListener('submit', async function (e) {
  e.preventDefault();
  console.log('SUBMIT CLICKED');

    if (!recoveryReady) {
      showMessage('Invalid or expired reset link.', true);
      return;
    }

    const pass1 = password.value.trim();
    const pass2 = password2.value.trim();

if (!validatePasswords(true)) {
  updateSubmitState();
  return;
}

    submitBtn.disabled = true;
    showMessage('Updating password...', false);

const { data, error } = await supabaseClient.auth.updateUser({
  password: pass1
});

console.log('updateUser data:', data);
console.log('updateUser error:', error);

if (error) {
  alert(error.message || 'Could not update password.');
  showMessage(error.message || 'Could not update password.', true);
  submitBtn.disabled = false;
  return;
}

    showMessage('Password updated successfully. You can now log in.', false);

    setTimeout(function () {
      window.location.href = '/';
    }, 1600);
  });
</script>
    </body>
    </html>
  `);
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
