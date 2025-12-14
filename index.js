// index.js — SurveyCash: grå landing + gul tema + auth-modal (login/signup)
require('dotenv').config();

const { createClient } = require('@supabase/supabase-js');

const supabaseAdmin = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_ROLE_KEY
);

const express = require('express');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const fs = require('fs');
const path = require('path');
const bcrypt = require('bcrypt');
const crypto = require('crypto');

function md5(s) {
  return crypto
    .createHash('md5')
    .update(String(s), 'utf8')
    .digest('hex');
}

const app = express();

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

app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

// --- Auth middleware: cookie -> Supabase profile -> req.user ---
async function loadUserFromCookie(req, res, next) {
  try {
    const emailRaw = req.cookies && req.cookies.authEmail;
    if (!emailRaw) {
      req.user = null;
      return next();
    }

    const email = String(emailRaw).toLowerCase().trim();

    const { data: profile, error } = await supabaseAdmin
      .from('profiles')
      .select(`
        user_id,
        email,
        username,
        created_at,
        balance_cents,
        total_earned_cents,
        completed_surveys,
        completed_offers,
        username_changed_at,
        password_changed_at
      `)
      .eq('email', email)
      .single();

    if (error || !profile) {
      req.user = null;
      return next();
    }

    req.user = {
      id: profile.user_id,
      email: profile.email,
      username: profile.username || (profile.email ? profile.email.split('@')[0] : 'User'),
      createdAt: profile.created_at ? new Date(profile.created_at).getTime() : Date.now(),
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

  function clearError() {
    if (!errorBox) return;
    errorBox.style.display = 'none';
    errorBox.textContent = '';
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
    margin:60px auto 0;
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
    margin-bottom:22px;
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

  <!-- Auth modal -->
  <div id="auth-backdrop" class="auth-backdrop">
    <div class="auth-modal">
      <button id="auth-close" class="auth-close" type="button">×</button>
      <div id="auth-title" class="auth-title">Log in</div>

      <div id="auth-error" class="auth-error"></div>

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
        By using SurveyCash you agree to our <a href="#">Terms</a> and <a href="#">Privacy Policy</a>.
      </div>
    </div>
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
  </section>`;
}



// ---------- Routes ----------
app.get('/', (req, res) => {
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

  const stats = aggregatePlatformStats();
  const totalEarnedUsd = formatUsdFromCents(stats.totalEarnedCents);
  const totalUsers = stats.totalUsers || 0;

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
    <h1>Games</h1>
    <p>Snart kan du spille mini-games og optjene rewards.</p>
  `,
    ),
  );
});




// --- CPX anti-duplicate log (trans_id + type) ---
const CPX_TX_FILE = path.join(__dirname, 'cpx_transactions.json');

function readJsonSafe(file, fallback) {
  try { return JSON.parse(fs.readFileSync(file, 'utf8')); } catch { return fallback; }
}
function writeJsonSafe(file, data) {
  fs.writeFileSync(file, JSON.stringify(data, null, 2));
}


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
    const q = req.query || {};

    const statusRaw = String(q.status || q.state || '').toLowerCase();
    const transId = String(q.trans_id || q.transaction_id || q.sid || q.subid || '').trim();
    const userId = String(q.user_id || q.ext_user_id || q.uid || '').trim();
    const type = String(q.type || 'complete').toLowerCase().trim();

    const amountRaw =
      q.amount_local ?? q.amount ?? q.reward ?? q.payout ?? q.value ?? '0';

    const amount = Number(String(amountRaw).replace(',', '.')) || 0;

    if (!transId || !userId) return res.status(200).send('ok');

    const isCredit =
      statusRaw === '1' || statusRaw === 'approved' || statusRaw === 'completed' || statusRaw === 'ok';

    const isReversal =
      statusRaw === '2' || statusRaw === 'reversed' || statusRaw === 'chargeback' ||
      statusRaw === 'canceled' || statusRaw === 'cancelled';

    const txLog = readJsonSafe(CPX_TX_FILE, {});
    const key = `${transId}:${type}`;

    const profile = await findProfileByUserIdOrEmailSupabase(userId);
    if (!profile) return res.status(200).send('ok');

    const currentBalance = Number(profile.balance_cents || 0);
    const currentTotal   = Number(profile.total_earned_cents || 0);
    const currentSurveys = Number(profile.completed_surveys || 0);

    if (isCredit) {
      if (!txLog[key]) {
        const cents = Math.round(Math.max(0, amount) * 100);

        txLog[key] = { userId: profile.user_id, transId, type, cents, at: Date.now(), status: 1 };
        writeJsonSafe(CPX_TX_FILE, txLog);

        if (cents > 0) {
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
      }
      return res.status(200).send('ok');
    }

    if (isReversal) {
      if (txLog[key] && txLog[key].status === 1) {
        txLog[key].status = 2;
        writeJsonSafe(CPX_TX_FILE, txLog);

        const cents = Number(txLog[key].cents || 0);
        if (cents > 0) {
          const newBalance = Math.max(0, currentBalance - cents);

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



app.get('/cashout', (req, res) => {
  if (!isLoggedIn(req)) return res.redirect('/');
  res.send(
    page(
      req,
      'Cash Out — SurveyCash',
      '/cashout',
      `
    <h1>Cash Out</h1>
    <p>Udbetal dine point til MobilePay, PayPal eller gavekort (kommer snart).</p>
  `,
    ),
  );
});

app.get('/support', (req, res) => {
  res.send(
    page(
      req,
      'Support — SurveyCash',
      '/support',
      `
    <h1>Support</h1>
    <p>Har du problemer? Kontakt os på
      <a href="mailto:support@surveycash.dk" style="color:#fbbf24;text-decoration:none;">
        support@surveycash.dk
      </a>
    </p>
  `,
    ),
  );
});

// --- Auth handlers (modal) — Supabase signup ---
app.post('/signup', async (req, res) => {
  let createdUserId = null;

  try {
    const email = String(req.body.email || '').trim().toLowerCase();
    const password = String(req.body.password || '');
    const usernameRaw = String(req.body.username || '').trim();
    const username = usernameRaw.toLowerCase();

    if (!email || !email.includes('@') || password.length < 6 || !username) {
      return res.redirect('/?authError=invalid&mode=signup');
    }

    // 1️⃣ Pre-check username (case-insensitive fordi vi gemmer lowercase)
    const { data: existing } = await supabaseAdmin
      .from('profiles')
      .select('user_id')
      .eq('username', username)
      .maybeSingle();

    if (existing) {
      return res.redirect('/?authError=username_taken&mode=signup');
    }

    // 2️⃣ Opret Auth-user
    const { data: created, error: createErr } =
      await supabaseAdmin.auth.admin.createUser({
        email,
        password,
        email_confirm: true,
      });

    if (createErr || !created?.user) {
      const msg = String(createErr?.message || '').toLowerCase();
      if (msg.includes('already')) {
        return res.redirect('/?authError=exists&mode=signup');
      }
      console.error('Signup createUser error:', createErr);
      return res.redirect('/?authError=unknown&mode=signup');
    }

    createdUserId = created.user.id;

    // 3️⃣ Trigger har allerede lavet profiles-row → UPDATE den
    const { error: upErr } = await supabaseAdmin
      .from('profiles')
      .update({ username })
      .eq('user_id', createdUserId);

    if (upErr) {
      // hvis username alligevel blev taget (race condition / DB index)
      if (upErr.code === '23505') {
        // ryd op: slet auth-user så email ikke bliver "låst"
        await supabaseAdmin.auth.admin.deleteUser(createdUserId);
        return res.redirect('/?authError=username_taken&mode=signup');
      }

      console.error('Signup profile update error:', upErr);

      // ryd op ved alle andre update-fejl
      await supabaseAdmin.auth.admin.deleteUser(createdUserId);
      return res.redirect('/?authError=unknown&mode=signup');
    }

    // 4️⃣ Log ind
    res.cookie('authEmail', email, { httpOnly: false, sameSite: 'Lax' });
    return res.redirect('/surveys');

  } catch (err) {
    console.error('Signup fejl:', err);

    // hvis der blev oprettet auth-user, men vi crasher bagefter → ryd op
    try {
      if (createdUserId) {
        await supabaseAdmin.auth.admin.deleteUser(createdUserId);
      }
    } catch (e) {
      console.error('Cleanup deleteUser failed:', e);
    }

    return res.redirect('/?authError=unknown&mode=signup');
  }
});

// --- Auth handlers (modal) — Supabase login ---
app.post('/login', async (req, res) => {
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

    // 2️⃣ Account findes → tjek password via Supabase Auth
    const supabasePublic = createClient(
      process.env.SUPABASE_URL,
      process.env.SUPABASE_ANON_KEY
    );

    const { error: signErr } = await supabasePublic.auth.signInWithPassword({
      email,
      password,
    });

    if (signErr) {
      // ❌ Forkert password
      return res.redirect('/?authError=badpass&mode=login');
    }

    // ✅ Login OK (samme cookie-flow som før)
    res.cookie('authEmail', email, { httpOnly: false, sameSite: 'Lax' });
    return res.redirect('/surveys');
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


// ---------- Health API ----------
app.get('/api/health', (req, res) => {
  res.json({ ok: true, app: 'SurveyCash Web', ts: Date.now(), loggedIn: isLoggedIn(req) });
});

app.get('/logout', (req, res) => {
  res.clearCookie('authEmail');
  return res.redirect('/');
});


// ---------- Start ----------
app.listen(PORT, () => {
  console.log('SurveyCash (web) kører på ' + BASE_URL);
});
