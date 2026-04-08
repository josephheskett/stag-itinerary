#!/usr/bin/env node
// Encrypts content.html into index.html with AES-256-GCM password protection
// Usage: node encrypt.js <password>

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const password = process.argv[2];
if (!password) {
  console.error('Usage: node encrypt.js <password>');
  process.exit(1);
}

const contentPath = path.join(__dirname, 'content.html');
const outputPath = path.join(__dirname, 'index.html');

if (!fs.existsSync(contentPath)) {
  console.error('content.html not found');
  process.exit(1);
}

const content = fs.readFileSync(contentPath, 'utf8');

// Generate random salt and IV
const salt = crypto.randomBytes(32);
const iv = crypto.randomBytes(12);

// Derive key using PBKDF2 (matching Web Crypto API params)
const key = crypto.pbkdf2Sync(password, salt, 600000, 32, 'sha256');

// Encrypt with AES-256-GCM
const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
let encrypted = cipher.update(content, 'utf8');
encrypted = Buffer.concat([encrypted, cipher.final()]);
const authTag = cipher.getAuthTag();

// Combine: salt + iv + authTag + ciphertext, base64 encode
const payload = Buffer.concat([salt, iv, authTag, encrypted]).toString('base64');

// Build the shell page
const shell = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Jack & Zosim's Stag Do</title>
<meta property="og:title" content="Jack & Zosim's Stag Do">
<meta property="og:description" content="2nd & 3rd May 2026 — London. You're invited!">
<meta property="og:type" content="website">
<meta property="og:url" content="https://stag-itinerary.vercel.app">
<meta name="twitter:card" content="summary">
<meta name="twitter:title" content="Jack & Zosim's Stag Do">
<meta name="twitter:description" content="2nd & 3rd May 2026 — London. You're invited!">
<meta name="theme-color" content="#7b2ff7">
<style>
  @import url('https://fonts.googleapis.com/css2?family=Outfit:wght@400;600;700;900&family=Playfair+Display:wght@700;900&display=swap');
  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    font-family: 'Outfit', sans-serif;
    min-height: 100vh;
    display: flex;
    align-items: center;
    justify-content: center;
    background: linear-gradient(135deg, #7b2ff7 0%, #ff2d87 50%, #ff6b35 100%);
    color: #fff;
  }
  .password-box {
    text-align: center;
    padding: 2.5rem;
    background: rgba(255,255,255,0.1);
    backdrop-filter: blur(20px);
    border: 1px solid rgba(255,255,255,0.2);
    border-radius: 24px;
    max-width: 400px;
    width: 90%;
  }
  .password-box h2 {
    font-family: 'Playfair Display', serif;
    font-size: 1.8rem;
    margin-bottom: 0.5rem;
  }
  .password-box p {
    font-size: 0.9rem;
    opacity: 0.7;
    margin-bottom: 1.5rem;
  }
  .lock-icon { font-size: 2.5rem; margin-bottom: 1rem; display: block; }
  .password-input {
    width: 100%;
    padding: 0.75rem 1rem;
    font-family: 'Outfit', sans-serif;
    font-size: 1rem;
    color: #fff;
    background: rgba(255,255,255,0.1);
    border: 1px solid rgba(255,255,255,0.3);
    border-radius: 12px;
    outline: none;
    text-align: center;
    margin-bottom: 1rem;
  }
  .password-input::placeholder { color: rgba(255,255,255,0.4); }
  .password-input:focus { border-color: rgba(255,255,255,0.6); }
  .password-submit {
    width: 100%;
    padding: 0.75rem;
    font-family: 'Outfit', sans-serif;
    font-size: 1rem;
    font-weight: 700;
    color: #fff;
    background: linear-gradient(135deg, #ff2d87, #7b2ff7);
    border: none;
    border-radius: 12px;
    cursor: pointer;
    transition: transform 0.2s, box-shadow 0.2s;
  }
  .password-submit:hover:not(:disabled) {
    transform: translateY(-2px);
    box-shadow: 0 4px 20px rgba(255,45,135,0.4);
  }
  .password-submit:disabled { opacity: 0.5; cursor: not-allowed; }
  .password-error { color: #ff6b6b; font-size: 0.85rem; margin-top: 0.75rem; min-height: 1.2rem; }
</style>
</head>
<body>
<div class="password-box" id="gate">
  <span class="lock-icon">🔒</span>
  <h2>Jack & Zosim's Stag Do</h2>
  <p>Enter the password to view the itinerary</p>
  <form id="form" onsubmit="return tryDecrypt(event)">
    <input type="password" class="password-input" id="pw" placeholder="Password" autocomplete="off" autofocus>
    <button type="submit" class="password-submit" id="btn">Let me in</button>
  </form>
  <div class="password-error" id="err"></div>
</div>
<script>
const PAYLOAD = '${payload}';
const SESSION_KEY = 'stagdo_auth';
const SESSION_DAYS = 30;
const ATTEMPTS_KEY = 'stagdo_attempts';
const LOCKOUT_KEY = 'stagdo_lockout';
const MAX_ATTEMPTS = 5;
const LOCKOUT_MS = 5 * 60 * 1000;

function b64toBytes(b64) {
  const bin = atob(b64);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes;
}

async function decrypt(password) {
  const data = b64toBytes(PAYLOAD);
  const salt = data.slice(0, 32);
  const iv = data.slice(32, 44);
  const authTag = data.slice(44, 60);
  const ciphertext = data.slice(60);

  const keyMaterial = await crypto.subtle.importKey(
    'raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveKey']
  );
  const key = await crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations: 600000, hash: 'SHA-256' },
    keyMaterial,
    { name: 'AES-GCM', length: 256 },
    false,
    ['decrypt']
  );

  // Combine ciphertext + authTag for Web Crypto (it expects them concatenated)
  const combined = new Uint8Array(ciphertext.length + authTag.length);
  combined.set(ciphertext);
  combined.set(authTag, ciphertext.length);

  const decrypted = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv },
    key,
    combined
  );
  return new TextDecoder().decode(decrypted);
}

function getAttempts() {
  try { return JSON.parse(localStorage.getItem(ATTEMPTS_KEY)) || { count: 0 }; }
  catch { return { count: 0 }; }
}

function isLockedOut() {
  const lockout = parseInt(localStorage.getItem(LOCKOUT_KEY) || '0');
  if (lockout && Date.now() < lockout) return lockout;
  if (lockout) { localStorage.removeItem(LOCKOUT_KEY); localStorage.removeItem(ATTEMPTS_KEY); }
  return false;
}

function updateLockoutUI(lockUntil) {
  const btn = document.getElementById('btn');
  const err = document.getElementById('err');
  const input = document.getElementById('pw');
  btn.disabled = true;
  input.disabled = true;
  const tick = () => {
    const remaining = Math.max(0, lockUntil - Date.now());
    if (remaining <= 0) {
      btn.disabled = false; input.disabled = false; err.textContent = '';
      localStorage.removeItem(LOCKOUT_KEY); localStorage.removeItem(ATTEMPTS_KEY);
      return;
    }
    const mins = Math.floor(remaining / 60000);
    const secs = Math.ceil((remaining % 60000) / 1000);
    err.textContent = 'Too many attempts. Try again in ' + mins + ':' + secs.toString().padStart(2, '0');
    setTimeout(tick, 1000);
  };
  tick();
}

function showContent(html) {
  document.open();
  document.write(html);
  document.close();
}

// Check session on load
(async function() {
  const session = localStorage.getItem(SESSION_KEY);
  if (session) {
    try {
      const { pw, expires } = JSON.parse(session);
      if (Date.now() < expires) {
        const html = await decrypt(pw);
        showContent(html);
        return;
      }
    } catch {}
    localStorage.removeItem(SESSION_KEY);
  }
  const lockUntil = isLockedOut();
  if (lockUntil) updateLockoutUI(lockUntil);
})();

async function tryDecrypt(e) {
  e.preventDefault();
  const lockUntil = isLockedOut();
  if (lockUntil) { updateLockoutUI(lockUntil); return false; }

  const pw = document.getElementById('pw').value;
  const err = document.getElementById('err');
  if (!pw) { err.textContent = 'Please enter the password'; return false; }

  try {
    const html = await decrypt(pw);
    // Success — save session (storing password for re-decryption)
    localStorage.setItem(SESSION_KEY, JSON.stringify({
      pw: pw,
      expires: Date.now() + SESSION_DAYS * 24 * 60 * 60 * 1000
    }));
    localStorage.removeItem(ATTEMPTS_KEY);
    localStorage.removeItem(LOCKOUT_KEY);
    showContent(html);
  } catch {
    // Wrong password — AES-GCM will throw on wrong key
    const attempts = getAttempts();
    attempts.count++;
    localStorage.setItem(ATTEMPTS_KEY, JSON.stringify(attempts));

    if (attempts.count >= MAX_ATTEMPTS) {
      const lockUntil = Date.now() + LOCKOUT_MS;
      localStorage.setItem(LOCKOUT_KEY, lockUntil.toString());
      updateLockoutUI(lockUntil);
    } else {
      const remaining = MAX_ATTEMPTS - attempts.count;
      err.textContent = 'Wrong password. ' + remaining + ' attempt' + (remaining === 1 ? '' : 's') + ' remaining.';
      document.getElementById('pw').value = '';
      document.getElementById('pw').focus();
    }
  }
  return false;
}
<\/script>
</body>
</html>`;

fs.writeFileSync(outputPath, shell);
console.log('Encrypted content.html → index.html (' + Math.round(payload.length / 1024) + 'KB encrypted payload)');
