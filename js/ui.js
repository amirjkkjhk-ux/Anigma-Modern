// ====================================================================================
// ANIGMA — ui.js
// Rendering, modals, tabs, identity/contacts UI, the secure-message UI, the files UI,
// and app startup. Cryptography itself lives in crypto.js/container.js; this file only
// wires the DOM to those modules.
// ====================================================================================

const APP_VERSION = '23.2';

// Security review #11 (clickjacking): the CSP's `frame-ancestors 'none'` only takes effect
// as a real HTTP response header — browsers silently ignore it when set via the <meta> tag
// above, which is the only mechanism available without control over how this app is
// served. This is a best-effort client-side fallback, run as early as possible (before
// DOMContentLoaded, so an embedding frame has the least possible time to interact with a
// rendered page first): if this document is not the top-level window, refuse to render
// anything meaningful. It is NOT a substitute for the real fix — sending an actual
// `X-Frame-Options: DENY` / `Content-Security-Policy: frame-ancestors 'none'` HTTP header
// from whatever serves these files — because a sandboxed iframe with scripts disabled
// defeats any JS-only defense entirely; that fix belongs at the hosting/server level,
// outside what this file can control.
(function () {
  try {
    if (window.top !== window.self) {
      document.documentElement.innerHTML = '';
      window.top.location = window.self.location; // best-effort: ask the browser to break out
    }
  } catch (e) {
    // Cross-origin access to window.top throws precisely when this page IS framed by a
    // different origin — the exact case we care about. Treat the throw itself as the signal.
    document.documentElement.innerHTML = '';
  }
})();

const QR_MAX_CHARS_HINT = 2900; // rough upper bound across supported EC levels/versions
// Buffering a whole decrypted package in a JS array (the fallback path when the File
// System Access API is unavailable — every mobile browser today, and any desktop browser
// the user declines the folder picker in) risks exhausting memory on a phone well before
// it would on a desktop. This is a soft warning threshold, not a hard cap: the user can
// still choose to proceed past it. See filesConfirmDecrypt().
const MEMORY_DECRYPT_WARN_BYTES = 300 * 1024 * 1024;

// ------------------------------------------------------------------ unlock-attempt rate limiting
// CLIENT-SIDE ONLY, BY NECESSITY. Anigma has no server to enforce anything against — all this
// can ever do is slow down someone guessing a PIN by hand, on THIS device, in THIS browser tab
// (e.g. a nosy classmate who's picked up the phone while it's open to the lock screen). It is
// NOT a defense against an attacker who has copied anigma_identity_v1 off the device: they can
// run crypto.subtle.deriveKey in their own offline script as many times as they like, with no
// delay this code can impose on them. The only real protection against that case is the PIN's
// own entropy and the KDF's iteration cost (deriveMasterKey, unchanged by this feature) — this
// is stated here, in identity.pin.rateLimitNote in the UI, and should stay stated wherever this
// is explained, so nobody mistakes a UX nicety for a cryptographic guarantee.
const UNLOCK_ATTEMPTS_KEY = 'anigma_unlock_attempts_v1';
const UNLOCK_FREE_ATTEMPTS = 5;             // this many wrong guesses cost nothing at all
const UNLOCK_BASE_DELAY_MS = 2000;          // delay for the 1st attempt past the free ones
const UNLOCK_MAX_DELAY_MS = 5 * 60 * 1000;  // hard cap, so a typo-prone legitimate owner is never locked out for more than this

// Pure function (no DOM, no storage) so it's directly unit-testable: how long must someone
// wait before attempt number `failCount+1`, given `failCount` wrong attempts so far.
// Exponential backoff starting right after the free allowance, capped at UNLOCK_MAX_DELAY_MS.
function unlockBackoffDelayMs(failCount) {
  if (!Number.isFinite(failCount) || failCount <= UNLOCK_FREE_ATTEMPTS) return 0;
  const n = failCount - UNLOCK_FREE_ATTEMPTS; // 1, 2, 3, ... for each attempt past the free ones
  const delay = UNLOCK_BASE_DELAY_MS * Math.pow(2, n - 1);
  return Math.min(delay, UNLOCK_MAX_DELAY_MS);
}

function unlockAttemptsLoad() {
  try {
    const raw = localStorage.getItem(UNLOCK_ATTEMPTS_KEY);
    if (!raw) return { count: 0, lastAttemptTs: 0 };
    const parsed = JSON.parse(raw);
    const count = Number(parsed.count), ts = Number(parsed.lastAttemptTs);
    return { count: Number.isFinite(count) && count >= 0 ? count : 0, lastAttemptTs: Number.isFinite(ts) && ts >= 0 ? ts : 0 };
  } catch (e) { return { count: 0, lastAttemptTs: 0 }; }
}
function unlockAttemptsRecordFailure() {
  const state = unlockAttemptsLoad();
  state.count += 1;
  state.lastAttemptTs = Date.now();
  try { localStorage.setItem(UNLOCK_ATTEMPTS_KEY, JSON.stringify(state)); } catch (e) {}
}
// Called on: new identity created, identity restored from backup, emergency wipe, and a
// SUCCESSFUL unlock — any of these means whatever was being guarded against no longer applies
// (either it's a fresh passphrase, or the right one was just proven).
function unlockAttemptsReset() {
  try { localStorage.removeItem(UNLOCK_ATTEMPTS_KEY); } catch (e) {}
  unlockCountdownStop();
}
// Milliseconds still remaining in the current cooldown (0 if none/expired). Re-derived fresh
// from storage+Date.now() every call rather than cached, so it survives a page reload exactly
// as it should (a refresh must not be a way to bypass the wait).
function unlockRemainingCooldownMs() {
  const state = unlockAttemptsLoad();
  const required = unlockBackoffDelayMs(state.count);
  if (required === 0) return 0;
  return Math.max(0, required - (Date.now() - state.lastAttemptTs));
}

let unlockCountdownTimer = null;
function unlockCountdownStop() {
  if (unlockCountdownTimer) { clearInterval(unlockCountdownTimer); unlockCountdownTimer = null; }
  const btn = document.getElementById('jsb8');
  if (btn) btn.disabled = false;
  const note = document.getElementById('idUnlockCooldownNote');
  if (note) note.textContent = '';
}
function unlockCountdownStart() {
  const btn = document.getElementById('jsb8');
  const note = document.getElementById('idUnlockCooldownNote');
  if (!btn) return;
  function tick() {
    const remainMs = unlockRemainingCooldownMs();
    if (remainMs <= 0) { unlockCountdownStop(); return; }
    btn.disabled = true;
    if (note) note.textContent = t('status.id.unlockCooldown', { seconds: Math.ceil(remainMs / 1000) });
  }
  tick();
  if (unlockCountdownTimer) clearInterval(unlockCountdownTimer);
  unlockCountdownTimer = setInterval(tick, 1000);
}

// ------------------------------------------------------------------ runtime state
let audioEnabled = true;
let loggingEnabled = true;
let currentLang = 'en';
// 'simple' (default for new users) or 'advanced'. Persisted in localStorage ('anigma_mode') and mirrored
// onto <html data-mode> so CSS can hide .adv-only / .simple-only parts. i18n.js's t() reads this to pick
// the plain-language 'key@simple' wording. Nothing here touches the crypto layer.
let uiMode = 'simple';
let isMenuOpen = false;
let qrInstance = null;

let idPrivateKey = null;
let idMasterKey = null;
let idPublicKeyRaw = null;
let idPublicKeyB64 = '';
let idFingerprint = '';
let idContacts = [];
// Security review #7: idLoadContacts() used to swallow a decrypt/parse failure (e.g. a few
// flipped bytes in localStorage) by silently setting idContacts = []. The user saw "0
// contacts" with no indication anything was wrong, and the very next "add contact" call
// saved that empty list right over the old (still-undecryptable-but-not-gone) blob,
// permanently destroying it. This flag lets idSaveContacts() refuse to overwrite storage
// until the user has been warned and explicitly confirms.
let idContactsLoadFailed = false;

// secure-message UI state
let secRecipientMode = 'paste';
let secPastedRecipientRaw = null;
let secSenderMode = 'auto';      // auto = try anonymous, then every saved contact (+ myself); contact/paste/none = the original manual choices (Advanced)
let secForceEncrypt = false;     // Advanced escape hatch: treat text that looks like a package as plain text to encrypt
let secClaimedSenderRaw = null;
let secLastOutputSensitive = false; // true once #secureOutput holds decrypted plaintext, not ciphertext

// files UI state
let filesSelected = [];  // [{file, relPath}]
let filesRecipientMode = 'paste';
let filesPastedRecipientRaw = null;
let filesSenderMode = 'auto';    // same idea as secSenderMode; 'contact'/'paste' are the manual choices (Advanced)
let filesFallbackFile = null;    // package awaiting a manually pasted sender key after automatic matching failed
let lastAddedContactId = null;
let filesClaimedSenderRaw = null;
let filesWorker = null;
let filesOperationActive = false;
// A native save/directory picker that a human actually saw and cancelled always takes
// noticeably longer than this to reject; a picker that never managed to open at all (no
// xdg-desktop-portal on Linux, sandboxed/embedded browser, some remote sessions, blocked by
// permissions policy) rejects with the identical AbortError in a handful of milliseconds.
// Used by filesStartEncrypt()/filesConfirmDecrypt() to tell the two apart. See their comments.
const FILES_PICKER_CANCEL_MIN_MS = 300;
let wakeLockRef = null;

// ====================================================================================
// ICONS
// ====================================================================================
// Duotone icon set: Phosphor Icons 2.1.1 (MIT, https://phosphoricons.com) — every glyph is a line shape plus a soft
// "duo" fill layer ({ duo: true }) that the CSS tints with the theme accent. Only the lock is hand-split so its shackle
// can lift on hover. viewBox is 256 for all of them.
const ICONS = {
  menu: { viewBox: '0 0 256 256', paths: [ { d: 'M216,64V192H40V64Z', duo: true }, { d: 'M224,128a8,8,0,0,1-8,8H40a8,8,0,0,1,0-16H216A8,8,0,0,1,224,128ZM40,72H216a8,8,0,0,0,0-16H40a8,8,0,0,0,0,16ZM216,184H40a8,8,0,0,0,0,16H216a8,8,0,0,0,0-16Z' } ] },
  close: { viewBox: '0 0 256 256', paths: [ { d: 'M205.66,194.34a8,8,0,0,1-11.32,11.32L128,139.31,61.66,205.66a8,8,0,0,1-11.32-11.32L116.69,128,50.34,61.66A8,8,0,0,1,61.66,50.34L128,116.69l66.34-66.35a8,8,0,0,1,11.32,11.32L139.31,128Z' } ] },
  globe: { viewBox: '0 0 256 256', fx: 'spin', paths: [ { d: 'M213.09,172.48a96,96,0,0,1-80.41,51.41l3.17-16.44a8,8,0,0,0-2-6.95l-19.74-20.33a8,8,0,0,1-1.44-8.69l13.7-30.74a8,8,0,0,1,8.38-4.67l22.82,3.08a8.11,8.11,0,0,1,3.12,1.11ZM116.71,95,129,88.24a7.46,7.46,0,0,0,1.5-1.07l26.91-24.33A8,8,0,0,0,159,53l-10.5-18.81A96.62,96.62,0,0,0,128,32,95.61,95.61,0,0,0,67.78,53.23L56,81.08A8,8,0,0,0,55.88,87l11.5,30.67a8,8,0,0,0,5.81,5l2.69.58L89.2,100a8,8,0,0,1,6.94-4h16.71A7.9,7.9,0,0,0,116.71,95Z', duo: true }, { d: 'M128,24A104,104,0,1,0,232,128,104.11,104.11,0,0,0,128,24Zm88,104a87.62,87.62,0,0,1-6.4,32.94l-44.7-27.49a15.92,15.92,0,0,0-6.24-2.23l-22.82-3.08a16.11,16.11,0,0,0-16,7.86h-8.72l-3.8-7.86a15.91,15.91,0,0,0-11-8.67l-8-1.73L96.14,104h16.71a16.06,16.06,0,0,0,7.73-2l12.25-6.76a16.62,16.62,0,0,0,3-2.14l26.91-24.34A15.93,15.93,0,0,0,166,49.1l-.36-.65A88.11,88.11,0,0,1,216,128ZM143.31,41.34,152,56.9,125.09,81.24,112.85,88H96.14a16,16,0,0,0-13.88,8l-8.73,15.23L63.38,84.19,74.32,58.32a87.87,87.87,0,0,1,69-17ZM40,128a87.53,87.53,0,0,1,8.54-37.8l11.34,30.27a16,16,0,0,0,11.62,10l21.43,4.61L96.74,143a16.09,16.09,0,0,0,14.4,9h1.48l-7.23,16.23a16,16,0,0,0,2.86,17.37l.14.14L128,205.94l-1.94,10A88.11,88.11,0,0,1,40,128Zm102.58,86.78,1.13-5.81a16.09,16.09,0,0,0-4-13.9,1.85,1.85,0,0,1-.14-.14L120,174.74,133.7,144l22.82,3.08,45.72,28.12A88.18,88.18,0,0,1,142.58,214.78Z' } ] },
  lock: { viewBox: '0 0 256 256', fx: 'lock', paths: [ { d: 'M216,96V208a8,8,0,0,1-8,8H48a8,8,0,0,1-8-8V96a8,8,0,0,1,8-8H208A8,8,0,0,1,216,96Z', duo: true }, { d: 'M208,80H48A16,16,0,0,0,32,96V208a16,16,0,0,0,16,16H208a16,16,0,0,0,16-16V96A16,16,0,0,0,208,80Zm0,128H48V96H208V208Zm-68-56a12,12,0,1,1-12-12A12,12,0,0,1,140,152Z' }, { tag: 'path', d: 'M88,84V56a40,40,0,0,1,80,0V84', stroke: true, width: 16, accent: true } ] },
  key: { viewBox: '0 0 256 256', paths: [ { d: 'M232,98.36C230.73,136.92,198.67,168,160.09,168a71.68,71.68,0,0,1-26.92-5.17h0L120,176H96v24H72v24H40a8,8,0,0,1-8-8V187.31a8,8,0,0,1,2.34-5.65l58.83-58.83h0A71.68,71.68,0,0,1,88,95.91c0-38.58,31.08-70.64,69.64-71.87A72,72,0,0,1,232,98.36Z', duo: true }, { d: 'M216.57,39.43A80,80,0,0,0,83.91,120.78L28.69,176A15.86,15.86,0,0,0,24,187.31V216a16,16,0,0,0,16,16H72a8,8,0,0,0,8-8V208H96a8,8,0,0,0,8-8V184h16a8,8,0,0,0,5.66-2.34l9.56-9.57A79.73,79.73,0,0,0,160,176h.1A80,80,0,0,0,216.57,39.43ZM224,98.1c-1.09,34.09-29.75,61.86-63.89,61.9H160a63.7,63.7,0,0,1-23.65-4.51,8,8,0,0,0-8.84,1.68L116.69,168H96a8,8,0,0,0-8,8v16H72a8,8,0,0,0-8,8v16H40V187.31l58.83-58.82a8,8,0,0,0,1.68-8.84A63.72,63.72,0,0,1,96,95.92c0-34.14,27.81-62.8,61.9-63.89A64,64,0,0,1,224,98.1ZM192,76a12,12,0,1,1-12-12A12,12,0,0,1,192,76Z' } ] },
  copy: { viewBox: '0 0 256 256', paths: [ { d: 'M216,40V168H168V88H88V40Z', duo: true }, { d: 'M216,32H88a8,8,0,0,0-8,8V80H40a8,8,0,0,0-8,8V216a8,8,0,0,0,8,8H168a8,8,0,0,0,8-8V176h40a8,8,0,0,0,8-8V40A8,8,0,0,0,216,32ZM160,208H48V96H160Zm48-48H176V88a8,8,0,0,0-8-8H96V48H208Z' } ] },
  paste: { viewBox: '0 0 256 256', paths: [ { d: 'M208,48V216a8,8,0,0,1-8,8H56a8,8,0,0,1-8-8V48a8,8,0,0,1,8-8H96a39.83,39.83,0,0,0-8,24v8h80V64a39.83,39.83,0,0,0-8-24h40A8,8,0,0,1,208,48Z', duo: true }, { d: 'M168,152a8,8,0,0,1-8,8H96a8,8,0,0,1,0-16h64A8,8,0,0,1,168,152Zm-8-40H96a8,8,0,0,0,0,16h64a8,8,0,0,0,0-16Zm56-64V216a16,16,0,0,1-16,16H56a16,16,0,0,1-16-16V48A16,16,0,0,1,56,32H92.26a47.92,47.92,0,0,1,71.48,0H200A16,16,0,0,1,216,48ZM96,64h64a32,32,0,0,0-64,0ZM200,48H173.25A47.93,47.93,0,0,1,176,64v8a8,8,0,0,1-8,8H88a8,8,0,0,1-8-8V64a47.93,47.93,0,0,1,2.75-16H56V216H200Z' } ] },
  refresh: { viewBox: '0 0 256 256', paths: [ { d: 'M216,128a88,88,0,1,1-88-88A88,88,0,0,1,216,128Z', duo: true }, { d: 'M224,48V96a8,8,0,0,1-8,8H168a8,8,0,0,1,0-16h28.69L182.06,73.37a79.56,79.56,0,0,0-56.13-23.43h-.45A79.52,79.52,0,0,0,69.59,72.71,8,8,0,0,1,58.41,61.27a96,96,0,0,1,135,.79L208,76.69V48a8,8,0,0,1,16,0ZM186.41,183.29a80,80,0,0,1-112.47-.66L59.31,168H88a8,8,0,0,0,0-16H40a8,8,0,0,0-8,8v48a8,8,0,0,0,16,0V179.31l14.63,14.63A95.43,95.43,0,0,0,130,222.06h.53a95.36,95.36,0,0,0,67.07-27.33,8,8,0,0,0-11.18-11.44Z' } ] },
  eraser: { viewBox: '0 0 256 256', paths: [ { d: 'M160,168l-48,48H66.75L36.69,185.94a16,16,0,0,1,0-22.63L96,104Z', duo: true }, { d: 'M225,80.4,183.6,39a24,24,0,0,0-33.94,0L31,157.66a24,24,0,0,0,0,33.94l30.06,30.06A8,8,0,0,0,66.74,224H216a8,8,0,0,0,0-16h-84.7L225,114.34A24,24,0,0,0,225,80.4ZM108.68,208H70.05L42.33,180.28a8,8,0,0,1,0-11.31L96,115.31,148.69,168Zm105-105L160,156.69,107.31,104,161,50.34a8,8,0,0,1,11.32,0l41.38,41.38a8,8,0,0,1,0,11.31Z' } ] },
  qr: { viewBox: '0 0 256 256', paths: [ { d: 'M112,56v48a8,8,0,0,1-8,8H56a8,8,0,0,1-8-8V56a8,8,0,0,1,8-8h48A8,8,0,0,1,112,56Zm-8,88H56a8,8,0,0,0-8,8v48a8,8,0,0,0,8,8h48a8,8,0,0,0,8-8V152A8,8,0,0,0,104,144Zm96-96H152a8,8,0,0,0-8,8v48a8,8,0,0,0,8,8h48a8,8,0,0,0,8-8V56A8,8,0,0,0,200,48Z', duo: true }, { d: 'M104,40H56A16,16,0,0,0,40,56v48a16,16,0,0,0,16,16h48a16,16,0,0,0,16-16V56A16,16,0,0,0,104,40Zm0,64H56V56h48v48Zm0,32H56a16,16,0,0,0-16,16v48a16,16,0,0,0,16,16h48a16,16,0,0,0,16-16V152A16,16,0,0,0,104,136Zm0,64H56V152h48v48ZM200,40H152a16,16,0,0,0-16,16v48a16,16,0,0,0,16,16h48a16,16,0,0,0,16-16V56A16,16,0,0,0,200,40Zm0,64H152V56h48v48Zm-64,72V144a8,8,0,0,1,16,0v32a8,8,0,0,1-16,0Zm80-16a8,8,0,0,1-8,8H184v40a8,8,0,0,1-8,8H144a8,8,0,0,1,0-16h24V144a8,8,0,0,1,16,0v8h24A8,8,0,0,1,216,160Zm0,32v16a8,8,0,0,1-16,0V192a8,8,0,0,1,16,0Z' } ] },
  upload: { viewBox: '0 0 256 256', paths: [ { d: 'M224,144v64a8,8,0,0,1-8,8H40a8,8,0,0,1-8-8V144a8,8,0,0,1,16,0v56H208V144a8,8,0,0,1,16,0ZM93.66,77.66,120,51.31V144a8,8,0,0,0,16,0V51.31l26.34,26.35a8,8,0,0,0,11.32-11.32l-40-40a8,8,0,0,0-11.32,0l-40,40A8,8,0,0,0,93.66,77.66Z' } ] },
  folder: { viewBox: '0 0 256 256', paths: [ { d: 'M208,88v24H69.77a8,8,0,0,0-7.59,5.47L32,208V64a8,8,0,0,1,8-8H93.33a8,8,0,0,1,4.8,1.6L128,80h72A8,8,0,0,1,208,88Z', duo: true }, { d: 'M245,110.64A16,16,0,0,0,232,104H216V88a16,16,0,0,0-16-16H130.67L102.94,51.2a16.14,16.14,0,0,0-9.6-3.2H40A16,16,0,0,0,24,64V208a8,8,0,0,0,8,8H211.1a8,8,0,0,0,7.59-5.47l28.49-85.47A16.05,16.05,0,0,0,245,110.64ZM93.34,64,123.2,86.4A8,8,0,0,0,128,88h72v16H69.77a16,16,0,0,0-15.18,10.94L40,158.7V64Zm112,136H43.1l26.67-80H232Z' } ] },
  identity: { viewBox: '0 0 256 256', paths: [ { d: 'M224,128a95.76,95.76,0,0,1-31.8,71.37A72,72,0,0,0,128,160a40,40,0,1,0-40-40,40,40,0,0,0,40,40,72,72,0,0,0-64.2,39.37h0A96,96,0,1,1,224,128Z', duo: true }, { d: 'M128,24A104,104,0,1,0,232,128,104.11,104.11,0,0,0,128,24ZM74.08,197.5a64,64,0,0,1,107.84,0,87.83,87.83,0,0,1-107.84,0ZM96,120a32,32,0,1,1,32,32A32,32,0,0,1,96,120Zm97.76,66.41a79.66,79.66,0,0,0-36.06-28.75,48,48,0,1,0-59.4,0,79.66,79.66,0,0,0-36.06,28.75,88,88,0,1,1,131.52,0Z' } ] },
  contacts: { viewBox: '0 0 256 256', paths: [ { d: 'M208,32H64a8,8,0,0,0-8,8V216a8,8,0,0,0,8,8H208a8,8,0,0,0,8-8V40A8,8,0,0,0,208,32ZM136,144a32,32,0,1,1,32-32A32,32,0,0,1,136,144Z', duo: true }, { d: 'M83.19,174.4a8,8,0,0,0,11.21-1.6,52,52,0,0,1,83.2,0,8,8,0,1,0,12.8-9.6A67.88,67.88,0,0,0,163,141.51a40,40,0,1,0-53.94,0A67.88,67.88,0,0,0,81.6,163.2,8,8,0,0,0,83.19,174.4ZM112,112a24,24,0,1,1,24,24A24,24,0,0,1,112,112Zm96-88H64A16,16,0,0,0,48,40V64H32a8,8,0,0,0,0,16H48v40H32a8,8,0,0,0,0,16H48v40H32a8,8,0,0,0,0,16H48v24a16,16,0,0,0,16,16H208a16,16,0,0,0,16-16V40A16,16,0,0,0,208,24Zm0,192H64V40H208Z' } ] },
  groups: { viewBox: '0 0 256 256', paths: [ { d: 'M168,144a40,40,0,1,1-40-40A40,40,0,0,1,168,144ZM64,56A32,32,0,1,0,96,88,32,32,0,0,0,64,56Zm128,0a32,32,0,1,0,32,32A32,32,0,0,0,192,56Z', duo: true }, { d: 'M244.8,150.4a8,8,0,0,1-11.2-1.6A51.6,51.6,0,0,0,192,128a8,8,0,0,1,0-16,24,24,0,1,0-23.24-30,8,8,0,1,1-15.5-4A40,40,0,1,1,219,117.51a67.94,67.94,0,0,1,27.43,21.68A8,8,0,0,1,244.8,150.4ZM190.92,212a8,8,0,1,1-13.85,8,57,57,0,0,0-98.15,0,8,8,0,1,1-13.84-8,72.06,72.06,0,0,1,33.74-29.92,48,48,0,1,1,58.36,0A72.06,72.06,0,0,1,190.92,212ZM128,176a32,32,0,1,0-32-32A32,32,0,0,0,128,176ZM72,120a8,8,0,0,0-8-8A24,24,0,1,1,87.24,82a8,8,0,1,0,15.5-4A40,40,0,1,0,37,117.51,67.94,67.94,0,0,0,9.6,139.19a8,8,0,1,0,12.8,9.61A51.6,51.6,0,0,1,64,128,8,8,0,0,0,72,120Z' } ] },
  message: { viewBox: '0 0 256 256', paths: [ { d: 'M224,128A96,96,0,0,1,79.93,211.11h0L42.54,223.58a8,8,0,0,1-10.12-10.12l12.47-37.39h0A96,96,0,1,1,224,128Z', duo: true }, { d: 'M128,24A104,104,0,0,0,36.18,176.88L24.83,210.93a16,16,0,0,0,20.24,20.24l34.05-11.35A104,104,0,1,0,128,24Zm0,192a87.87,87.87,0,0,1-44.06-11.81,8,8,0,0,0-4-1.08,7.85,7.85,0,0,0-2.53.42L40,216,52.47,178.6a8,8,0,0,0-.66-6.54A88,88,0,1,1,128,216Zm40-104a8,8,0,0,1-8,8H96a8,8,0,0,1,0-16h64A8,8,0,0,1,168,112Zm0,32a8,8,0,0,1-8,8H96a8,8,0,0,1,0-16h64A8,8,0,0,1,168,144Z' } ] },
  file: { viewBox: '0 0 256 256', paths: [ { d: 'M208,88H152V32Z', duo: true }, { d: 'M213.66,82.34l-56-56A8,8,0,0,0,152,24H56A16,16,0,0,0,40,40V216a16,16,0,0,0,16,16H200a16,16,0,0,0,16-16V88A8,8,0,0,0,213.66,82.34ZM160,51.31,188.69,80H160ZM200,216H56V40h88V88a8,8,0,0,0,8,8h48V216Zm-32-80a8,8,0,0,1-8,8H96a8,8,0,0,1,0-16h64A8,8,0,0,1,168,136Zm0,32a8,8,0,0,1-8,8H96a8,8,0,0,1,0-16h64A8,8,0,0,1,168,168Z' } ] },
  personAdd: { viewBox: '0 0 256 256', paths: [ { d: 'M168,100a60,60,0,1,1-60-60A60,60,0,0,1,168,100Z', duo: true }, { d: 'M256,136a8,8,0,0,1-8,8H232v16a8,8,0,0,1-16,0V144H200a8,8,0,0,1,0-16h16V112a8,8,0,0,1,16,0v16h16A8,8,0,0,1,256,136Zm-57.87,58.85a8,8,0,0,1-12.26,10.3C165.75,181.19,138.09,168,108,168s-57.75,13.19-77.87,37.15a8,8,0,0,1-12.25-10.3c14.94-17.78,33.52-30.41,54.17-37.17a68,68,0,1,1,71.9,0C164.6,164.44,183.18,177.07,198.13,194.85ZM108,152a52,52,0,1,0-52-52A52.06,52.06,0,0,0,108,152Z' } ] },
  trash: { viewBox: '0 0 256 256', paths: [ { d: 'M200,56V208a8,8,0,0,1-8,8H64a8,8,0,0,1-8-8V56Z', duo: true }, { d: 'M216,48H176V40a24,24,0,0,0-24-24H104A24,24,0,0,0,80,40v8H40a8,8,0,0,0,0,16h8V208a16,16,0,0,0,16,16H192a16,16,0,0,0,16-16V64h8a8,8,0,0,0,0-16ZM96,40a8,8,0,0,1,8-8h48a8,8,0,0,1,8,8v8H96Zm96,168H64V64H192ZM112,104v64a8,8,0,0,1-16,0V104a8,8,0,0,1,16,0Zm48,0v64a8,8,0,0,1-16,0V104a8,8,0,0,1,16,0Z' } ] },
  wipe: { viewBox: '0 0 256 256', paths: [ { d: 'M208,144a80,80,0,0,1-160,0c0-30.57,14.42-58.26,31-80l33,32,26.27-72C159.86,41.92,208,88.15,208,144Z', duo: true }, { d: 'M183.89,153.34a57.6,57.6,0,0,1-46.56,46.55A8.75,8.75,0,0,1,136,200a8,8,0,0,1-1.32-15.89c16.57-2.79,30.63-16.85,33.44-33.45a8,8,0,0,1,15.78,2.68ZM216,144a88,88,0,0,1-176,0c0-27.92,11-56.47,32.66-84.85a8,8,0,0,1,11.93-.89l24.12,23.41,22-60.41a8,8,0,0,1,12.63-3.41C165.21,36,216,84.55,216,144Zm-16,0c0-46.09-35.79-85.92-58.21-106.33L119.52,98.74a8,8,0,0,1-13.09,3L80.06,76.16C64.09,99.21,56,122,56,144a72,72,0,0,0,144,0Z' } ] },
  shield: { viewBox: '0 0 256 256', paths: [ { d: 'M216,56v56c0,96-88,120-88,120S40,208,40,112V56a8,8,0,0,1,8-8H208A8,8,0,0,1,216,56Z', duo: true }, { d: 'M208,40H48A16,16,0,0,0,32,56v56c0,52.72,25.52,84.67,46.93,102.19,23.06,18.86,46,25.26,47,25.53a8,8,0,0,0,4.2,0c1-.27,23.91-6.67,47-25.53C198.48,196.67,224,164.72,224,112V56A16,16,0,0,0,208,40Zm0,72c0,37.07-13.66,67.16-40.6,89.42A129.3,129.3,0,0,1,128,223.62a128.25,128.25,0,0,1-38.92-21.81C61.82,179.51,48,149.3,48,112l0-56,160,0ZM82.34,141.66a8,8,0,0,1,11.32-11.32L112,148.69l50.34-50.35a8,8,0,0,1,11.32,11.32l-56,56a8,8,0,0,1-11.32,0Z' } ] },
  undo: { viewBox: '0 0 256 256', paths: [ { d: 'M216,128a88,88,0,1,1-88-88A88,88,0,0,1,216,128Z', duo: true }, { d: 'M224,128a96,96,0,0,1-94.71,96H128A95.38,95.38,0,0,1,62.1,197.8a8,8,0,0,1,11-11.63A80,80,0,1,0,71.43,71.39a3.07,3.07,0,0,1-.26.25L44.59,96H72a8,8,0,0,1,0,16H24a8,8,0,0,1-8-8V56a8,8,0,0,1,16,0V85.8L60.25,60A96,96,0,0,1,224,128Z' } ] },
  check: { viewBox: '0 0 256 256', paths: [ { d: 'M229.66,77.66l-128,128a8,8,0,0,1-11.32,0l-56-56a8,8,0,0,1,11.32-11.32L96,188.69,218.34,66.34a8,8,0,0,1,11.32,11.32Z' } ] },
  help: { viewBox: '0 0 256 256', paths: [ { d: 'M224,128a96,96,0,1,1-96-96A96,96,0,0,1,224,128Z', duo: true }, { d: 'M140,180a12,12,0,1,1-12-12A12,12,0,0,1,140,180ZM128,72c-22.06,0-40,16.15-40,36v4a8,8,0,0,0,16,0v-4c0-11,10.77-20,24-20s24,9,24,20-10.77,20-24,20a8,8,0,0,0-8,8v8a8,8,0,0,0,16,0v-.72c18.24-3.35,32-17.9,32-35.28C168,88.15,150.06,72,128,72Zm104,56A104,104,0,1,1,128,24,104.11,104.11,0,0,1,232,128Zm-16,0a88,88,0,1,0-88,88A88.1,88.1,0,0,0,216,128Z' } ] },
  palette: { viewBox: '0 0 256 256', paths: [ { d: 'M224,127.17a96.48,96.48,0,0,1-2.39,22.18A24,24,0,0,1,198.21,168H152a24,24,0,0,0-24,24,24,24,0,0,1-32,22.61C58.73,201.44,32,169.81,32,128a96,96,0,0,1,95-96C179.84,31.47,223.55,74.35,224,127.17Z', duo: true }, { d: 'M200.77,53.89A103.27,103.27,0,0,0,128,24h-1.07A104,104,0,0,0,24,128c0,43,26.58,79.06,69.36,94.17A32,32,0,0,0,136,192a16,16,0,0,1,16-16h46.21a31.81,31.81,0,0,0,31.2-24.88,104.43,104.43,0,0,0,2.59-24A103.28,103.28,0,0,0,200.77,53.89Zm13,93.71A15.89,15.89,0,0,1,198.21,160H152a32,32,0,0,0-32,32,16,16,0,0,1-21.31,15.07C62.49,194.3,40,164,40,128a88,88,0,0,1,87.09-88h.9a88.35,88.35,0,0,1,88,87.25A88.86,88.86,0,0,1,213.81,147.6ZM140,76a12,12,0,1,1-12-12A12,12,0,0,1,140,76ZM96,100A12,12,0,1,1,84,88,12,12,0,0,1,96,100Zm0,56a12,12,0,1,1-12-12A12,12,0,0,1,96,156Zm88-56a12,12,0,1,1-12-12A12,12,0,0,1,184,100Z' } ] },
  sound: { viewBox: '0 0 256 256', paths: [ { d: 'M80,88v80H32a8,8,0,0,1-8-8V96a8,8,0,0,1,8-8Z', duo: true }, { d: 'M155.51,24.81a8,8,0,0,0-8.42.88L77.25,80H32A16,16,0,0,0,16,96v64a16,16,0,0,0,16,16H77.25l69.84,54.31A8,8,0,0,0,160,224V32A8,8,0,0,0,155.51,24.81ZM32,96H72v64H32ZM144,207.64,88,164.09V91.91l56-43.55Zm54-106.08a40,40,0,0,1,0,52.88,8,8,0,0,1-12-10.58,24,24,0,0,0,0-31.72,8,8,0,0,1,12-10.58ZM248,128a79.9,79.9,0,0,1-20.37,53.34,8,8,0,0,1-11.92-10.67,64,64,0,0,0,0-85.33,8,8,0,1,1,11.92-10.67A79.83,79.83,0,0,1,248,128Z' } ] },
  soundOff: { viewBox: '0 0 256 256', paths: [ { d: 'M80,88v80H32a8,8,0,0,1-8-8V96a8,8,0,0,1,8-8Z', duo: true }, { d: 'M53.92,34.62A8,8,0,1,0,42.08,45.38L73.55,80H32A16,16,0,0,0,16,96v64a16,16,0,0,0,16,16H77.25l69.84,54.31A8,8,0,0,0,160,224V175.09l42.08,46.29a8,8,0,1,0,11.84-10.76ZM32,96H72v64H32ZM144,207.64,88,164.09V95.89l56,61.6Zm42-63.77a24,24,0,0,0,0-31.72,8,8,0,1,1,12-10.57,40,40,0,0,1,0,52.88,8,8,0,0,1-12-10.59Zm-80.16-76a8,8,0,0,1,1.4-11.23l39.85-31A8,8,0,0,1,160,32v74.83a8,8,0,0,1-16,0V48.36l-26.94,21A8,8,0,0,1,105.84,67.91ZM248,128a79.9,79.9,0,0,1-20.37,53.34,8,8,0,0,1-11.92-10.67,64,64,0,0,0,0-85.33,8,8,0,1,1,11.92-10.67A79.83,79.83,0,0,1,248,128Z' } ] },
  pause: { viewBox: '0 0 256 256', paths: [ { d: 'M208,48V208a8,8,0,0,1-8,8H160a8,8,0,0,1-8-8V48a8,8,0,0,1,8-8h40A8,8,0,0,1,208,48ZM96,40H56a8,8,0,0,0-8,8V208a8,8,0,0,0,8,8H96a8,8,0,0,0,8-8V48A8,8,0,0,0,96,40Z', duo: true }, { d: 'M200,32H160a16,16,0,0,0-16,16V208a16,16,0,0,0,16,16h40a16,16,0,0,0,16-16V48A16,16,0,0,0,200,32Zm0,176H160V48h40ZM96,32H56A16,16,0,0,0,40,48V208a16,16,0,0,0,16,16H96a16,16,0,0,0,16-16V48A16,16,0,0,0,96,32Zm0,176H56V48H96Z' } ] },
  play: { viewBox: '0 0 256 256', paths: [ { d: 'M228.23,134.69,84.15,222.81A8,8,0,0,1,72,216.12V39.88a8,8,0,0,1,12.15-6.69l144.08,88.12A7.82,7.82,0,0,1,228.23,134.69Z', duo: true }, { d: 'M232.4,114.49,88.32,26.35a16,16,0,0,0-16.2-.3A15.86,15.86,0,0,0,64,39.87V216.13A15.94,15.94,0,0,0,80,232a16.07,16.07,0,0,0,8.36-2.35L232.4,141.51a15.81,15.81,0,0,0,0-27ZM80,215.94V40l143.83,88Z' } ] },
  chevron: { viewBox: '0 0 256 256', paths: [ { d: 'M213.66,101.66l-80,80a8,8,0,0,1-11.32,0l-80-80A8,8,0,0,1,53.66,90.34L128,164.69l74.34-74.35a8,8,0,0,1,11.32,11.32Z' } ] },
  cancel: { viewBox: '0 0 256 256', paths: [ { d: 'M224,128a96,96,0,1,1-96-96A96,96,0,0,1,224,128Z', duo: true }, { d: 'M165.66,101.66,139.31,128l26.35,26.34a8,8,0,0,1-11.32,11.32L128,139.31l-26.34,26.35a8,8,0,0,1-11.32-11.32L116.69,128,90.34,101.66a8,8,0,0,1,11.32-11.32L128,116.69l26.34-26.35a8,8,0,0,1,11.32,11.32ZM232,128A104,104,0,1,1,128,24,104.11,104.11,0,0,1,232,128Zm-16,0a88,88,0,1,0-88,88A88.1,88.1,0,0,0,216,128Z' } ] },
  download: { viewBox: '0 0 256 256', paths: [ { d: 'M224,144v64a8,8,0,0,1-8,8H40a8,8,0,0,1-8-8V144a8,8,0,0,1,16,0v56H208V144a8,8,0,0,1,16,0Zm-101.66,5.66a8,8,0,0,0,11.32,0l40-40a8,8,0,0,0-11.32-11.32L136,124.69V32a8,8,0,0,0-16,0v92.69L93.66,98.34a8,8,0,0,0-11.32,11.32Z' } ] },
  share: { viewBox: '0 0 256 256', paths: [ { d: 'M208,200a32,32,0,1,1-32-32A32,32,0,0,1,208,200ZM176,88a32,32,0,1,0-32-32A32,32,0,0,0,176,88Z', duo: true }, { d: 'M176,160a39.89,39.89,0,0,0-28.62,12.09l-46.1-29.63a39.8,39.8,0,0,0,0-28.92l46.1-29.63a40,40,0,1,0-8.66-13.45l-46.1,29.63a40,40,0,1,0,0,55.82l46.1,29.63A40,40,0,1,0,176,160Zm0-128a24,24,0,1,1-24,24A24,24,0,0,1,176,32ZM64,152a24,24,0,1,1,24-24A24,24,0,0,1,64,152Zm112,72a24,24,0,1,1,24-24A24,24,0,0,1,176,224Z' } ] },
  scan: { viewBox: '0 0 256 256', paths: [ { d: 'M176,80v96H80V80Z', duo: true }, { d: 'M224,40V80a8,8,0,0,1-16,0V48H176a8,8,0,0,1,0-16h40A8,8,0,0,1,224,40ZM80,208H48V176a8,8,0,0,0-16,0v40a8,8,0,0,0,8,8H80a8,8,0,0,0,0-16Zm136-40a8,8,0,0,0-8,8v32H176a8,8,0,0,0,0,16h40a8,8,0,0,0,8-8V176A8,8,0,0,0,216,168ZM40,88a8,8,0,0,0,8-8V48H80a8,8,0,0,0,0-16H40a8,8,0,0,0-8,8V80A8,8,0,0,0,40,88ZM80,72h96a8,8,0,0,1,8,8v96a8,8,0,0,1-8,8H80a8,8,0,0,1-8-8V80A8,8,0,0,1,80,72Zm8,96h80V88H88Z' } ] },
  sliders: { viewBox: '0 0 256 256', paths: [ { d: 'M128,80a24,24,0,1,1-24-24A24,24,0,0,1,128,80Zm40,72a24,24,0,1,0,24,24A24,24,0,0,0,168,152Z', duo: true }, { d: 'M40,88H73a32,32,0,0,0,62,0h81a8,8,0,0,0,0-16H135a32,32,0,0,0-62,0H40a8,8,0,0,0,0,16Zm64-24A16,16,0,1,1,88,80,16,16,0,0,1,104,64ZM216,168H199a32,32,0,0,0-62,0H40a8,8,0,0,0,0,16h97a32,32,0,0,0,62,0h17a8,8,0,0,0,0-16Zm-48,24a16,16,0,1,1,16-16A16,16,0,0,1,168,192Z' } ] },
  clock: { viewBox: '0 0 256 256', paths: [ { d: 'M224,128a96,96,0,1,1-96-96A96,96,0,0,1,224,128Z', duo: true }, { d: 'M128,24A104,104,0,1,0,232,128,104.11,104.11,0,0,0,128,24Zm0,192a88,88,0,1,1,88-88A88.1,88.1,0,0,1,128,216Zm64-88a8,8,0,0,1-8,8H128a8,8,0,0,1-8-8V72a8,8,0,0,1,16,0v48h48A8,8,0,0,1,192,128Z' } ] },
  deleteAll: { viewBox: '0 0 256 256', fx: 'shake', paths: [ { d: 'M224,91.55v72.9a8,8,0,0,1-2.34,5.66l-51.55,51.55a8,8,0,0,1-5.66,2.34H91.55a8,8,0,0,1-5.66-2.34L34.34,170.11A8,8,0,0,1,32,164.45V91.55a8,8,0,0,1,2.34-5.66L85.89,34.34A8,8,0,0,1,91.55,32h72.9a8,8,0,0,1,5.66,2.34l51.55,51.55A8,8,0,0,1,224,91.55Z', duo: true }, { d: 'M120,136V80a8,8,0,0,1,16,0v56a8,8,0,0,1-16,0ZM232,91.55v72.9a15.86,15.86,0,0,1-4.69,11.31l-51.55,51.55A15.86,15.86,0,0,1,164.45,232H91.55a15.86,15.86,0,0,1-11.31-4.69L28.69,175.76A15.86,15.86,0,0,1,24,164.45V91.55a15.86,15.86,0,0,1,4.69-11.31L80.24,28.69A15.86,15.86,0,0,1,91.55,24h72.9a15.86,15.86,0,0,1,11.31,4.69l51.55,51.55A15.86,15.86,0,0,1,232,91.55Zm-16,0L164.45,40H91.55L40,91.55v72.9L91.55,216h72.9L216,164.45ZM128,160a12,12,0,1,0,12,12A12,12,0,0,0,128,160Z' } ] },
  rocket: { viewBox: '0 0 256 256', paths: [ { d: 'M184,120v61.65a8,8,0,0,1-2.34,5.65l-34.35,34.35a8,8,0,0,1-13.57-4.53L128,176ZM136,72H74.35a8,8,0,0,0-5.65,2.34L34.35,108.69a8,8,0,0,0,4.53,13.57L80,128ZM40,216c37.65,0,50.69-19.69,54.56-28.18L68.18,161.44C59.69,165.31,40,178.35,40,216Z', duo: true }, { d: 'M223.85,47.12a16,16,0,0,0-15-15c-12.58-.75-44.73.4-71.41,27.07L132.69,64H74.36A15.91,15.91,0,0,0,63,68.68L28.7,103a16,16,0,0,0,9.07,27.16l38.47,5.37,44.21,44.21,5.37,38.49a15.94,15.94,0,0,0,10.78,12.92,16.11,16.11,0,0,0,5.1.83A15.91,15.91,0,0,0,153,227.3L187.32,193A15.91,15.91,0,0,0,192,181.64V123.31l4.77-4.77C223.45,91.86,224.6,59.71,223.85,47.12ZM74.36,80h42.33L77.16,119.52,40,114.34Zm74.41-9.45a76.65,76.65,0,0,1,59.11-22.47,76.46,76.46,0,0,1-22.42,59.16L128,164.68,91.32,128ZM176,181.64,141.67,216l-5.19-37.17L176,139.31Zm-74.16,9.5C97.34,201,82.29,224,40,224a8,8,0,0,1-8-8c0-42.29,23-57.34,32.86-61.85a8,8,0,0,1,6.64,14.56c-6.43,2.93-20.62,12.36-23.12,38.91,26.55-2.5,36-16.69,38.91-23.12a8,8,0,1,1,14.56,6.64Z' } ] },
  keyPair: { viewBox: '0 0 256 256', paths: [ { d: 'M232,98.36C230.73,136.92,198.67,168,160.09,168a71.68,71.68,0,0,1-26.92-5.17h0L120,176H96v24H72v24H40a8,8,0,0,1-8-8V187.31a8,8,0,0,1,2.34-5.65l58.83-58.83h0A71.68,71.68,0,0,1,88,95.91c0-38.58,31.08-70.64,69.64-71.87A72,72,0,0,1,232,98.36Z', duo: true }, { d: 'M216.57,39.43A80,80,0,0,0,83.91,120.78L28.69,176A15.86,15.86,0,0,0,24,187.31V216a16,16,0,0,0,16,16H72a8,8,0,0,0,8-8V208H96a8,8,0,0,0,8-8V184h16a8,8,0,0,0,5.66-2.34l9.56-9.57A79.73,79.73,0,0,0,160,176h.1A80,80,0,0,0,216.57,39.43ZM224,98.1c-1.09,34.09-29.75,61.86-63.89,61.9H160a63.7,63.7,0,0,1-23.65-4.51,8,8,0,0,0-8.84,1.68L116.69,168H96a8,8,0,0,0-8,8v16H72a8,8,0,0,0-8,8v16H40V187.31l58.83-58.82a8,8,0,0,0,1.68-8.84A63.72,63.72,0,0,1,96,95.92c0-34.14,27.81-62.8,61.9-63.89A64,64,0,0,1,224,98.1ZM192,76a12,12,0,1,1-12-12A12,12,0,0,1,192,76Z' } ] },
  chatLock: { viewBox: '0 0 256 256', paths: [ { d: 'M224,128A96,96,0,0,1,79.93,211.11h0L42.54,223.58a8,8,0,0,1-10.12-10.12l12.47-37.39h0A96,96,0,1,1,224,128Z', duo: true }, { d: 'M128,24A104,104,0,0,0,36.18,176.88L24.83,210.93a16,16,0,0,0,20.24,20.24l34.05-11.35A104,104,0,1,0,128,24Zm0,192a87.87,87.87,0,0,1-44.06-11.81,8,8,0,0,0-4-1.08,7.85,7.85,0,0,0-2.53.42L40,216,52.47,178.6a8,8,0,0,0-.66-6.54A88,88,0,1,1,128,216Zm12-88a12,12,0,1,1-12-12A12,12,0,0,1,140,128Zm-44,0a12,12,0,1,1-12-12A12,12,0,0,1,96,128Zm88,0a12,12,0,1,1-12-12A12,12,0,0,1,184,128Z' } ] },
  ruler: { viewBox: '0 0 256 256', paths: [ { d: 'M229.66,90.34,90.34,229.66a8,8,0,0,1-11.31,0L26.34,177a8,8,0,0,1,0-11.31L165.66,26.34a8,8,0,0,1,11.31,0L229.66,79A8,8,0,0,1,229.66,90.34Z', duo: true }, { d: 'M235.32,73.37,182.63,20.69a16,16,0,0,0-22.63,0L20.68,160a16,16,0,0,0,0,22.63l52.69,52.68a16,16,0,0,0,22.63,0L235.32,96A16,16,0,0,0,235.32,73.37ZM84.68,224,32,171.31l32-32,26.34,26.35a8,8,0,0,0,11.32-11.32L75.31,128,96,107.31l26.34,26.35a8,8,0,0,0,11.32-11.32L107.31,96,128,75.31l26.34,26.35a8,8,0,0,0,11.32-11.32L139.31,64l32-32L224,84.69Z' } ] },
  fileShield: { viewBox: '0 0 256 256', paths: [ { d: 'M48,184h72v40H48ZM152,32V88h56Z', duo: true }, { d: 'M120,176h-8v-4a28,28,0,0,0-56,0v4H48a8,8,0,0,0-8,8v40a8,8,0,0,0,8,8h72a8,8,0,0,0,8-8V184A8,8,0,0,0,120,176Zm-48-4a12,12,0,0,1,24,0v4H72Zm40,44H56V192h56ZM213.66,82.34l-56-56A8,8,0,0,0,152,24H56A16,16,0,0,0,40,40v88a8,8,0,0,0,16,0V40h88V88a8,8,0,0,0,8,8h48V216H160a8,8,0,0,0,0,16h40a16,16,0,0,0,16-16V88A8,8,0,0,0,213.66,82.34ZM160,51.31,188.69,80H160Z' } ] },
  fingerprint: { viewBox: '0 0 256 256', paths: [ { d: 'M224,128a96,96,0,1,1-96-96A96,96,0,0,1,224,128Z', duo: true }, { d: 'M72,128a134.63,134.63,0,0,1-14.16,60.47,8,8,0,1,1-14.32-7.12A118.8,118.8,0,0,0,56,128,71.73,71.73,0,0,1,83,71.8,8,8,0,1,1,93,84.29,55.76,55.76,0,0,0,72,128Zm56-8a8,8,0,0,0-8,8,184.12,184.12,0,0,1-23,89.1,8,8,0,0,0,14,7.76A200.19,200.19,0,0,0,136,128,8,8,0,0,0,128,120Zm0-32a40,40,0,0,0-40,40,8,8,0,0,0,16,0,24,24,0,0,1,48,0,214.09,214.09,0,0,1-20.51,92A8,8,0,1,0,146,226.83,230,230,0,0,0,168,128,40,40,0,0,0,128,88Zm0-64A104.11,104.11,0,0,0,24,128a87.76,87.76,0,0,1-5,29.33,8,8,0,0,0,15.09,5.33A103.9,103.9,0,0,0,40,128a88,88,0,0,1,176,0,282.24,282.24,0,0,1-5.29,54.45,8,8,0,0,0,6.3,9.4,8.22,8.22,0,0,0,1.55.15,8,8,0,0,0,7.84-6.45A298.37,298.37,0,0,0,232,128,104.12,104.12,0,0,0,128,24ZM94.4,152.17A8,8,0,0,0,85,158.42a151,151,0,0,1-17.21,45.44,8,8,0,0,0,13.86,8,166.67,166.67,0,0,0,19-50.25A8,8,0,0,0,94.4,152.17ZM128,56a72.85,72.85,0,0,0-9,.56,8,8,0,0,0,2,15.87A56.08,56.08,0,0,1,184,128a252.12,252.12,0,0,1-1.92,31A8,8,0,0,0,189,168a8.39,8.39,0,0,0,1,.06,8,8,0,0,0,7.92-7,266.48,266.48,0,0,0,2-33A72.08,72.08,0,0,0,128,56Zm57.93,128.25a8,8,0,0,0-9.75,5.75c-1.46,5.69-3.15,11.4-5,17a8,8,0,0,0,5,10.13,7.88,7.88,0,0,0,2.55.42,8,8,0,0,0,7.58-5.46c2-5.92,3.79-12,5.35-18.05A8,8,0,0,0,185.94,184.26Z' } ] },
  keyOff: { viewBox: '0 0 256 256', paths: [ { d: 'M224,128a96,96,0,1,1-96-96A96,96,0,0,1,224,128Z', duo: true }, { d: 'M128,24A104,104,0,1,0,232,128,104.11,104.11,0,0,0,128,24Zm88,104a87.56,87.56,0,0,1-20.41,56.28L71.72,60.4A88,88,0,0,1,216,128ZM40,128A87.56,87.56,0,0,1,60.41,71.72L184.28,195.6A88,88,0,0,1,40,128Z' } ] },
  cloudUpload: { viewBox: '0 0 256 256', paths: [ { d: 'M240,128a80,80,0,0,1-80,80H72A56,56,0,1,1,85.92,97.74l0,.1A80,80,0,0,1,240,128Z', duo: true }, { d: 'M178.34,165.66,160,147.31V208a8,8,0,0,1-16,0V147.31l-18.34,18.35a8,8,0,0,1-11.32-11.32l32-32a8,8,0,0,1,11.32,0l32,32a8,8,0,0,1-11.32,11.32ZM160,40A88.08,88.08,0,0,0,81.29,88.68,64,64,0,1,0,72,216h40a8,8,0,0,0,0-16H72a48,48,0,0,1,0-96c1.1,0,2.2,0,3.29.12A88,88,0,0,0,72,128a8,8,0,0,0,16,0,72,72,0,1,1,100.8,66,8,8,0,0,0,3.2,15.34,7.9,7.9,0,0,0,3.2-.68A88,88,0,0,0,160,40Z' } ] },
  wifiOff: { viewBox: '0 0 256 256', paths: [ { d: 'M238.2,87.69l-104,125.43a8,8,0,0,1-12.3,0L17.8,87.69a7.79,7.79,0,0,1,1.31-11.21,180.75,180.75,0,0,1,217.78,0A7.79,7.79,0,0,1,238.2,87.69Z', duo: true }, { d: 'M53.92,34.62A8,8,0,1,0,42.08,45.38l4.55,5A187.93,187.93,0,0,0,14.28,70.1,15.93,15.93,0,0,0,8.11,80.91,15.65,15.65,0,0,0,11.65,92.8l104,125.43A15.93,15.93,0,0,0,128,224h0a15.93,15.93,0,0,0,12.31-5.77l28.1-33.88,33.67,37a8,8,0,1,0,11.84-10.76ZM128,208,24.09,82.74A171.5,171.5,0,0,1,57.91,62.79l99.63,109.6ZM244.35,92.8l-49.42,59.58a8,8,0,0,1-12.32-10.21l49.3-59.43A170.76,170.76,0,0,0,128,48a175.15,175.15,0,0,0-32.39,3,8,8,0,1,1-3-15.72A190.62,190.62,0,0,1,128,32,186.67,186.67,0,0,1,241.72,70.1a15.93,15.93,0,0,1,6.17,10.81A15.65,15.65,0,0,1,244.35,92.8Z' } ] },
  alertTriangle: { viewBox: '0 0 256 256', paths: [ { d: 'M215.46,216H40.54C27.92,216,20,202.79,26.13,192.09L113.59,40.22c6.3-11,22.52-11,28.82,0l87.46,151.87C236,202.79,228.08,216,215.46,216Z', duo: true }, { d: 'M236.8,188.09,149.35,36.22h0a24.76,24.76,0,0,0-42.7,0L19.2,188.09a23.51,23.51,0,0,0,0,23.72A24.35,24.35,0,0,0,40.55,224h174.9a24.35,24.35,0,0,0,21.33-12.19A23.51,23.51,0,0,0,236.8,188.09ZM222.93,203.8a8.5,8.5,0,0,1-7.48,4.2H40.55a8.5,8.5,0,0,1-7.48-4.2,7.59,7.59,0,0,1,0-7.72L120.52,44.21a8.75,8.75,0,0,1,15,0l87.45,151.87A7.59,7.59,0,0,1,222.93,203.8ZM120,144V104a8,8,0,0,1,16,0v40a8,8,0,0,1-16,0Zm20,36a12,12,0,1,1-12-12A12,12,0,0,1,140,180Z' } ] },
  helpCircle: { viewBox: '0 0 256 256', paths: [ { d: 'M224,128a96,96,0,1,1-96-96A96,96,0,0,1,224,128Z', duo: true }, { d: 'M140,180a12,12,0,1,1-12-12A12,12,0,0,1,140,180ZM128,72c-22.06,0-40,16.15-40,36v4a8,8,0,0,0,16,0v-4c0-11,10.77-20,24-20s24,9,24,20-10.77,20-24,20a8,8,0,0,0-8,8v8a8,8,0,0,0,16,0v-.72c18.24-3.35,32-17.9,32-35.28C168,88.15,150.06,72,128,72Zm104,56A104,104,0,1,1,128,24,104.11,104.11,0,0,1,232,128Zm-16,0a88,88,0,1,0-88,88A88.1,88.1,0,0,0,216,128Z' } ] },
  code2: { viewBox: '0 0 256 256', paths: [ { d: 'M240,128l-48,40H64L16,128,64,88H192Z', duo: true }, { d: 'M69.12,94.15,28.5,128l40.62,33.85a8,8,0,1,1-10.24,12.29l-48-40a8,8,0,0,1,0-12.29l48-40a8,8,0,0,1,10.24,12.3Zm176,27.7-48-40a8,8,0,1,0-10.24,12.3L227.5,128l-40.62,33.85a8,8,0,1,0,10.24,12.29l48-40a8,8,0,0,0,0-12.29ZM162.73,32.48a8,8,0,0,0-10.25,4.79l-64,176a8,8,0,0,0,4.79,10.26A8.14,8.14,0,0,0,96,224a8,8,0,0,0,7.52-5.27l64-176A8,8,0,0,0,162.73,32.48Z' } ] },
  unlock: { viewBox: '0 0 256 256', paths: [ { d: 'M216,96V208a8,8,0,0,1-8,8H48a8,8,0,0,1-8-8V96a8,8,0,0,1,8-8H208A8,8,0,0,1,216,96Z', duo: true }, { d: 'M208,80H96V56a32,32,0,0,1,32-32c15.37,0,29.2,11,32.16,25.59a8,8,0,0,0,15.68-3.18C171.32,24.15,151.2,8,128,8A48.05,48.05,0,0,0,80,56V80H48A16,16,0,0,0,32,96V208a16,16,0,0,0,16,16H208a16,16,0,0,0,16-16V96A16,16,0,0,0,208,80Zm0,128H48V96H208V208Zm-68-56a12,12,0,1,1-12-12A12,12,0,0,1,140,152Z' } ] }
};
function applyIcons(root) { (root || document).querySelectorAll('[data-icon]').forEach(function (el) { setIcon(el, el.getAttribute('data-icon')); }); }
// Only classes meant to style an *icon* (icon-anim, icon-hero, icon-drop, icon-spin, ...)
// are ever copied onto the generated <svg>. Copying the host element's full className
// (its old behaviour) meant a button like .help-dot — which itself sets width/height/
// border/background/border-radius — re-applied those same rules to the icon glyph inside
// it, stretching and boxing the icon instead of showing it. This is why some icons
// (notably the help button) rendered incorrectly.
function iconIntrinsicClasses(el) {
  return (el.className || '').split(/\s+/).filter(function (c) { return c.indexOf('icon-') === 0; }).join(' ');
}
function setIcon(el, name) { el.innerHTML = iconSvg(name, iconIntrinsicClasses(el)); }
function iconSvg(name, extraClass) {
  const spec = ICONS[name];
  if (!spec) return '';
  const cls = ('icon ' + (extraClass || '')).trim();
  // An icon spec is either a plain path string (legacy) or { paths, viewBox, accent }
  // allowing a two-tone accent stroke for a more finished, professional look, and a
  // per-icon animation hook (data-icon-fx, driven purely by CSS) for subtle motion.
  const isObj = typeof spec === 'object';
  const viewBox = isObj && spec.viewBox ? spec.viewBox : '0 0 24 24';
  const fx = isObj && spec.fx ? ' data-icon-fx="' + spec.fx + '"' : '';
  let inner;
  if (isObj) {
    const shapes = spec.shapes || spec.paths || [];
    inner = shapes.map(function (p) {
      const strokeFam = spec.stroke || p.stroke;
      const strokeAttrs = strokeFam ? ' fill="none" stroke="currentColor" stroke-width="' + (p.width || spec.width || 1.7) + '" stroke-linecap="round" stroke-linejoin="round"' : '';
      const accentCls = p.accent ? ' icon-accent' : '';
      const cls2 = ' class="icon-part' + accentCls + (p.duo ? ' icon-duo' : '') + '"';
      switch (p.tag) {
        case 'circle': return '<circle' + cls2 + ' cx="' + p.cx + '" cy="' + p.cy + '" r="' + p.r + '"' + strokeAttrs + '/>';
        case 'line': return '<line' + cls2 + ' x1="' + p.x1 + '" y1="' + p.y1 + '" x2="' + p.x2 + '" y2="' + p.y2 + '"' + strokeAttrs + '/>';
        case 'rect': return '<rect' + cls2 + ' x="' + p.x + '" y="' + p.y + '" width="' + p.w + '" height="' + p.h + '" rx="' + (p.rx || 0) + '"' + strokeAttrs + '/>';
        default: return '<path' + cls2 + ' d="' + p.d + '"' + strokeAttrs + '/>';
      }
    }).join('');
  } else {
    inner = '<path d="' + spec + '"/>';
  }
  return '<svg class="' + cls + '" viewBox="' + viewBox + '" fill="currentColor" aria-hidden="true" focusable="false"' + fx + '>' + inner + '</svg>';
}
function escapeHtml(str) { const d = document.createElement('div'); d.textContent = String(str); return d.innerHTML; }

// ====================================================================================
// STATUS BAR + LOG
// ====================================================================================
let lastStatus = { key: 'status.ready', params: null, isError: false };
let logEntries = [];
const LOG_LIMIT = 100;
const STATUS_AUTO_HIDE_MS = 4000;      // normal messages
const STATUS_AUTO_HIDE_ERROR_MS = 7000; // errors get longer on screen before auto-hiding
let statusHideTimer = null;

function updateStatus(key, params, isError) { lastStatus = { key: key, params: params || null, isError: !!isError }; renderStatus(); }
function renderStatus() {
  const bar = document.getElementById('statusBar');
  if (!bar) return;
  bar.textContent = t(lastStatus.key, lastStatus.params);
  bar.classList.toggle('is-error', lastStatus.isError);
  // A fixed-position status bar with no auto-hide sits over whatever scrollable content
  // happens to occupy that same screen region indefinitely — very visible on taller forms.
  // Auto-hide after a few seconds like any other toast/snackbar; a fresh status restarts the
  // timer rather than stacking, so a burst of updates doesn't make the bar flicker on and off.
  if (statusHideTimer) clearTimeout(statusHideTimer);
  statusHideTimer = setTimeout(function () {
    bar.textContent = '';
    statusHideTimer = null;
  }, lastStatus.isError ? STATUS_AUTO_HIDE_ERROR_MS : STATUS_AUTO_HIDE_MS);
}
function addLog(key, params) {
  if (!loggingEnabled) return;
  logEntries.unshift({ time: new Date().toLocaleTimeString(), key: key, params: params || null });
  if (logEntries.length > LOG_LIMIT) logEntries.length = LOG_LIMIT;
  renderLogs();
}
function renderLogs() {
  const box = document.getElementById('logContent');
  if (!box) return;
  box.textContent = '';
  logEntries.forEach(function (e) {
    const line = document.createElement('div');
    line.textContent = '[' + e.time + '] ' + t(e.key, e.params);
    box.appendChild(line);
  });
}
function clearLogs() { playSound('click'); logEntries = []; renderLogs(); }
function toggleLogStatus() { playSound('click'); loggingEnabled = !loggingEnabled; renderDynamicText(); }

function showError(key, params) {
  updateStatus(key, params, true);
  const prev = loggingEnabled;
  loggingEnabled = true;
  addLog(key, params);
  loggingEnabled = prev;
}

window.addEventListener('error', function (ev) { updateStatus('status.unexpected', { msg: (ev && ev.message) ? ev.message : 'unknown' }, true); });
window.addEventListener('unhandledrejection', function (ev) {
  const r = ev && ev.reason;
  updateStatus('status.unexpected', { msg: (r && r.message) ? r.message : String(r) }, true);
});

// ====================================================================================
// SOUND
// ====================================================================================
let audioCtx = null;
function playSound(type) {
  if (!audioEnabled) return;
  try {
    const AC = window.AudioContext || window.webkitAudioContext;
    if (!AC) return;
    if (!audioCtx) audioCtx = new AC();
    if (audioCtx.state === 'suspended' && audioCtx.resume) { const p = audioCtx.resume(); if (p && p.catch) p.catch(function () {}); }
    if (audioCtx.state !== 'running') return;
    const osc = audioCtx.createOscillator();
    const gain = audioCtx.createGain();
    osc.connect(gain); gain.connect(audioCtx.destination);
    if (type === 'click') {
      osc.frequency.setValueAtTime(800, audioCtx.currentTime);
      gain.gain.setValueAtTime(0.05, audioCtx.currentTime);
      osc.start(); osc.stop(audioCtx.currentTime + 0.05);
    } else if (type === 'lock') {
      osc.frequency.setValueAtTime(400, audioCtx.currentTime);
      osc.frequency.exponentialRampToValueAtTime(800, audioCtx.currentTime + 0.15);
      gain.gain.setValueAtTime(0.1, audioCtx.currentTime);
      osc.start(); osc.stop(audioCtx.currentTime + 0.15);
    } else if (type === 'unlock') {
      osc.frequency.setValueAtTime(800, audioCtx.currentTime);
      osc.frequency.exponentialRampToValueAtTime(400, audioCtx.currentTime + 0.15);
      gain.gain.setValueAtTime(0.1, audioCtx.currentTime);
      osc.start(); osc.stop(audioCtx.currentTime + 0.15);
    }
  } catch (e) { /* sound is optional */ }
}
function toggleAudio() {
  audioEnabled = !audioEnabled;
  try { localStorage.setItem('anigma_sound', audioEnabled ? '1' : '0'); } catch (e) {}
  renderDynamicText();
  if (audioEnabled) playSound('click');
}

// ====================================================================================
// CLIPBOARD
// ====================================================================================
async function copyToClipboard(text) {
  if (!text) return false;
  try { if (navigator.clipboard && window.isSecureContext) { await navigator.clipboard.writeText(text); return true; } } catch (e) {}
  try {
    const ta = document.createElement('textarea');
    ta.value = text; ta.setAttribute('readonly', ''); ta.style.position = 'fixed'; ta.style.top = '-1000px'; ta.style.opacity = '0';
    document.body.appendChild(ta); ta.select(); ta.setSelectionRange(0, text.length);
    const ok = document.execCommand('copy'); document.body.removeChild(ta);
    return !!ok;
  } catch (e) { return false; }
}
async function readFromClipboard() {
  if (navigator.clipboard && navigator.clipboard.readText && window.isSecureContext) return await navigator.clipboard.readText();
  throw new Error('clipboard-unavailable');
}
const CLIPBOARD_CLEAR_MS = 30000;
// For copies of decrypted plaintext: best-effort auto-clear after CLIPBOARD_CLEAR_MS, so a
// secret doesn't sit in the system clipboard indefinitely. "Best-effort" because: (a) the
// Clipboard API requires a page permission we may not have to read it back and confirm
// it's still ours before clearing, in which case we just clear unconditionally, and (b) on
// some platforms other apps can also read/replace the OS clipboard in the meantime, which
// this can't detect or prevent either way.
function copySensitiveToClipboard(text) {
  return copyToClipboard(text).then(function (ok) {
    if (ok && text) {
      setTimeout(async function () {
        try {
          let current = null;
          try { current = await readFromClipboard(); } catch (e) { /* no read permission — clear anyway below */ }
          if (current === null || current === text) await copyToClipboard('');
        } catch (e) { /* best-effort only */ }
      }, CLIPBOARD_CLEAR_MS);
    }
    return ok;
  });
}

// ====================================================================================
// MENU / THEME / MODALS
// ====================================================================================
function toggleMenu() { playSound('click'); isMenuOpen = !isMenuOpen; applyMenuState(); }
function closeMenu() { if (!isMenuOpen) return; playSound('click'); isMenuOpen = false; applyMenuState(); }
function applyMenuState() {
  const menu = document.getElementById('sideMenu');
  const overlay = document.getElementById('menuOverlay');
  menu.classList.toggle('ltr', currentLang === 'en');
  menu.classList.toggle('open', isMenuOpen);
  overlay.style.display = isMenuOpen ? 'block' : 'none';
}
function changeTheme(themeName) {
  playSound('click');
  document.documentElement.setAttribute('data-theme', themeName);
  try { localStorage.setItem('anigma_theme', themeName); } catch (e) {}
  const label = t(themeName === 'light' ? 'menu.theme.light' : 'menu.theme.dark');
  updateStatus('status.theme', { theme: label });
  addLog('log.msg.theme', { theme: label });
  closeMenu();
}
function toggleLanguage() {
  playSound('click');
  applyLanguage(currentLang === 'fa' ? 'en' : 'fa');
  updateStatus('status.lang');
  addLog('log.msg.lang');
}
function openModal(id) { document.getElementById(id).classList.add('open'); }
function closeModal(id) { playSound('click'); document.getElementById(id).classList.remove('open'); onModalClosed(id); }
// Some modals own resources (the camera) or state (first-run seen flag) that must be released
// however the modal gets closed — the Close button, Escape, or a tap on the backdrop.
function onModalClosed(id) {
  if (id === 'scanModal') scanStop();
  if (id === 'onboardModal') onboardMarkSeen();
}
document.addEventListener('keydown', function (ev) {
  if (ev.key !== 'Escape') return;
  document.querySelectorAll('.modal.open').forEach(function (m) { m.classList.remove('open'); onModalClosed(m.id); });
  if (isMenuOpen) closeMenu();
});
document.addEventListener('DOMContentLoaded', function () {
  document.querySelectorAll('.modal').forEach(function (m) { m.addEventListener('click', function (ev) { if (ev.target === m) { m.classList.remove('open'); onModalClosed(m.id); } }); });
});

// "Animated icon" needs to work identically on a mouse (hover) and a touchscreen (tap) —
// CSS :hover alone is unreliable on touch devices (it fires once, inconsistently, or not
// at all depending on the browser). So every tap/click on an icon explicitly (re)starts a
// short one-shot wiggle via JS, on top of the continuous CSS hover-wiggle desktop already
// gets for free. Delegated on document so it also covers icons rendered after load.
document.addEventListener('pointerdown', function (ev) {
  // Look for the enclosing button first, then animate whichever icon(s) it contains —
  // a tap almost never lands pixel-perfect on the small icon glyph itself, it lands
  // somewhere on the button around it.
  const btn = ev.target.closest ? ev.target.closest('button') : null;
  if (!btn) return;
  const icons = btn.querySelectorAll('.icon-anim');
  icons.forEach(function (icon) {
    icon.classList.remove('icon-tap');
    void icon.offsetWidth; // force reflow so re-adding the class restarts the animation
    icon.classList.add('icon-tap');
  });
}, true);
document.addEventListener('animationend', function (ev) {
  if (ev.animationName === 'iconWiggle' && ev.target.classList && ev.target.classList.contains('icon-tap')) ev.target.classList.remove('icon-tap');
}, true);

function openHelp() { playSound('click'); closeMenu(); openModal('helpModal'); }

// ====================================================================================
// HELP GUIDE: a task-by-task guide. One accordion item per topic (HELP_TOPICS in i18n.js);
// the text comes from help.t.<id>.title / help.t.<id>.body (our own static strings).
// ====================================================================================
function renderHelp() {
  const box = document.getElementById('helpAccordion');
  if (!box) return;
  const openIds = [];
  box.querySelectorAll('.acc-item.open').forEach(function (el) { openIds.push(el.getAttribute('data-sec')); });
  const first = HELP_TOPICS.length ? HELP_TOPICS[0].id : null;
  box.textContent = '';
  HELP_TOPICS.forEach(function (topic) {
    const item = document.createElement('div');
    const isOpen = openIds.indexOf(topic.id) !== -1 || (openIds.length === 0 && topic.id === first);
    item.className = 'acc-item' + (isOpen ? ' open' : '') + (topic.adv ? ' adv-only' : '');
    item.setAttribute('data-sec', topic.id);
    const head = document.createElement('button');
    head.type = 'button'; head.className = 'acc-head';
    head.setAttribute('aria-expanded', isOpen ? 'true' : 'false');
    head.innerHTML = iconSvg(topic.icon, 'acc-topic-icon') + '<span>' + escapeHtml(t('help.t.' + topic.id + '.title')) + '</span>' + iconSvg('chevron', 'acc-chevron');
    head.addEventListener('click', function () {
      const nowOpen = !item.classList.contains('open');
      item.classList.toggle('open', nowOpen);
      head.setAttribute('aria-expanded', nowOpen ? 'true' : 'false');
    });
    const body = document.createElement('div');
    body.className = 'acc-body';
    body.innerHTML = t('help.t.' + topic.id + '.body');
    item.appendChild(head); item.appendChild(body);
    box.appendChild(item);
  });
}

// ====================================================================================
// QR
// ====================================================================================
function renderQR(text, titleKey, descKey, logKey) {
  playSound('click');
  const box = document.getElementById('qrcodeBox');
  const err = document.getElementById('qrError');
  document.getElementById('qrModalTitle').textContent = t(titleKey);
  document.getElementById('qrModalDesc').textContent = t(descKey);
  box.textContent = ''; err.style.display = 'none';

  function fail(key, params) {
    box.style.display = 'none'; err.style.display = 'block'; err.textContent = t(key, params);
    openModal('qrModal'); updateStatus(key, params, true);
  }
  if (!text || !text.trim()) return fail('qr.err.empty');
  try {
    box.style.display = 'flex';
    AnigmaQR.render(box, text, { width: 220, correctLevel: 'L' });
    openModal('qrModal');
    addLog(logKey);
  } catch (e) {
    if (e && e.code === 'too-long') fail('qr.err.long', { len: text.length, max: QR_MAX_CHARS_HINT });
    else fail('qr.err.fail');
  }
}
function showQRCodeModal() { renderQR(document.getElementById('secureOutput').value.trim(), 'qr.title.text', 'qr.desc.text', 'log.msg.qr'); }
function idShowMyQR() { renderQR(idPublicKeyB64, 'qr.title.pub', 'qr.desc.pub', 'log.msg.qrPub'); }

// ====================================================================================
// TABS (top level)
// ====================================================================================
// ---- "How it travels": a live timeline of what will really happen to the message ----
// Everything shown here is read from the real state (message text, the chosen recipient, the sender
// identity, the anonymous switch and, after sending, the actual output). It never touches key material
// beyond public keys, and it changes nothing about how encryption works.
let pipeSent = null;       // the finished send/open run (texts + sizes) until anything changes
let pipeStage = 0;         // how many steps the post-send animation has completed (0..3)
let pipeTimers = [];
const pipeFpCache = {};    // public key (base64) -> fingerprint, filled asynchronously

function taAutoGrow(ta) {
  ta.style.height = 'auto';
  if (ta.value) ta.style.height = Math.min(ta.scrollHeight + 2, 220) + 'px';
  else ta.style.height = '';
}
function pipeSize(n) {
  const fa = currentLang === 'fa';
  if (n < 1024) return pipeNum(n) + (fa ? ' بایت' : ' B');
  const kb = n / 1024;
  if (kb < 1024) return pipeNum(Math.round(kb * 10) / 10) + (fa ? ' کیلوبایت' : ' KB');
  return pipeNum(Math.round(kb / 102.4) / 10) + (fa ? ' مگابایت' : ' MB');
}
function pipeNum(n) { return Number(n).toLocaleString(currentLang === 'fa' ? 'fa-IR' : 'en-US'); }
function pipeClearTimers() { pipeTimers.forEach(clearTimeout); pipeTimers = []; }

function pipeCurveName(raw) { try { return AnigmaCrypto.curveFromRawPubLen(raw); } catch (e) { return null; } }

// Resolves who the message is currently addressed to: { state: 'none'|'bad'|'ok', label, raw, verified }
function pipeRecipient() {
  if (secRecipientMode === 'contact') {
    const sel = document.getElementById('idContactSelect');
    const c = sel && idContacts.find(function (x) { return x.id === sel.value; });
    if (!c) return { state: 'none' };
    try { return { state: 'ok', label: c.alias, raw: AnigmaCrypto.b64ToBuf(c.pub), verified: !!c.verified }; } catch (e) { return { state: 'bad' }; }
  }
  const txt = document.getElementById('secPastePubKey');
  if (secPastedRecipientRaw) return { state: 'ok', label: t('pipe.pasted'), raw: secPastedRecipientRaw, verified: false };
  return (txt && txt.value.trim()) ? { state: 'bad' } : { state: 'none' };
}

function pipeFingerprint(raw) {
  if (!raw) return '';
  const key = AnigmaCrypto.bufToB64(raw);
  if (pipeFpCache[key]) return pipeFpCache[key];
  AnigmaCrypto.computeFingerprint(raw).then(function (fp) { pipeFpCache[key] = fp; pipeRender(); }).catch(function () {});
  return '';
}

function pipeSet(id, state, line, sub) {
  const li = document.getElementById(id); if (!li) return;
  li.setAttribute('data-state', state);
  li.querySelector('.ps-line').textContent = line || '';
  const sb = li.querySelector('.ps-sub'); if (sb) sb.textContent = sub || '';
}

function pipeRender() {
  if (!document.getElementById('secPipe')) return;
  const adv = uiMode === 'advanced';
  const input = document.getElementById('secureInput').value;
  const chars = Array.from(input).length;
  const bytes = chars ? new TextEncoder().encode(input).length : 0;
  const anon = adv && secIsAnonymous();
  const rcp = pipeRecipient();
  const rcpFp = rcp.state === 'ok' ? pipeFingerprint(rcp.raw) : '';
  const rcpCurve = rcp.state === 'ok' ? pipeCurveName(rcp.raw) : null;
  const myCurve = idPublicKeyRaw ? pipeCurveName(idPublicKeyRaw) : null;
  const mismatch = rcp.state === 'ok' && !anon && rcpCurve && myCurve && rcpCurve !== myCurve;
  const algo = 'AES-256-GCM \u00b7 ECDH ' + (rcpCurve || '') ;

  // ---- step 1: your message / who it is from
  const msgLine = chars ? t(adv ? 'pipe.msg.adv' : 'pipe.msg', { n: pipeNum(chars), b: pipeNum(bytes) }) : t('pipe.msg.empty');
  const fromSub = anon ? t('pipe.adv.fromAnon') : (idFingerprint ? t('pipe.adv.from', { fp: idFingerprint.split(' ').slice(0, 4).join(' ') }) : '');

  // ---- step 3: recipient
  let thLine, thSub = '', thState;
  if (rcp.state === 'ok') {
    thState = 'ready';
    thLine = t(rcp.verified ? 'pipe.to.ok' : 'pipe.to.unverified', { name: rcp.label });
    thSub = rcpFp ? t('pipe.adv.to', { fp: rcpFp.split(' ').slice(0, 4).join(' ') }) : '';
  } else if (rcp.state === 'bad') { thState = 'warn'; thLine = t('pipe.to.bad'); }
  else { thState = 'idle'; thLine = t('pipe.to.none'); }

  // ---- step 2: encryption
  let enState, enLine, enSub = '';
  if (mismatch) {
    enState = 'warn';
    enLine = t('pipe.mismatch');
    enSub = t('pipe.adv.mismatch', { a: myCurve, b: rcpCurve });
  } else if (rcp.state === 'ok' && chars) {
    enState = 'ready';
    enLine = t(anon ? 'pipe.enc.anon' : 'pipe.enc.ready');
    enSub = algo;
  } else {
    enState = 'idle';
    enLine = t('pipe.enc.wait');
  }

  // A pasted encrypted package is about to be OPENED, not encrypted: say so instead of describing it as a message to send.
  const opening = pipeSent ? pipeSent.kind === 'open' : (typeof secCurrentAction === 'function' && secCurrentAction() === 'decrypt');
  pipeTitles(opening);
  if (!pipeSent && opening) {
    pipeSet('psYou', 'ready', t('pipe.dec.you', { size: pipeSize(new TextEncoder().encode(input).length) }), '');
    pipeSet('psEnc', 'idle', t('pipe.dec.enc'), '');
    pipeSet('psThem', 'idle', t('pipe.dec.them'), '');
    pipeBar(0);
    return;
  }
  if (pipeSent) { pipeRenderRun(pipeSent, rcp); return; }
  pipeSet('psYou', chars ? 'ready' : 'idle', msgLine, fromSub);
  pipeSet('psEnc', enState, enLine, enSub);
  pipeSet('psThem', thState, thLine, thSub);
  pipeBar(0);
}

// Step titles follow what is happening: sending a message (default) or opening a package we received.
function pipeTitles(opening) {
  [['psYou', opening ? 'pipe.open.t1' : 'pipe.you'], ['psEnc', opening ? 'pipe.open.t2' : 'pipe.enc'], ['psThem', opening ? 'pipe.open.t3' : 'pipe.them']].forEach(function (x) {
    const el = document.querySelector('#' + x[0] + ' .ps-title');
    const txt = t(x[1]);
    if (el && el.textContent !== txt) el.textContent = txt;
  });
}
function pipeBar(frac) {
  const i = document.querySelector('#psEnc .ps-bar i');
  if (i) i.style.width = Math.round(Math.max(0, Math.min(1, frac)) * 100) + '%';
}

// ---- the run: what the app really does, shown one step at a time ----
// The encryption itself takes a few milliseconds, which makes a plain "done" look like nothing happened. So the
// real operations (one-time key, shared key, AES-256, seal, packing) are listed one by one with a progress bar,
// paced so a person can read them, and the finished step shows real numbers (package size, a short package code).
const PIPE_SEND_SUBS = ['pipe.run.s1', 'pipe.run.s2', 'pipe.run.s3', 'pipe.run.s4'];
const PIPE_OPEN_SUBS = ['pipe.open.s1', 'pipe.open.s2', 'pipe.open.s3'];
let pipeSub = 0;          // which sub-step of the middle node is showing

function pipeRenderRun(r, rcp) {
  const open = r.kind === 'open';
  const subs = open ? PIPE_OPEN_SUBS : PIPE_SEND_SUBS;
  const st = function (i) { return i < pipeStage ? 'done' : (i === pipeStage ? 'active' : 'idle'); };
  pipeSet('psYou', st(0), pipeStage > 0 ? r.l1 : t(open ? 'pipe.open.read' : 'pipe.run.read'), pipeStage > 0 ? r.s1 : '');
  if (pipeStage > 1) { pipeSet('psEnc', 'done', r.l2, r.s2); pipeBar(1); }
  else if (pipeStage === 1) { pipeSet('psEnc', 'active', t(subs[Math.min(pipeSub, subs.length - 1)]), ''); pipeBar((pipeSub + 1) / subs.length); }
  else { pipeSet('psEnc', 'idle', t(open ? 'pipe.open.wait' : 'pipe.enc.wait'), ''); pipeBar(0); }
  if (pipeStage > 2) pipeSet('psThem', 'done', r.l3, r.s3);
  else if (pipeStage === 2) pipeSet('psThem', 'active', open ? t('pipe.open.check') : t('pipe.run.deliver', { name: r.name || '' }), '');
  else pipeSet('psThem', 'idle', open ? t('pipe.open.wait3') : r.live3, '');
}

// Anything that changes what would be sent drops the finished run and goes back to the live preview.
function pipeInvalidate() {
  pipeSent = null; pipeStage = 0; pipeSub = 0; pipeClearTimers();
  const p = document.getElementById('secPipe');
  if (p) p.querySelectorAll('.ps').forEach(function (n) { n.classList.remove('go'); });
  pipeRender();
}
function fxPipeReset() { pipeInvalidate(); }

function pipeText(id) { const el = document.querySelector('#' + id); return el ? el.textContent : ''; }
// Short, real checksum of the finished package (first 8 hex digits of its SHA-256), shown to Advanced users.
function pipePackageCode(packed) {
  try {
    return crypto.subtle.digest('SHA-256', new TextEncoder().encode(packed)).then(function (buf) {
      const h = Array.from(new Uint8Array(buf).slice(0, 4)).map(function (b) { return (b < 16 ? '0' : '') + b.toString(16); }).join('').toUpperCase();
      return h.slice(0, 4) + ' ' + h.slice(4);
    });
  } catch (e) { return Promise.resolve(''); }
}
function pipeStart(run, plan) {
  const p = document.getElementById('secPipe'); if (!p) return;
  const nodes = p.querySelectorAll('.ps');
  const reduce = window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  pipeSent = run; pipeSub = 0;
  if (reduce) { pipeStage = 3; pipeRender(); return; }
  pipeStage = 0; pipeRender();
  void p.offsetWidth;
  pipeTimers.push(setTimeout(function () { nodes[0].classList.add('go'); }, 150));
  pipeTimers.push(setTimeout(function () { pipeStage = 1; pipeSub = 0; pipeRender(); }, plan.read));
  for (let i = 1; i < plan.subs; i++) {
    pipeTimers.push(setTimeout(function () { pipeSub = i; pipeRender(); }, plan.read + i * plan.step));
  }
  pipeTimers.push(setTimeout(function () { pipeStage = 2; nodes[1].classList.add('go'); pipeRender(); }, plan.read + plan.subs * plan.step));
  pipeTimers.push(setTimeout(function () { pipeStage = 3; pipeRender(); }, plan.read + plan.subs * plan.step + plan.last));
}

function fxPipeRun(outLen, packed) {
  const p = document.getElementById('secPipe'); if (!p) return;
  pipeInvalidate();                       // paints the live preview, which we read the "before" texts from
  const rcp = pipeRecipient();
  const run = { kind: 'send', l1: pipeText('psYouLine'), s1: pipeText('psYouSub'), live3: pipeText('psThemLine'), name: rcp.label || '',
    l2: t('pipe.enc.done', { size: pipeSize(outLen || 0) }), s2: pipeText('psEncSub'), l3: t(rcp.verified ? 'pipe.to.done' : 'pipe.to.doneUnv', { name: rcp.label || '' }), s3: pipeText('psThemSub') };
  pipeStart(run, { read: 450, subs: PIPE_SEND_SUBS.length, step: 420, last: 450 });
  pipePackageCode(packed || '').then(function (code) {
    if (code && pipeSent === run) { run.s2 = (run.s2 ? run.s2 + ' \u00b7 ' : '') + t('pipe.adv.code', { code: code }); pipeRender(); }
  });
}

// Opening a received package: same idea, with the steps that really happen (structure + integrity check,
// finding the sender, unlocking with your private key) and the real outcome about the sender.
function fxPipeOpen(info) {
  const p = document.getElementById('secPipe'); if (!p) return;
  pipeInvalidate();
  const l3 = { ok: 'pipe.open.from.ok', unv: 'pipe.open.from.unv', pasted: 'pipe.open.from.pasted', anon: 'pipe.open.from.anon', none: 'pipe.open.from.none' }[info.kind] || 'pipe.open.from.none';
  const run = { kind: 'open', l1: pipeText('psYouLine'), s1: '', name: info.name || '',
    l2: t('pipe.open.done', { n: pipeNum(info.chars || 0) }), s2: 'AES-256-GCM', l3: t(l3, { name: info.name || '' }), s3: '' };
  pipeStart(run, { read: 350, subs: PIPE_OPEN_SUBS.length, step: 380, last: 400 });
}

function switchMainTab(name) {
  playSound('click');
  document.querySelectorAll('.tabs:not(.sub-tabs) > .tab-btn').forEach(function (b) { b.classList.remove('active'); });
  document.querySelectorAll('.tab-content').forEach(function (c) { c.classList.remove('active'); });
  const map = { mykey: ['tabMyKeyBtn', 'panelMyKey'], contacts: ['tabContactsBtn', 'panelContacts'], secure: ['tabSecureBtn', 'panelSecure'], files: ['tabFilesBtn', 'panelFiles'], groups: ['tabGroupsBtn', 'panelGroups'] };
  const pair = map[name];
  if (!pair) return;
  document.getElementById(pair[0]).classList.add('active');
  document.getElementById(pair[1]).classList.add('active');
  const addedBanner = document.getElementById('idContactAddedBanner'); if (addedBanner) addedBanner.style.display = 'none';
  if (name === 'contacts') idRenderContacts();
  if (name === 'secure') { idRenderContactSelect(); idRenderClaimedSenderSelect(); secUpdateSmartUI(); }
  if (name === 'files') idRenderFileContactCheckboxes();
  if (name === 'groups' && typeof groupsShowList === 'function') { groupsShowList(); groupsRenderList(); }
  idRefreshView();
}

// ====================================================================================
// RENDER DYNAMIC TEXT (labels that depend on state, not just language)
// ====================================================================================
function renderDynamicText() {
  const toggleLogText = document.getElementById('toggleLogBtnText');
  if (toggleLogText) toggleLogText.textContent = loggingEnabled ? t('log.stop') : t('log.start');
  const toggleLogIcon = document.getElementById('toggleLogIcon');
  if (toggleLogIcon) setIcon(toggleLogIcon, loggingEnabled ? 'pause' : 'play');

  const menuAudioText = document.getElementById('menuAudioText');
  if (menuAudioText) menuAudioText.textContent = audioEnabled ? t('sound.on') : t('sound.off');
  const menuAudioIcon = document.getElementById('menuAudioIcon');
  if (menuAudioIcon) setIcon(menuAudioIcon, audioEnabled ? 'sound' : 'soundOff');

  const footer = document.getElementById('appFooter');
  if (footer) footer.textContent = t('footer.version', { v: APP_VERSION });
  const helpVersion = document.getElementById('helpVersion');
  if (helpVersion) helpVersion.textContent = t('help.version', { v: APP_VERSION });

  const menu = document.getElementById('sideMenu');
  if (menu) menu.classList.toggle('ltr', currentLang === 'en');

  const modeBtn = document.getElementById('modeFooterBtn');
  if (modeBtn) modeBtn.textContent = t(uiMode === 'simple' ? 'mode.footer.toAdvanced' : 'mode.footer.toSimple');
  secUpdateSmartUI();
  secUpdateResultActions();
  refreshTips();
  onboardRefreshLabels();

  renderFilesManifest();
  if (document.getElementById('fileChunkSizeLabelText')) filesUpdateChunkLabel();
  document.querySelectorAll('textarea.ta-compact').forEach(taAutoGrow);
  pipeInvalidate();
}

// ====================================================================================
// IDENTITY CORE
// ====================================================================================
function idRefreshView() {
  const msg = document.getElementById('idLockedStatusMsg');
  if (!msg) return;
  const exists = !!localStorage.getItem('anigma_identity_v1');
  // Simple mode shows only the one button that applies (Create when there is no ID yet, Unlock when
  // there is); see the [data-has-identity] rules in app.css.
  const lockedView = document.getElementById('idKeyLockedView');
  if (lockedView) lockedView.setAttribute('data-has-identity', exists ? '1' : '0');
  if (idPrivateKey) return;
  msg.textContent = t(exists ? 'identity.locked.exists' : 'identity.locked.none');
}

function idCheckPinStrength(inputId, fillId, textId) {
  const input = document.getElementById(inputId || 'idPinInput');
  const fill = document.getElementById(fillId || 'idPinStrengthFill');
  const text = document.getElementById(textId || 'idPinStrengthText');
  if (!input || !fill || !text) return;
  const r = AnigmaCrypto.estimatePasswordStrength(input.value);
  fill.style.width = r.percent + '%';
  fill.className = 'strength-meter-fill' + (r.className ? ' ' + r.className : '');
  text.textContent = r.key ? t(r.key) : '';
}

// pkcs8 private-key import needs the same curve/algorithm object used to generate the
// key; detect it from the raw public key's byte length rather than trusting a caller-
// supplied flag, so an identity blob can never claim one curve while holding another.
function idAlgoForPub(pubRawBuf) {
  const curve = AnigmaCrypto.curveFromRawPubLen(pubRawBuf);
  return curve === AnigmaCrypto.CURVE_X25519 ? { name: 'X25519' } : { name: 'ECDH', namedCurve: 'P-256' };
}
// The identity key that stays in memory while unlocked is imported NON-extractable: a script that
// got into the page (a tampered dependency, an extension) can still ask the app to use it, but can no
// longer simply call exportKey() and walk away with the private key. `extractable` is only ever true
// for a short-lived copy used to read the public coordinates off it (unlock) — see idUnlockIdentityImpl.
function idImportPkcs8(pkcs8Buf, pubRawBuf, extractable) {
  return crypto.subtle.importKey('pkcs8', pkcs8Buf, idAlgoForPub(pubRawBuf), extractable === true, ['deriveBits']);
}
function idWipeBuffer(buf) { try { new Uint8Array(buf).fill(0); } catch (e) {} }

// One passphrase derivation at a time: a double click on Unlock/Create/Backup/Restore must not start two
// 128 MiB Argon2id computations in parallel (memory!) or race on what gets written to storage.
let idKdfBusy = false;
function idGuarded(fn) {
  return async function () {
    if (idKdfBusy) return;
    idKdfBusy = true;
    try { return await fn.apply(this, arguments); } finally { idKdfBusy = false; idKdfBusyClass(false); }
  };
}
idCreateIdentity = idGuarded(idCreateIdentity);
idExportIdentity = idGuarded(idExportIdentity);
idImportIdentity = idGuarded(idImportIdentity);

// Argon2id takes a couple of seconds on purpose (it runs in a worker, so the page stays responsive).
// Tell the person what is happening, and let the browser paint that message before the work starts.
// While it runs, decorative animations are paused (html.kdf-busy): on a weak or busy phone they compete with the
// worker for CPU/GPU and can make the wait several times longer.
function idKdfBusyClass(on) { try { document.documentElement.classList.toggle('kdf-busy', !!on); } catch (e) { /* ignore */ } }
// Ask the browser not to evict our data under storage pressure (Chrome/Edge/Firefox/Safari 15.2+; silently ignored elsewhere).
// Safari on iPhone/iPad may still clear a website's data after 7 days without a visit unless the app is added to the Home
// Screen — the Help says so and asks people to keep a backup.
function idAskPersistentStorage() {
  try {
    if (navigator.storage && typeof navigator.storage.persist === 'function') {
      navigator.storage.persisted().then(function (already) { if (!already) return navigator.storage.persist(); }).catch(function () {});
    }
  } catch (e) { /* not available: nothing to do */ }
}

async function idShowDeriving() { idKdfBusyClass(true); updateStatus('status.id.deriving'); await new Promise(function (r) { setTimeout(r, 60); }); }
// Maps a KDF failure to a plain message. Returns true when it handled the error.
function idHandleKdfError(e, kdfName) {
  const m = e && e.message;
  if (m === 'argon2id-memory') { showError('status.id.kdfMemory'); return true; }
  if (m === 'argon2id-unavailable' || m === 'argon2id-failed' || m === 'unknown-kdf') { showError('status.id.kdfUnavailable', { kdf: kdfName || 'argon2id' }); return true; }
  return false;
}

async function idCreateIdentity() {
  playSound('click');
  const pin = document.getElementById('idPinInput').value;
  if (!pin || pin.length < AnigmaCrypto.ID_PASSPHRASE_MIN_LENGTH) { updateStatus('status.id.pinShort', null, true); return; }
  if (AnigmaCrypto.estimatePasswordStrength(pin).className === 'weak') { updateStatus('status.id.pinWeak', null, true); return; }
  if (localStorage.getItem('anigma_identity_v1')) { if (!confirm(t('confirm.newIdentity'))) return; }
  try {
    const curveSelect = document.getElementById('idCurveSelect');
    // The curve choice only exists in Advanced mode; Simple mode always gets the compatible default.
    const curve = (uiMode === 'advanced' && curveSelect && curveSelect.value === 'x25519') ? AnigmaCrypto.CURVE_X25519 : AnigmaCrypto.CURVE_P256;
    const kp = await AnigmaCrypto.generateIdentityKeyPair(curve);
    const pubRaw = await crypto.subtle.exportKey('raw', kp.publicKey);
    const privPkcs8 = await crypto.subtle.exportKey('pkcs8', kp.privateKey);

    const salt = crypto.getRandomValues(new Uint8Array(16));
    await idShowDeriving();
    const made = await AnigmaCrypto.deriveNewKey(pin, salt); // Argon2id (memory-hard); PBKDF2 only if Argon2id isn't loaded
    const masterKey = made.key;
    const sealed = await AnigmaCrypto.sealStored(masterKey, 'identity', privPkcs8);
    const iv = sealed.iv, ctPriv = sealed.ct;

    // v2 identity storage: records its own KDF name + parameters (iteration count for PBKDF2, m/t/p for
    // Argon2id), so a change to the defaults never locks anyone out of an identity made under older ones.
    localStorage.setItem('anigma_identity_v1', JSON.stringify(Object.assign({
      v: 2, pn: AnigmaCrypto.PASSPHRASE_NORM_VERSION, aad: 1,
      salt: AnigmaCrypto.bufToB64(salt), iv: AnigmaCrypto.bufToB64(iv), ct: AnigmaCrypto.bufToB64(ctPriv), pub: AnigmaCrypto.bufToB64(pubRaw)
    }, made.kdfFields)));
    localStorage.removeItem('anigma_contacts_v1');
    localStorage.removeItem('anigma_groups_v1');
    localStorage.removeItem('anigma_seen_v1');
    localStorage.removeItem('anigma_meta_v1');
    unlockAttemptsReset(); // brand-new passphrase: nothing carried over

    idPrivateKey = await idImportPkcs8(privPkcs8, pubRaw, false);
    idWipeBuffer(privPkcs8);
    idPublicKeyRaw = pubRaw;
    idPublicKeyB64 = AnigmaCrypto.bufToB64(pubRaw);
    idFingerprint = await AnigmaCrypto.computeFingerprint(pubRaw);
    idMasterKey = masterKey;
    idContacts = [];
    if (typeof idGroups !== 'undefined') idGroups = [];
    idNoteIdentityCreated();

    document.getElementById('idPinInput').value = '';
    idCheckPinStrength();
    idShowUnlockedView();
    playSound('lock');
    updateStatus('status.id.created');
    idAskPersistentStorage();
    addLog('log.msg.idCreated');
    autolockArm();
  } catch (e) {
    showError('status.id.error', { msg: (e && e.message) ? e.message : '' });
  }
}

// Only one unlock attempt may be in flight at a time. The cooldown check below runs BEFORE the
// (deliberately slow) key derivation, and a failure is only recorded AFTER it — so without this,
// a burst of rapid clicks / scripted calls would ALL pass the cooldown check while the counter
// still read 0, and the rate limit could be walked around just by submitting concurrently.
let unlockInFlight = false;
async function idUnlockIdentity() {
  if (unlockInFlight) return;
  unlockInFlight = true;
  try { await idUnlockIdentityImpl(); } finally { unlockInFlight = false; idKdfBusyClass(false); }
}
async function idUnlockIdentityImpl() {
  playSound('click');
  const pin = document.getElementById('idPinInput').value;
  if (!pin) { updateStatus('status.id.needPin', null, true); return; }
  const raw = localStorage.getItem('anigma_identity_v1');
  if (!raw) { updateStatus('status.id.none', null, true); return; }
  // See the "unlock-attempt rate limiting" block near the top of this file for exactly what
  // this does and doesn't protect against. A still-active cooldown blocks even trying — this
  // check is in the logic itself, not just the button's disabled state, so a forced click or
  // a page reload can't get around it.
  const cooldownMs = unlockRemainingCooldownMs();
  if (cooldownMs > 0) { unlockCountdownStart(); updateStatus('status.id.unlockCooldown', { seconds: Math.ceil(cooldownMs / 1000) }, true); return; }
  try {
    const blob = JSON.parse(raw);
    if (blob.kdf === 'argon2id') await idShowDeriving();
    const salt = new Uint8Array(AnigmaCrypto.b64ToBuf(blob.salt));
    const iv = new Uint8Array(AnigmaCrypto.b64ToBuf(blob.iv));
    // v1 blobs (created before this field existed) are always pbkdf2 @ 200000 — the
    // values the app used to hardcode. v2 blobs carry their own kdf/iter. `pn` says how the
    // passphrase was normalised (absent = legacy raw bytes; openWithPassphrase handles both).
    const kdf = blob.kdf || 'pbkdf2';
    const iterations = blob.iter || 200000;
    let masterKey, privPkcs8;
    try {
      const opened = await AnigmaCrypto.openWithPassphrase(pin, { salt: salt, iv: iv, ct: AnigmaCrypto.b64ToBuf(blob.ct), iter: iterations, kdf: kdf, kp: blob.kp, pn: blob.pn, aad: blob.aad === 1 ? AnigmaCrypto.storageAad('identity') : undefined });
      masterKey = opened.masterKey; privPkcs8 = opened.plain;
    } catch (err) {
      if (!err || err.message !== 'wrong-passphrase') {
        // Only reachable if the blob claims a KDF this build can't run (or the device lacks the memory
        // for Argon2id) — distinct from a wrong PIN, and NOT counted as a failed attempt.
        if (!idHandleKdfError(err, kdf)) showError('status.id.kdfUnavailable', { kdf: kdf });
        return;
      }
      unlockAttemptsRecordFailure();
      const waitMs = unlockRemainingCooldownMs();
      if (waitMs > 0) { unlockCountdownStart(); updateStatus('status.id.wrongPinCooldown', { seconds: Math.ceil(waitMs / 1000) }, true); }
      else updateStatus('status.id.wrongPin', null, true);
      addLog('log.msg.idUnlockFail');
      return;
    }
    // Security review #6: never trust the stored `pub` field on its own — it lives outside
    // the encrypted envelope and can be tampered with independently of the private key. We
    // still need SOME public-key bytes up front to pick the right import algorithm
    // (P-256 vs X25519), but the value that becomes this identity's actual public key is
    // always the one re-derived from the private key we just decrypted, below.
    //
    // The public coordinates can only be read from an EXTRACTABLE copy (JWK export), so a throw-away
    // extractable import does that one job; the key kept in memory is a second, non-extractable import.
    const storedPubRaw = AnigmaCrypto.b64ToBuf(blob.pub);
    const curve = AnigmaCrypto.curveFromRawPubLen(storedPubRaw);
    const tmpKey = await idImportPkcs8(privPkcs8, storedPubRaw, true);
    const derivedPubRaw = await AnigmaCrypto.derivePublicRawFromPrivateKey(tmpKey, curve);
    idPrivateKey = await idImportPkcs8(privPkcs8, storedPubRaw, false);
    if (blob.aad !== 1) {
      // Blob from before slot-binding: rewrite it (same key, fresh IV) so it is bound to the "identity" slot.
      try {
        const re = await AnigmaCrypto.sealStored(masterKey, 'identity', privPkcs8);
        blob.iv = AnigmaCrypto.bufToB64(re.iv); blob.ct = AnigmaCrypto.bufToB64(re.ct); blob.aad = 1;
        localStorage.setItem('anigma_identity_v1', JSON.stringify(blob));
      } catch (e) { /* still readable the old way next time */ }
    }
    idWipeBuffer(privPkcs8);
    const derivedPubB64 = AnigmaCrypto.bufToB64(derivedPubRaw);
    if (derivedPubB64 !== blob.pub) {
      // The stored pub doesn't match the private key it's supposed to belong to. Repair
      // storage with the correct value and tell the user plainly — this should never
      // happen from normal app use, so if it does, something else touched their storage.
      try {
        blob.pub = derivedPubB64;
        localStorage.setItem('anigma_identity_v1', JSON.stringify(blob));
      } catch (e) {}
      showError('status.id.pubMismatchRepaired');
    }
    idPublicKeyRaw = derivedPubRaw;
    idPublicKeyB64 = derivedPubB64;
    idFingerprint = await AnigmaCrypto.computeFingerprint(idPublicKeyRaw);
    idMasterKey = masterKey;
    unlockAttemptsReset(); // right password proven: whatever was being guarded against no longer applies

    await idLoadContacts();
    if (typeof groupsLoadAll === 'function') { await groupsLoadAll(); groupsRenderList(); }
    // Blobs written before slot-binding (AAD) are rewritten once, now that they provably decrypt.
    try {
      if (contactsNeedRebind && !idContactsLoadFailed) { await idSaveContacts(); contactsNeedRebind = false; }
      if (typeof groupsNeedRebind !== 'undefined' && groupsNeedRebind && !groupsLoadFailed) { await groupsSaveAll(); groupsNeedRebind = false; }
    } catch (e) {}

    document.getElementById('idPinInput').value = '';
    idCheckPinStrength();
    idShowUnlockedView();
    playSound('unlock');
    updateStatus('status.id.unlocked');
    idAskPersistentStorage();
    addLog('log.msg.idUnlocked');
    autolockArm();
    // Simple mode: unlocking is only ever a means to an end, so go straight to the main task.
    if (uiMode === 'simple') switchMainTab('secure');
  } catch (e) {
    showError('status.id.error', { msg: (e && e.message) ? e.message : '' });
  }
}

function idShowUnlockedView() {
  document.getElementById('idKeyLockedView').style.display = 'none';
  document.documentElement.setAttribute('data-id-locked', '0');
  document.getElementById('idKeyUnlockedView').style.display = 'block';
  document.getElementById('idMyFingerprint').textContent = idFingerprint;
  document.getElementById('idMyPublicKey').value = idPublicKeyB64;
  idRenderContacts();
  idRenderContactSelect();
  idRenderClaimedSenderSelect();
  idRenderFileContactCheckboxes();
  idBackupReminderCheck();
}

// Clears every on-screen and in-memory trace of plaintext/keys that a lock or wipe is
// supposed to remove: the message boxes, any file-decrypt session left in flight (fix for
// security review #5 — `filesPendingDecrypt` carries an already-unwrapped `cekBytes`, so
// without this a "Decrypt and write" click still worked after locking because it never
// needed `idPrivateKey` again), and the open manifest modal if one is showing.
function secClearSensitiveUiState() {
  const inputEl = document.getElementById('secureInput');
  const outputEl = document.getElementById('secureOutput');
  if (inputEl) inputEl.value = '';
  if (outputEl) outputEl.value = '';
  secLastOutputSensitive = false;
  filesPendingDecrypt = null;
  const manifestModal = document.getElementById('filesManifestModal');
  if (manifestModal && manifestModal.classList.contains('open')) closeModal('filesManifestModal');
}

function idLockIdentity() {
  playSound('click');
  idPrivateKey = null; idMasterKey = null; idPublicKeyRaw = null; idPublicKeyB64 = ''; idFingerprint = ''; idContacts = [];
  secClearSensitiveUiState();
  document.getElementById('idKeyUnlockedView').style.display = 'none';
  document.getElementById('idKeyLockedView').style.display = 'block';
  document.documentElement.setAttribute('data-id-locked', '1');
  document.getElementById('idPinInput').value = '';
  idCheckPinStrength();
  idRefreshView();
  idRenderContacts();
  idRenderContactSelect();
  idRenderClaimedSenderSelect();
  idRenderFileContactCheckboxes();
  updateStatus('status.id.locked');
  addLog('log.msg.idLocked');
  autolockDisarm();
  hideBackupBanner();
}

async function idCopyPublicKey() {
  playSound('click');
  const ok = await copyToClipboard(idPublicKeyB64);
  updateStatus(ok ? 'status.id.pubCopied' : 'status.copy.failed', null, !ok);
}

// Removes EVERY trace this origin holds: all localStorage/sessionStorage keys the app ever wrote
// (including the "onboarded", language, backup-time and unlock-attempt markers — each of them is
// evidence the app was used), the service worker registration and the offline copy in Cache Storage.
// Flash storage cannot be securely overwritten from a web page, so this is deletion, not erasure:
// a strong passphrase remains the real protection for anything recoverable from the device.
async function appPurgeLocalTraces() {
  try {
    const names = [];
    for (let i = 0; i < localStorage.length; i++) names.push(localStorage.key(i));
    names.forEach(function (k) { if (k && /^anigma/i.test(k)) localStorage.removeItem(k); });
  } catch (e) {}
  try {
    const names = [];
    for (let i = 0; i < sessionStorage.length; i++) names.push(sessionStorage.key(i));
    names.forEach(function (k) { if (k && /^anigma/i.test(k)) sessionStorage.removeItem(k); });
  } catch (e) {}
  try {
    if ('serviceWorker' in navigator && navigator.serviceWorker.getRegistrations) {
      const regs = await navigator.serviceWorker.getRegistrations();
      await Promise.all(regs.map(function (r) { return r.unregister(); }));
    }
  } catch (e) {}
  try {
    if (typeof caches !== 'undefined' && caches.keys) {
      const keys = await caches.keys();
      await Promise.all(keys.map(function (k) { return caches.delete(k); }));
    }
  } catch (e) {}
}

async function idEmergencyWipe() {
  if (!confirm(t('confirm.wipe'))) return;
  playSound('click');
  // In-memory secrets first, so nothing usable survives even if the purge below is interrupted.
  idPrivateKey = null; idMasterKey = null; idPublicKeyRaw = null; idPublicKeyB64 = ''; idFingerprint = ''; idContacts = [];
  if (typeof idGroups !== 'undefined') idGroups = [];
  secClearSensitiveUiState();
  autolockDisarm();
  await appPurgeLocalTraces();
  window.location.reload(); // guaranteed-clean state: no leftover UI, no service worker, no cache
}

// Full reset: identity, contacts, and every saved preference (theme, language, sound,
// "help seen") — everything this app has ever written to localStorage on this device.
// Distinct from Emergency wipe above, which only clears identity + contacts and leaves
// preferences in place. Requires typing a confirmation word so it can't be triggered by
// a stray double-click, then reloads to a guaranteed-clean state.
function idDeleteAllData() {
  playSound('click');
  if (!confirm(t('confirm.deleteAll'))) return;
  const word = t('confirm.deleteAll.word');
  const typed = prompt(t('confirm.deleteAll.prompt', { word: word }));
  if (typed === null) return;
  if (typed.trim().toUpperCase() !== word.trim().toUpperCase()) {
    updateStatus('confirm.deleteAll.mismatch', null, true);
    return;
  }
  try { localStorage.clear(); } catch (e) {}
  appPurgeLocalTraces().then(function () { window.location.reload(); }, function () { window.location.reload(); });
}

// ------------------------------------------------------------------ identity backup/restore
async function idExportIdentity() {
  playSound('click');
  if (!idPrivateKey) { updateStatus('status.secure.needUnlock', null, true); return; }
  const pw = document.getElementById('idExportPassword').value;
  if (!pw || pw.length < AnigmaCrypto.ID_PASSPHRASE_MIN_LENGTH) { updateStatus('status.id.pinShort', null, true); return; }
  if (AnigmaCrypto.estimatePasswordStrength(pw).className === 'weak') { updateStatus('status.id.pinWeak', null, true); return; }
  try {
    // The in-memory key is non-extractable, so the PKCS#8 comes from the stored, encrypted copy:
    // opened with the master key that is already held, used for this one export, then zeroed.
    const stored = JSON.parse(localStorage.getItem('anigma_identity_v1') || 'null');
    if (!stored || !idMasterKey) { updateStatus('status.secure.needUnlock', null, true); return; }
    const privPkcs8 = await AnigmaCrypto.openStored(idMasterKey, 'identity', stored);
    let json;
    await idShowDeriving();
    try { json = await AnigmaCrypto.exportIdentityBackup(privPkcs8, idPublicKeyRaw, idContacts, pw); }
    finally { idWipeBuffer(privPkcs8); }
    const blob = new Blob([json], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url; a.download = 'anigma-identity-backup.json';
    document.body.appendChild(a); a.click(); document.body.removeChild(a);
    setTimeout(function () { URL.revokeObjectURL(url); }, 4000);
    document.getElementById('idExportPassword').value = '';
    updateStatus('identity.backup.exportDone');
    addLog('log.msg.idExported');
    idNoteBackupDone();
  } catch (e) {
    if (!idHandleKdfError(e)) showError('status.id.error', { msg: (e && e.message) ? e.message : '' });
  }
}

async function idImportIdentity() {
  playSound('click');
  const fileInput = document.getElementById('idImportFile');
  const pw = document.getElementById('idImportPassword').value;
  if (!fileInput.files || !fileInput.files[0]) return;
  if (!pw) { updateStatus('status.id.needPin', null, true); return; }
  if (localStorage.getItem('anigma_identity_v1')) { if (!confirm(t('identity.backup.confirmOverwrite'))) return; }
  try {
    const text = await fileInput.files[0].text();
    let restored;
    await idShowDeriving();
    try {
      restored = await AnigmaCrypto.importIdentityBackup(text, pw);
    } catch (e) {
      if (e.message === 'bad-format') { updateStatus('identity.backup.badFile', null, true); return; }
      if (idHandleKdfError(e)) return;
      updateStatus('identity.backup.badPassword', null, true);
      return;
    }
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const made = await AnigmaCrypto.deriveNewKey(pw, salt);
    const masterKey = made.key;
    const sealed = await AnigmaCrypto.sealStored(masterKey, 'identity', restored.privPkcs8);
    const iv = sealed.iv, ctPriv = sealed.ct;
    localStorage.setItem('anigma_identity_v1', JSON.stringify(Object.assign({
      v: 2, pn: AnigmaCrypto.PASSPHRASE_NORM_VERSION, aad: 1,
      salt: AnigmaCrypto.bufToB64(salt), iv: AnigmaCrypto.bufToB64(iv), ct: AnigmaCrypto.bufToB64(ctPriv), pub: AnigmaCrypto.bufToB64(restored.pubRaw)
    }, made.kdfFields)));

    idPrivateKey = await idImportPkcs8(restored.privPkcs8, restored.pubRaw, false);
    idWipeBuffer(restored.privPkcs8);
    idPublicKeyRaw = restored.pubRaw;
    idPublicKeyB64 = AnigmaCrypto.bufToB64(restored.pubRaw);
    idFingerprint = await AnigmaCrypto.computeFingerprint(idPublicKeyRaw);
    idMasterKey = masterKey;
    idContacts = restored.contacts || [];
    for (const c of idContacts) { // never trust a stored fp (see idLoadContacts)
      try { const real = await AnigmaCrypto.computeFingerprint(AnigmaCrypto.b64ToBuf(c.pub)); if (c.fp !== real) { c.fp = real; c.verified = false; } } catch (e2) { c.verified = false; }
    }
    await idSaveContacts();
    unlockAttemptsReset(); // restored identity = fresh passphrase context
    // Groups aren't part of the identity-backup format yet (see js/groups-ui.js) — a
    // restored identity starts with none, and any stale groups blob under the OLD master
    // key (now unreadable) is cleared rather than left around to surface as a load error.
    if (typeof idGroups !== 'undefined') { idGroups = []; localStorage.removeItem('anigma_groups_v1'); }
    idNoteIdentityCreated();
    idNoteBackupDone(); // importing a backup means a backup already exists by definition

    document.getElementById('idImportPassword').value = '';
    fileInput.value = '';
    idShowUnlockedView();
    updateStatus('identity.backup.importDone');
    addLog('log.msg.idImported');
    autolockArm();
  } catch (e) {
    showError('status.id.error', { msg: (e && e.message) ? e.message : '' });
  }
}

// ------------------------------------------------------------------ contacts
// ---- partial-rollback detection ------------------------------------------------------------------
// Contacts and groups blobs carry a save counter `seq`; the latest value of each is also kept in a small
// separate sealed record. If someone restores an OLDER copy of just one blob (e.g. to bring back a
// contact list from before a key was replaced), the blob's counter is lower than the record's and the
// user is warned. This cannot stop an attacker who rolls back BOTH together — without somewhere the
// attacker can't write there is nothing to compare against — it raises the bar, it is not a guarantee.
async function storageMetaRead() {
  try {
    const raw = localStorage.getItem('anigma_meta_v1');
    if (!raw || !idMasterKey) return {};
    const m = JSON.parse(new TextDecoder().decode(await AnigmaCrypto.openStored(idMasterKey, 'meta', JSON.parse(raw))));
    return (m && typeof m === 'object') ? m : {};
  } catch (e) { return {}; }
}
async function storageMetaWrite(m) {
  const sealed = await AnigmaCrypto.sealStored(idMasterKey, 'meta', new TextEncoder().encode(JSON.stringify(m)));
  localStorage.setItem('anigma_meta_v1', JSON.stringify({ v: 1, aad: 1, iv: AnigmaCrypto.bufToB64(sealed.iv), ct: AnigmaCrypto.bufToB64(sealed.ct) }));
}
// Next counter value for `slot`, remembered in the meta record. Call right before writing the slot's blob.
async function storageNextSeq(slot) {
  const m = await storageMetaRead();
  m[slot] = (Number.isInteger(m[slot]) ? m[slot] : 0) + 1;
  try { await storageMetaWrite(m); } catch (e) {}
  return m[slot];
}
// True when `blob` is older than the newest save this device recorded for `slot`.
async function storageIsRolledBack(slot, blob) {
  const m = await storageMetaRead();
  if (!Number.isInteger(m[slot]) || m[slot] === 0) return false;
  return !Number.isInteger(blob.seq) || blob.seq < m[slot];
}

let contactsNeedRebind = false; // true after reading a blob written before slot-binding; rewritten once loading succeeds
async function idLoadContacts() {
  const raw = localStorage.getItem('anigma_contacts_v1');
  idContactsLoadFailed = false;
  if (!raw || !idMasterKey) { idContacts = []; return; }
  try {
    const blob = JSON.parse(raw);
    const pt = await AnigmaCrypto.openStored(idMasterKey, 'contacts', blob);
    idContacts = JSON.parse(new TextDecoder().decode(pt));
    contactsNeedRebind = blob.aad !== 1;
    if (await storageIsRolledBack('contacts', blob)) showError('status.storage.rolledBack');
    // A stored `fp` is only a cache: recompute it from the public key actually used for
    // encryption, so a verification can never be performed against a fingerprint that belongs
    // to some other key. A mismatch also drops the "verified" mark.
    for (const c of idContacts) {
      try {
        const real = await AnigmaCrypto.computeFingerprint(AnigmaCrypto.b64ToBuf(c.pub));
        if (c.fp !== real) { c.fp = real; c.verified = false; }
      } catch (e2) { c.verified = false; }
    }
  } catch (e) {
    // Distinct from "no contacts yet": there IS saved data, but it didn't decrypt/parse.
    // Keep idContacts empty for this session (nothing else to show), but mark the failure
    // so idSaveContacts() below won't silently bury the still-present-but-unreadable blob
    // under a fresh empty one, and tell the user plainly instead of pretending all is well.
    idContacts = [];
    idContactsLoadFailed = true;
    showError('status.contacts.loadFailed');
  }
}
async function idSaveContacts() {
  if (!idMasterKey) return;
  if (idContactsLoadFailed) {
    if (!confirm(t('confirm.contactsOverwrite'))) return;
    idContactsLoadFailed = false; // user explicitly accepted losing the unreadable old blob
  }
  const sealed = await AnigmaCrypto.sealStored(idMasterKey, 'contacts', new TextEncoder().encode(JSON.stringify(idContacts)));
  localStorage.setItem('anigma_contacts_v1', JSON.stringify({ v: 2, aad: 1, seq: await storageNextSeq('contacts'), iv: AnigmaCrypto.bufToB64(sealed.iv), ct: AnigmaCrypto.bufToB64(sealed.ct) }));
}

async function idAddContactRaw(alias, pubB64) {
  const pubRaw = AnigmaCrypto.b64ToBuf(pubB64);
  await AnigmaCrypto.importPublicKeyRaw(pubRaw); // validates
  const fp = await AnigmaCrypto.computeFingerprint(pubRaw);
  idContacts.push({ id: (crypto.randomUUID ? crypto.randomUUID() : ('c' + Date.now() + Math.random())), alias: alias, pub: pubB64, fp: fp, verified: false });
  await idSaveContacts();
  return fp;
}

async function idAddContact() {
  playSound('click');
  const alias = document.getElementById('idNewContactAlias').value.trim();
  const pubB64 = document.getElementById('idNewContactPubKey').value.trim();
  if (!idPrivateKey) { updateStatus('status.contact.needUnlock', null, true); return; }
  if (!alias) { updateStatus('status.contact.needAlias', null, true); return; }
  if (!pubB64) { updateStatus('status.contact.needPub', null, true); return; }
  try {
    const fp = await idAddContactRaw(alias, pubB64);
    lastAddedContactId = idContacts.length ? idContacts[idContacts.length - 1].id : null;
    // Advanced keeps the raw fingerprint line; everyone gets the plain "Contact added" confirmation
    // plus the optional "How do I make sure this is really them?" link.
    document.getElementById('idPendingFingerprint').style.display = 'block';
    document.getElementById('idPendingFingerprintText').textContent = fp;
    document.getElementById('idGotIdBanner').style.display = 'none';
    document.getElementById('idContactAddedBanner').style.display = 'flex';
    document.getElementById('idNewContactAlias').value = '';
    document.getElementById('idNewContactPubKey').value = '';
    idRenderContacts();
    idRenderContactSelect();
    idRenderClaimedSenderSelect();
    idRenderFileContactCheckboxes();
    updateStatus('status.contact.added');
    addLog('log.msg.contactAdded', { alias: alias });
  } catch (e) {
    updateStatus('status.contact.badKey', null, true);
  }
}

function idRenderContacts() {
  const box = document.getElementById('idContactsList');
  if (!box) return;
  box.textContent = '';
  if (!idContacts.length) {
    const p = document.createElement('p');
    p.className = 'field-hint';
    p.textContent = t('contacts.empty');
    box.appendChild(p);
    return;
  }
  idContacts.forEach(function (c) {
    const card = document.createElement('div');
    card.className = 'contact-card';
    const left = document.createElement('div');
    const name = document.createElement('div');
    name.className = 'cc-name';
    const dot = document.createElement('span');
    dot.className = 'cc-status-dot ' + (c.verified ? 'verified' : 'unverified');
    dot.title = t(c.verified ? 'contacts.dot.verified' : 'contacts.dot.unverified');
    dot.setAttribute('aria-label', dot.title);
    name.appendChild(dot);
    name.appendChild(document.createTextNode(c.alias));
    const fp = document.createElement('div');
    fp.className = 'cc-fp adv-only';
    fp.textContent = c.fp;
    left.appendChild(name); left.appendChild(fp);

    const actions = document.createElement('div');
    actions.style.display = 'flex'; actions.style.gap = '6px'; actions.style.flexShrink = '0';
    const verifyBtn = document.createElement('button');
    verifyBtn.type = 'button'; verifyBtn.className = 'btn-sm';
    if (uiMode === 'simple') {
      // Simple mode: the button opens the guided check instead of a bare "mark as verified" switch.
      verifyBtn.innerHTML = iconSvg('shield', 'icon-anim') + '<span>' + escapeHtml(t('contacts.check')) + '</span>';
      verifyBtn.addEventListener('click', function () { fpOpenVerify(c.id); });
    } else {
      verifyBtn.innerHTML = iconSvg(c.verified ? 'undo' : 'shield', 'icon-anim') + '<span>' + escapeHtml(t(c.verified ? 'contacts.unverify' : 'contacts.verify')) + '</span>';
      verifyBtn.addEventListener('click', function () { idToggleContactVerified(c.id); });
    }
    const delBtn = document.createElement('button');
    delBtn.type = 'button'; delBtn.className = 'btn-sm';
    delBtn.innerHTML = iconSvg('trash', 'icon-anim') + '<span>' + escapeHtml(t('contacts.delete')) + '</span>';
    delBtn.addEventListener('click', function () { idDeleteContact(c.id); });
    actions.appendChild(verifyBtn); actions.appendChild(delBtn);
    card.appendChild(left); card.appendChild(actions);
    box.appendChild(card);
  });
}

async function idToggleContactVerified(id) {
  playSound('click');
  const c = idContacts.find(function (x) { return x.id === id; });
  if (!c) return;
  c.verified = !c.verified;
  await idSaveContacts();
  idRenderContacts();
  updateStatus(c.verified ? 'status.contact.verified' : 'status.contact.unverified', { alias: c.alias });
}

async function idDeleteContact(id) {
  if (!confirm(t('contacts.deleteConfirm'))) return;
  playSound('click');
  idContacts = idContacts.filter(function (c) { return c.id !== id; });
  await idSaveContacts();
  idRenderContacts();
  idRenderContactSelect();
  idRenderClaimedSenderSelect();
  idRenderFileContactCheckboxes();
  updateStatus('status.contact.deleted');
  addLog('log.msg.contactDeleted');
}

function idRenderContactSelect() {
  const sel = document.getElementById('idContactSelect');
  if (!sel) return;
  const previous = sel.value;
  sel.textContent = '';
  if (!idContacts.length) {
    const opt = document.createElement('option'); opt.value = ''; opt.textContent = t('contacts.none'); sel.appendChild(opt);
    secUpdateSmartUI();
    return;
  }
  // Security review #14: with no placeholder option, the <select> defaulted to whichever
  // contact happened to be first — so an unchanged dropdown silently meant "send to my
  // first contact", not "no recipient chosen". A disabled placeholder forces an explicit
  // pick before anything can be sent (secProcess() already checks for an empty value).
  const placeholder = document.createElement('option');
  placeholder.value = ''; placeholder.disabled = true; placeholder.textContent = t('contacts.selectPlaceholder');
  sel.appendChild(placeholder);
  idContacts.forEach(function (c) {
    const opt = document.createElement('option'); opt.value = c.id; opt.textContent = c.alias; sel.appendChild(opt);
  });
  sel.value = previous && idContacts.some(function (c) { return c.id === previous; }) ? previous : '';
  secUpdateSmartUI();
}

function idRenderClaimedSenderSelect() {
  const sel = document.getElementById('idClaimedSenderSelect');
  if (!sel) return;
  const previous = sel.value;
  sel.textContent = '';
  if (!idContacts.length) {
    const opt = document.createElement('option'); opt.value = ''; opt.textContent = t('contacts.none'); sel.appendChild(opt);
    return;
  }
  idContacts.forEach(function (c) {
    const opt = document.createElement('option'); opt.value = c.id; opt.textContent = c.alias; sel.appendChild(opt);
  });
  if (previous) sel.value = previous;
}

// ====================================================================================
// SECURE MESSAGE UI
// ====================================================================================
function secSetRecipientMode(mode, silent) {
  if (!silent) playSound('click');
  secRecipientMode = mode;
  ['contact', 'paste'].forEach(function (m) {
    document.getElementById('secRecip' + capitalize(m) + 'Btn').classList.toggle('active', m === mode);
    document.getElementById('secRecip' + capitalize(m) + 'Wrap').style.display = (m === mode) ? 'block' : 'none';
  });
  pipeInvalidate();
  secUpdateSmartUI();
}
function secSetSenderMode(mode, silent) {
  if (!silent) playSound('click');
  secSenderMode = mode;
  ['auto', 'contact', 'paste', 'none'].forEach(function (m) {
    document.getElementById('secSender' + capitalize(m) + 'Btn').classList.toggle('active', m === mode);
    document.getElementById('secSender' + capitalize(m) + 'Wrap').style.display = (m === mode) ? 'block' : 'none';
  });
}
function capitalize(s) { return s.charAt(0).toUpperCase() + s.slice(1); }

async function secCheckPastedRecipient() {
  const val = document.getElementById('secPastePubKey').value.trim();
  const box = document.getElementById('secPasteFpBox');
  secPastedRecipientRaw = null;
  pipeInvalidate();
  if (!val) { box.style.display = 'none'; return; }
  try {
    const raw = AnigmaCrypto.b64ToBuf(val);
    await AnigmaCrypto.importPublicKeyRaw(raw);
    const fp = await AnigmaCrypto.computeFingerprint(raw);
    secPastedRecipientRaw = raw;
    box.style.display = 'block';
    document.getElementById('secPasteFpText').textContent = fp;
  } catch (e) {
    box.style.display = 'none';
  }
  pipeRender();
}
async function secSaveAsContact() {
  if (!secPastedRecipientRaw) return;
  const alias = prompt(t('contacts.saveAsPrompt'));
  if (!alias) return;
  try {
    await idAddContactRaw(alias, document.getElementById('secPastePubKey').value.trim());
    idRenderContacts(); idRenderContactSelect(); idRenderClaimedSenderSelect(); idRenderFileContactCheckboxes();
    updateStatus('status.contact.added');
    addLog('log.msg.contactAdded', { alias: alias });
  } catch (e) { updateStatus('status.contact.badKey', null, true); }
}

function secSyncAnonUI() {
  const btn = document.getElementById('secAnonToggle'); if (!btn) return;
  const on = btn.classList.contains('on');
  const st = document.getElementById('secAnonState');
  if (st) { st.textContent = t(on ? 'switch.on' : 'switch.off'); st.classList.toggle('on', on); }
  const hint = document.getElementById('secAnonHint'); if (hint) hint.style.display = on ? '' : 'none';
}
function secToggleAnonymous() {
  playSound('click');
  const btn = document.getElementById('secAnonToggle');
  const on = !btn.classList.contains('on');
  btn.classList.toggle('on', on);
  btn.setAttribute('aria-checked', on ? 'true' : 'false');
  secSyncAnonUI();
  pipeInvalidate();
}
// Anonymous sending is an Advanced-only control: in Simple mode a leftover "on" can never apply.
function secIsAnonymous() { return uiMode === 'advanced' && document.getElementById('secAnonToggle').classList.contains('on'); }

// secBanner is meant to be the only container for the current decryption-result display.
// If anything is ever added as a sibling next to it (e.g. via insertAdjacentElement)
// instead of as a child, it would never be cleared by this function otherwise — so as a
// safeguard we also sweep secBanner's parent for such leftovers.
function secClearBanner() {
  const b = document.getElementById('secBanner');
  b.style.display = 'none'; b.innerHTML = '';
  const fb = document.getElementById('secFallback'); if (fb) fb.style.display = 'none';
  if (b.parentElement) {
    Array.from(b.parentElement.querySelectorAll('.sec-banner-extra')).forEach(function (el) { el.remove(); });
  }
}
function secShowBanner(cls, iconName, text) {
  const b = document.getElementById('secBanner');
  b.className = 'banner ' + cls;
  b.style.display = 'flex';
  b.innerHTML = iconSvg(iconName) + '<span>' + escapeHtml(text) + '</span>';
}

// ---- smart action: one button, label follows what is in the box --------------------------------
// Anything that starts with Anigma's package prefix ("ANGM<version>:") is treated as an encrypted
// package to open; everything else is plain text to encrypt. The prefix check is the same magic
// string crypto.js itself requires (AnigmaCrypto.MSG_MAGIC = 'ANGM3:'); matching any ANGM<n>: means an
// older/newer package gets crypto.js's clear "not a valid / older version" answer instead of being
// silently re-encrypted as if it were a message.
//
// Security review #10: invisible Unicode formatting characters (bidi marks like RLM/LRM, zero-width
// characters) are ordinary, legitimate content in real Persian/Arabic text — a user may genuinely
// have one at the very start of a pasted paragraph — so they must never be stripped from plaintext
// the user is choosing to ENCRYPT. But they are never legitimately part of an Anigma package's own
// "ANGM<n>:" prefix or its base64 body, so when text is being treated AS a package — for the
// encrypt-vs-decrypt detection below, and for the string actually handed to decryptMessage() — they
// only ever get in the way: a leading one hid the "ANGM" prefix entirely (making a real package look
// like plain text, so "Send securely" re-encrypted an already-encrypted package instead of opening
// it), and a trailing one broke parsing with a generic "Couldn't open this message". Stripping them
// ONLY on this package-detection/parsing path — never from plaintext being encrypted — fixes both
// without touching anything a Persian-speaking user actually typed.
function stripInvisibleFormatting(s) { return (s || '').replace(/[\u200B-\u200F\u202A-\u202E\u2066-\u2069]/g, ''); }
// Current messages carry NO recognisable prefix (that was the point: a fixed header lets any filter flag
// every user). So "is this a package?" is a shape test: legacy "ANGM<n>:" text, or one unbroken run of
// base64 at least as long as the smallest possible message (32+28 header bytes + a 256-byte padded body
// + tag = 332 bytes = 444 characters). Line breaks added by chat apps are tolerated; spaces are not, so
// ordinary prose never matches. Long pure-base64 text someone wants to encrypt as-is: "Encrypt anyway".
function secLooksLikePackage(text) {
  const s = stripInvisibleFormatting(text || '').trim();
  if (/^ANGM\d+:/.test(s)) return true;
  const flat = s.replace(/[\r\n]+/g, '');
  return flat.length >= 440 && flat.length % 4 === 0 && /^[A-Za-z0-9+\/]+={0,2}$/.test(flat);
}
function secCurrentAction() {
  if (secForceEncrypt) return 'encrypt';
  return secLooksLikePackage(document.getElementById('secureInput').value) ? 'decrypt' : 'encrypt';
}
function secUpdateSmartUI() {
  const panel = document.getElementById('panelSecure');
  const inputEl = document.getElementById('secureInput');
  if (!panel || !inputEl) return;
  const looksPackage = secLooksLikePackage(inputEl.value);
  const action = secCurrentAction();
  const enc = action === 'encrypt';
  panel.setAttribute('data-smart', action);

  const label = document.getElementById('secSmartLabel');
  const key = enc ? 'secure.action.encrypt' : 'secure.action.decrypt';
  label.setAttribute('data-i18n', key); label.textContent = t(key);
  const icon = document.getElementById('secSmartIcon');
  const wantIcon = enc ? 'lock' : 'unlock';
  if (icon.getAttribute('data-icon') !== wantIcon) { icon.setAttribute('data-icon', wantIcon); setIcon(icon, wantIcon); }

  document.getElementById('secDetectHint').textContent = inputEl.value.trim() ? t(enc ? 'secure.detect.encrypt' : 'secure.detect.decrypt') : '';
  document.getElementById('secForceEncBtn').style.display = (looksPackage && !secForceEncrypt) ? '' : 'none';

  // Recipient area: pasting a key is the primary path; the contact picker (or a friendly
  // "add a contact first" nudge when there are none) only shows up in contact mode.
  const contactMode = secRecipientMode === 'contact';
  document.getElementById('secRecipContactWrap').style.display = (contactMode && idContacts.length) ? 'block' : 'none';
  document.getElementById('secNoContacts').style.display = (contactMode && !idContacts.length) ? 'block' : 'none';
  pipeRender();
}
function secOnInput() {
  secForceEncrypt = false;
  pipeInvalidate();
  secUpdateSmartUI();
}
function secSmartAction() { return secProcess(secCurrentAction() === 'encrypt'); }

// ---- sharing (Web Share API, falling back to copy) ---------------------------------------------
function canWebShare() { return typeof navigator !== 'undefined' && typeof navigator.share === 'function'; }
// Resolves to 'shared' | 'cancelled' | 'copied' | 'failed'. A user dismissing the share sheet is a
// normal outcome (AbortError), not an error; any other failure falls back to the clipboard.
async function shareTextOrCopy(text, title) {
  if (canWebShare()) {
    try { await navigator.share({ title: title, text: text }); return 'shared'; }
    catch (e) { if (e && e.name === 'AbortError') return 'cancelled'; }
  }
  return (await copyToClipboard(text)) ? 'copied' : 'failed';
}
function secClearOutput() {
  document.getElementById('secureOutput').value = '';
  fxPipeReset();
  secLastOutputSensitive = false;
  secUpdateResultActions();
}
function secUpdateResultActions() {
  const btn = document.getElementById('secShareBtn');
  if (!btn) return;
  // Only ciphertext is ever offered for sharing. Decrypted plaintext stays on the copy path, which
  // has the clipboard auto-clear; pushing it into another app's share sheet is not something to make easy.
  const hasCipher = !!document.getElementById('secureOutput').value && !secLastOutputSensitive;
  btn.style.display = (canWebShare() && hasCipher) ? '' : 'none';
}
async function secShareOutput() {
  playSound('click');
  const val = document.getElementById('secureOutput').value;
  if (!val) { updateStatus('status.out.empty'); return; }
  if (secLastOutputSensitive) return;
  const r = await shareTextOrCopy(val, t('secure.shareTitle'));
  if (r === 'copied') updateStatus('status.share.fallbackCopied');
  else if (r === 'failed') updateStatus('status.copy.failed', null, true);
}
async function idShareMyId() {
  playSound('click');
  if (!idPublicKeyB64) return;
  const r = await shareTextOrCopy(idPublicKeyB64, t('identity.shareTitle'));
  if (r === 'copied') updateStatus('status.share.fallbackCopied');
  else if (r === 'failed') updateStatus('status.copy.failed', null, true);
}

// ---- encrypt / decrypt ------------------------------------------------------------------------
async function secProcess(isEncrypt) {
  playSound('click');
  secClearBanner();
  if (!idPrivateKey) { updateStatus('status.secure.needUnlock', null, true); return; }
  const input = document.getElementById('secureInput').value;
  if (!input.trim()) { updateStatus('status.secure.needInput', null, true); return; }
  updateStatus(isEncrypt ? 'status.busy.encrypting' : 'status.busy.decrypting');
  // Never leave the previous result (possibly decrypted plaintext) sitting under a new attempt's outcome.
  secClearOutput();

  try {
    if (isEncrypt) {
      let recipientRaw = null;
      if (secRecipientMode === 'contact') {
        const contactId = document.getElementById('idContactSelect').value;
        const c = idContacts.find(function (x) { return x.id === contactId; });
        if (!c) { updateStatus('status.secure.needRecipient', null, true); return; }
        recipientRaw = AnigmaCrypto.b64ToBuf(c.pub);
      } else if (secRecipientMode === 'paste') {
        if (!secPastedRecipientRaw) { updateStatus('status.secure.needRecipient', null, true); return; }
        recipientRaw = secPastedRecipientRaw;
      }
      const anon = secIsAnonymous();
      const packed = await AnigmaCrypto.encryptMessage(input, recipientRaw, {
        senderPrivateKey: idPrivateKey, senderPublicKeyRaw: idPublicKeyRaw, anonymous: anon
      });
      document.getElementById('secureOutput').value = packed;
      fxPipeRun(packed.length, packed);
      secLastOutputSensitive = false;
      secUpdateResultActions();
      playSound('lock');
      updateStatus('status.secure.encrypted');
      addLog('log.msg.secureEnc');
    } else {
      await secDecryptFlow(stripInvisibleFormatting(input).trim());
    }
  } catch (e) {
    addLog('log.msg.decFail');
    if (isEncrypt && e && e.message === 'curve-mismatch') {
      showError('status.secure.curveMismatch');
      return;
    }
    showError(isEncrypt ? 'status.unexpected' : 'status.secure.failed', { msg: (e && e.message) ? e.message : '' });
  }
}

// One decrypt attempt against (optionally) one claimed sender. Never throws for the expected crypto
// outcomes; returns { ok:true, result } or { ok:false, code } so callers can decide what to do next.
async function secAttemptDecrypt(packed, claimedSenderRaw) {
  try {
    const result = await AnigmaCrypto.decryptMessage(packed, { myPrivateKey: idPrivateKey, myPublicKeyRaw: idPublicKeyRaw, claimedSenderPubRaw: claimedSenderRaw });
    return { ok: true, result: result };
  } catch (e) {
    const m = e && e.message;
    if (m === 'not-anigma' || m === 'unsupported-version') return { ok: false, code: 'not-anigma' };
    if (m === 'no-candidate' || m === 'mode-mismatch' || m === 'decrypt-failed') return { ok: false, code: m };
    return { ok: false, code: 'error', err: e };
  }
}
function secReportDecryptFailure(code) {
  // Differentiate what actually went wrong where the crypto can tell us — but never claim more precision
  // than AEAD gives: a wrong key and a tampered/corrupted ciphertext both surface as the *same*
  // authentication failure by design, so the generic failure text honestly names both.
  const map = { 'not-anigma': 'status.secure.notAnigma', 'no-candidate': 'status.secure.needCandidate', 'mode-mismatch': 'status.secure.modeMismatch' };
  updateStatus(map[code] || 'status.secure.failed', null, true);
  addLog('log.msg.decFail');
}

// Who could have sent this? Every saved contact, then the user's own key (a message they encrypted for
// themselves is authenticated under their own identity).
function secSenderCandidates() {
  const out = idContacts.map(function (c) { return { alias: c.alias, b64: c.pub, verified: !!c.verified }; });
  if (idPublicKeyB64) out.push({ alias: t('common.you'), b64: idPublicKeyB64, verified: true }); // messages "from yourself" need no separate out-of-band check
  return out;
}

async function secDecryptFlow(packed) {
  // Manual sender choices (the original behavior) are still honored, exactly, in Advanced mode.
  if (uiMode === 'advanced' && secSenderMode !== 'auto') {
    let claimedRaw = null, claimedAlias = null, claimedVerified = false;
    if (secSenderMode === 'contact') {
      const sid = document.getElementById('idClaimedSenderSelect').value;
      const c = idContacts.find(function (x) { return x.id === sid; });
      if (c) { claimedRaw = AnigmaCrypto.b64ToBuf(c.pub); claimedAlias = c.alias; claimedVerified = !!c.verified; }
    } else if (secSenderMode === 'paste') {
      const val = document.getElementById('secSenderPasteKey').value.trim();
      if (val) { try { claimedRaw = AnigmaCrypto.b64ToBuf(val); } catch (e) {} }
    }
    if (secSenderMode !== 'none' && !claimedRaw) { updateStatus('status.secure.needSenderInfo', null, true); return; }
    const r = await secAttemptDecrypt(packed, claimedRaw);
    if (!r.ok) { secReportDecryptFailure(r.code); return; }
    let sender = null;
    if (r.result.mode === 'auth') {
      sender = (secSenderMode === 'paste')
        ? { pastedFp: await AnigmaCrypto.computeFingerprint(claimedRaw) }
        : { alias: claimedAlias || t('secure.claimedSenderMode.paste'), verified: claimedVerified };
    }
    secShowDecrypted(r.result, sender);
    return;
  }

  // Automatic: try the anonymous form first (needs no sender at all), then every candidate sender.
  // This is nothing more than the trial the user used to do by hand — each attempt is a normal
  // authenticated decryption whose tag only verifies under the true sender's key — so no security
  // property changes; it just no longer asks the user to guess who to pick.
  const first = await secAttemptDecrypt(packed, null);
  if (first.ok) { secShowDecrypted(first.result, null); return; }
  if (first.code !== 'no-candidate' && first.code !== 'decrypt-failed') { secReportDecryptFailure(first.code); return; }

  for (const cand of secSenderCandidates()) {
    let raw;
    try { raw = AnigmaCrypto.b64ToBuf(cand.b64); } catch (e) { continue; }
    const r = await secAttemptDecrypt(packed, raw);
    if (r.ok) { secShowDecrypted(r.result, { alias: cand.alias, verified: cand.verified }); return; }
    // An inconsistent/tampered result or a non-Anigma package must stop the search and be reported,
    // not be papered over by trying more keys. A plain authentication failure just means "not this one".
    if (r.code === 'mode-mismatch' || r.code === 'not-anigma') { secReportDecryptFailure(r.code); return; }
  }

  // Nobody matched: only now do we ask the user for a sender key.
  secReportDecryptFailure('decrypt-failed');
  const fb = document.getElementById('secFallback');
  document.getElementById('secFallbackKey').value = '';
  fb.style.display = 'block';
}

async function secFallbackRetry() {
  playSound('click');
  if (!idPrivateKey) { updateStatus('status.secure.needUnlock', null, true); return; }
  const val = document.getElementById('secFallbackKey').value.trim();
  let raw;
  try { raw = AnigmaCrypto.b64ToBuf(val); await AnigmaCrypto.importPublicKeyRaw(raw); }
  catch (e) { updateStatus('status.contact.badKey', null, true); return; }
  secClearOutput();
  const r = await secAttemptDecrypt(stripInvisibleFormatting(document.getElementById('secureInput').value).trim(), raw);
  if (!r.ok) { secReportDecryptFailure(r.code); return; }
  secClearBanner();
  secShowDecrypted(r.result, { pastedFp: await AnigmaCrypto.computeFingerprint(raw) });
}

// sender: null (anonymous), { alias, verified } (a saved contact / "you"), or { pastedFp } (a key
// pasted by hand). The AEAD tag proves the message was encrypted under the key we tried, full
// stop — whether that key was ever confirmed out-of-band (fingerprint compare) as belonging to the
// real person is a separate question this banner must not blur (security review #14): an
// unverified contact's key is trust-on-first-use, same as adding a new contact in Signal or
// WhatsApp — a real property, just not the same one "confirmed" implies.
function secShowDecrypted(result, sender) {
  document.getElementById('secureOutput').value = result.text;
  fxPipeOpen({ chars: Array.from(result.text).length, name: sender && sender.alias,
    kind: (result.mode === 'auth' && sender) ? (sender.pastedFp ? 'pasted' : (sender.verified ? 'ok' : 'unv')) : (result.mode === 'anon' ? 'anon' : 'none') });
  secLastOutputSensitive = true;
  secUpdateResultActions();
  if (result.mode === 'auth' && sender) {
    if (sender.pastedFp) secShowBanner('banner-verified', 'shield', t('secure.banner.authPastedKey', { fp: sender.pastedFp }));
    else if (sender.verified) secShowBanner('banner-verified', 'shield', t('secure.banner.verified', { alias: sender.alias }));
    else secShowBanner('banner-verified', 'help', t('secure.banner.authUnverified', { alias: sender.alias }));
  } else {
    secShowBanner('banner-anon', 'help', t('secure.banner.anon'));
  }
  playSound('unlock');
  updateStatus('status.secure.decrypted');
  addLog('log.msg.secureDec');
  seenCheckAndRecord(result.id).then(function (firstSeenTs) {
    if (firstSeenTs) secAppendBannerWarning(t('secure.banner.replay', { when: new Date(firstSeenTs).toLocaleString() }));
  }, function () {});
}

// ---- replay hint --------------------------------------------------------------------------------
// Every message carries a random id inside its authenticated plaintext. This device keeps the ids of
// the last 500 messages it opened (encrypted under the identity key, bound to its own storage slot).
// Seeing an id again means the same ciphertext is being presented a second time — you re-opening it
// yourself, or somebody re-sending a copy they recorded. It is a warning, not a block, and it only
// works per device: a replay to a device that never saw the original can't be recognised.
async function seenCheckAndRecord(id) {
  if (!id || !idMasterKey) return null;
  let list = [];
  try {
    const raw = localStorage.getItem('anigma_seen_v1');
    if (raw) list = JSON.parse(new TextDecoder().decode(await AnigmaCrypto.openStored(idMasterKey, 'seen', JSON.parse(raw))));
    if (!Array.isArray(list)) list = [];
  } catch (e) { list = []; }
  const hit = list.find(function (x) { return x && x.i === id; });
  if (hit) return hit.t || Date.now();
  list.push({ i: id, t: Date.now() });
  if (list.length > 500) list = list.slice(-500);
  try {
    const sealed = await AnigmaCrypto.sealStored(idMasterKey, 'seen', new TextEncoder().encode(JSON.stringify(list)));
    localStorage.setItem('anigma_seen_v1', JSON.stringify({ v: 1, aad: 1, iv: AnigmaCrypto.bufToB64(sealed.iv), ct: AnigmaCrypto.bufToB64(sealed.ct) }));
  } catch (e) {}
  return null;
}
function secAppendBannerWarning(text) {
  const b = document.getElementById('secBanner');
  const span = b && b.querySelector('span');
  if (!span) return;
  const w = document.createElement('div');
  w.style.marginTop = '6px'; w.style.fontWeight = '600';
  w.textContent = text;
  span.appendChild(w);
}

async function secCopyOutput() {
  playSound('click');
  const val = document.getElementById('secureOutput').value;
  if (!val) { updateStatus('status.out.empty'); return; }
  const ok = secLastOutputSensitive ? await copySensitiveToClipboard(val) : await copyToClipboard(val);
  updateStatus(ok ? (secLastOutputSensitive ? 'status.out.copiedClears' : 'status.out.copied') : 'status.copy.failed', null, !ok);
}

// ====================================================================================
// FILES UI
// ====================================================================================
function idRenderFileContactCheckboxes() {
  const box = document.getElementById('fileContactsCheckboxList');
  if (!box) return;
  const checked = Array.from(box.querySelectorAll('input[type=checkbox]:checked')).map(function (el) { return el.value; });
  box.textContent = '';
  if (!idContacts.length) {
    const p = document.createElement('p'); p.className = 'field-hint'; p.textContent = t('contacts.empty'); box.appendChild(p);
    return;
  }
  idContacts.forEach(function (c) {
    const row = document.createElement('label');
    row.className = 'contact-card';
    row.style.cursor = 'pointer';
    const left = document.createElement('div'); left.className = 'cc-name';
    const cb = document.createElement('input'); cb.type = 'checkbox'; cb.value = c.id; cb.checked = checked.indexOf(c.id) !== -1;
    left.appendChild(cb);
    left.appendChild(document.createTextNode(' ' + c.alias));
    row.appendChild(left);
    box.appendChild(row);
  });
}

function filesSetRecipientMode(mode, silent) {
  if (!silent) playSound('click');
  filesRecipientMode = mode;
  ['contacts', 'paste'].forEach(function (m) {
    document.getElementById('fileRecip' + capitalize(m) + 'Btn').classList.toggle('active', m === mode);
    document.getElementById('fileRecip' + capitalize(m) + 'Wrap').style.display = (m === mode) ? 'block' : 'none';
  });
}
function filesSetSenderMode(mode, silent) {
  if (!silent) playSound('click');
  filesSenderMode = mode;
  ['auto', 'contact', 'paste'].forEach(function (m) {
    document.getElementById('fileSender' + capitalize(m) + 'Btn').classList.toggle('active', m === mode);
    document.getElementById('fileSender' + capitalize(m) + 'Wrap').style.display = (m === mode) ? 'block' : 'none';
  });
}
async function filesCheckPastedRecipient() {
  const val = document.getElementById('fileRecipPasteKey').value.trim();
  const box = document.getElementById('fileRecipPasteFpBox');
  filesPastedRecipientRaw = null;
  if (!val) { box.style.display = 'none'; return; }
  try {
    const raw = AnigmaCrypto.b64ToBuf(val);
    await AnigmaCrypto.importPublicKeyRaw(raw);
    filesPastedRecipientRaw = raw;
    box.style.display = 'block';
    document.getElementById('fileRecipPasteFpText').textContent = await AnigmaCrypto.computeFingerprint(raw);
  } catch (e) { box.style.display = 'none'; }
}
function filesCheckPastedSender() {
  const val = document.getElementById('fileSenderPasteKey').value.trim();
  filesClaimedSenderRaw = null;
  if (!val) return;
  try { filesClaimedSenderRaw = AnigmaCrypto.b64ToBuf(val); } catch (e) {}
}

function humanSize(bytes) {
  if (bytes < 1024) return bytes + ' B';
  const units = ['KB', 'MB', 'GB', 'TB'];
  let v = bytes, i = -1;
  do { v /= 1024; i++; } while (v >= 1024 && i < units.length - 1);
  return v.toFixed(v < 10 ? 2 : 1) + ' ' + units[i];
}

function filesAddEntries(newFiles) {
  for (const f of newFiles) {
    const relPath = f.webkitRelativePath && f.webkitRelativePath.length ? f.webkitRelativePath : f.name;
    filesSelected.push({ file: f, relPath: relPath });
  }
  renderFilesManifest();
}
function filesClearSelection() { filesSelected = []; renderFilesManifest(); }

function renderFilesManifest() {
  const box = document.getElementById('filesManifestBox');
  const title = document.getElementById('filesManifestTitle');
  if (!box || !title) return;
  if (!filesSelected.length) { box.style.display = 'none'; title.textContent = ''; return; }
  let total = 0;
  box.style.display = 'block';
  box.textContent = '';
  filesSelected.forEach(function (e) {
    total += e.file.size;
    const row = document.createElement('div');
    row.className = 'file-manifest-row';
    const name = document.createElement('span'); name.className = 'fm-name'; name.textContent = e.relPath;
    const size = document.createElement('span'); size.className = 'fm-size'; size.textContent = humanSize(e.file.size);
    row.appendChild(name); row.appendChild(size);
    box.appendChild(row);
  });
  title.textContent = t('files.manifestTitle', { count: filesSelected.length, size: humanSize(total) });
}

function filesUpdateChunkLabel() {
  const range = document.getElementById('fileChunkSizeRange');
  document.getElementById('fileChunkSizeLabelText').textContent = t('files.chunkSize.label', { mb: range.value });
}

// ------------------------------------------------------------------ progress UI
function filesShowProgress(show) {
  document.getElementById('filesProgressWrap').style.display = show ? 'block' : 'none';
  document.getElementById('fileEncryptBtn').disabled = show;
  document.getElementById('filesDecryptTrigger').disabled = show;
}
let filesProgressStartTime = 0;
// Tracks which phase the currently-displayed progress belongs to ('preparing' while
// worker.js is reading+compressing files, undefined/'writing' once it's actually
// streaming ciphertext to disk) so filesStartEncrypt() can reset the elapsed-time
// baseline when the phase changes — 'processed'/'total' mean different things in each
// phase (original bytes read vs. final ciphertext bytes written), so a speed/ETA figure
// computed across the boundary would be meaningless.
let filesProgressPhase = null;
function filesRenderProgress(processed, total, fileName, fileIndex, fileCount, phase) {
  const pct = total > 0 ? Math.min(100, Math.round((processed / total) * 100)) : 0;
  document.getElementById('filesProgressFill').style.width = pct + '%';
  const elapsedS = (Date.now() - filesProgressStartTime) / 1000;
  const speed = elapsedS > 0 ? processed / elapsedS : 0;
  const remaining = total - processed;
  const etaS = speed > 0 ? remaining / speed : 0;
  const statsKey = phase === 'preparing' ? 'files.progress.preparingStats' : 'files.progress.stats';
  document.getElementById('filesProgressMeta').textContent =
    t(statsKey, { percent: pct, done: humanSize(processed), total: humanSize(total), speed: humanSize(speed), eta: formatEta(etaS) }) +
    (fileName ? ' — ' + t('files.progress.processing', { name: fileName, index: fileIndex || 0, count: fileCount || filesSelected.length }) : '');
}
function formatEta(seconds) {
  if (!isFinite(seconds) || seconds < 0) return '—';
  const s = Math.round(seconds);
  const m = Math.floor(s / 60), r = s % 60;
  return m > 0 ? (m + 'm ' + r + 's') : (r + 's');
}

// ------------------------------------------------------------------ wake lock + unload guard
async function filesAcquireWakeLock() {
  try { if ('wakeLock' in navigator) wakeLockRef = await navigator.wakeLock.request('screen'); } catch (e) { wakeLockRef = null; }
}
function filesReleaseWakeLock() { try { if (wakeLockRef) wakeLockRef.release(); } catch (e) {} wakeLockRef = null; }
function filesBeforeUnload(ev) { if (filesOperationActive) { ev.preventDefault(); ev.returnValue = ''; } }
window.addEventListener('beforeunload', filesBeforeUnload);

// ------------------------------------------------------------------ ENCRYPT
async function filesStartEncrypt() {
  playSound('click');
  if (!idPrivateKey) { updateStatus('files.needUnlock', null, true); return; }
  if (!filesSelected.length) { updateStatus('files.needFiles', null, true); return; }
  if (filesOperationActive) { updateStatus('files.busy', null, true); return; } // see the race-condition note in filesHandleDecryptFile()

  let recipientPubs = [];
  try {
    if (filesRecipientMode === 'contacts') {
      const checked = Array.from(document.getElementById('fileContactsCheckboxList').querySelectorAll('input:checked')).map(function (el) { return el.value; });
      recipientPubs = idContacts.filter(function (c) { return checked.indexOf(c.id) !== -1; }).map(function (c) { return AnigmaCrypto.b64ToBuf(c.pub); });
    } else if (filesRecipientMode === 'paste') {
      if (filesPastedRecipientRaw) recipientPubs = [filesPastedRecipientRaw];
    }
  } catch (e) { recipientPubs = []; }
  if (!recipientPubs.length) { updateStatus('files.needRecipient', null, true); return; }
  if (recipientPubs.length > AnigmaContainer.MAX_RECIPIENTS) { updateStatus('files.err.tooManyRecipients', { max: AnigmaContainer.MAX_RECIPIENTS }, true); return; }

  const chunkSizeMB = parseInt(document.getElementById('fileChunkSizeRange').value, 10);
  const compressMode = document.getElementById('fileCompressionSelect').value;
  const roundSize = document.getElementById('fileRoundSizeToggle').classList.contains('on');

  const totalBytes = filesSelected.reduce(function (s, e) { return s + e.file.size; }, 0);
  const BLOB_CAP = 800 * 1024 * 1024;
  let destination = null;
  const hasFsApi = 'showSaveFilePicker' in window;
  if (hasFsApi) {
    const pickerStartedAt = Date.now();
    try {
      const handle = await window.showSaveFilePicker({ suggestedName: 'package.anigma', types: [{ description: 'Anigma package', accept: { 'application/octet-stream': ['.anigma'] } }] });
      destination = { mode: 'fsapi', handle: handle };
    } catch (e) {
      // Both a real user-cancel AND a picker that never actually opened (missing native
      // file-dialog support — e.g. Linux without xdg-desktop-portal, some sandboxed/embedded
      // browsers, certain remote/headless sessions, blocked by permissions policy) surface as
      // the exact same AbortError, with no other distinguishing field. The only reliable
      // signal is time: showing a native dialog, letting a human see it and click Cancel takes
      // well over our threshold; a picker that failed to open rejects near-instantly. Treat a
      // fast AbortError as a picker failure (fall back), and only a slow one as a genuine
      // cancel — this is what previously made encryption silently do nothing whenever the
      // native picker couldn't be shown at all.
      const pickerFailedInstantly = (Date.now() - pickerStartedAt) < FILES_PICKER_CANCEL_MIN_MS;
      if (e && e.name === 'AbortError' && !pickerFailedInstantly) { updateStatus('files.saveCancelled'); return; }
      if (totalBytes > BLOB_CAP) { updateStatus('files.err.tooLargeForBlob', { cap: humanSize(BLOB_CAP) }, true); return; }
      filesNote('files.err.fsapiFallback', { cap: humanSize(BLOB_CAP) });
      destination = { mode: 'blob' };
    }
  } else {
    if (totalBytes > BLOB_CAP) { updateStatus('files.err.tooLargeForBlob', { cap: humanSize(BLOB_CAP) }, true); return; }
    filesNote('files.err.fsapiMissing', { cap: humanSize(BLOB_CAP) });
    destination = { mode: 'blob' };
  }

  try {
    if (navigator.storage && navigator.storage.estimate) {
      const est = await navigator.storage.estimate();
      const free = (est.quota || 0) - (est.usage || 0);
      if (free && free < totalBytes) {
        if (!confirm(t('files.err.diskSpace', { need: humanSize(totalBytes), free: humanSize(free) }))) return;
      }
    }
  } catch (e) { /* estimate unsupported; proceed */ }

  const cekBytes = crypto.getRandomValues(new Uint8Array(32));
  const baseNonce = crypto.getRandomValues(new Uint8Array(7));
  const wraps = [];
  const authKeys = [];
  try {
    for (const pubRaw of recipientPubs) {
      const pubKey = await AnigmaCrypto.importPublicKeyRaw(pubRaw);
      wraps.push(await AnigmaContainer.wrapCekForRecipient(cekBytes, pubKey, idPrivateKey));
      // Per-recipient sender-authentication key (static-static DH): proves to THAT recipient who made
      // the package, which the shared content key cannot.
      authKeys.push(await AnigmaContainer.deriveFileAuthKey(idPrivateKey, pubKey, idPublicKeyRaw, new Uint8Array(pubRaw), baseNonce));
    }
  } catch (e) {
    if (e && e.message === 'curve-mismatch') { showError('files.err.curveMismatch'); return; }
    showError('status.unexpected', { msg: (e && e.message) ? e.message : '' });
    return;
  }
  const headerBytes = await AnigmaContainer.buildMaskedHeader({ chunkSizeMB: chunkSizeMB, baseNonce: baseNonce, wraps: wraps, senderAuth: true });

  await filesRunEncryptOperation({
    files: filesSelected, chunkSizeMB: chunkSizeMB, cekBytes: cekBytes, baseNonce: baseNonce, authKeys: authKeys,
    headerBytes: headerBytes, compressMode: compressMode, roundSize: roundSize, destination: destination,
    outputFilename: 'package.anigma', doneLogKey: 'log.msg.filesEncrypted', doneLogParams: { count: filesSelected.length }
  });
}

// Generic "run the file-encrypt worker to completion" — everything after a caller has
// already worked out WHO the package is for (direct recipients vs a group) and produced
// cekBytes/headerBytes accordingly. Extracted out of filesStartEncrypt() so group file
// encryption (js/groups-ui.js) can share this instead of duplicating it; the contacts/
// self path above is the only caller changed, and only to call this at the same point it
// used to inline this exact code — no behavior change for it.
async function filesRunEncryptOperation(opts) {
  const showProgress = opts.showProgress || filesShowProgress;
  const renderProgress = opts.renderProgress || filesRenderProgress;
  const finishOp = function () { filesFinishOperation(opts.showProgress); };
  filesOperationActive = true;
  showProgress(true);
  filesProgressStartTime = Date.now();
  filesProgressPhase = null;
  await filesAcquireWakeLock();
  updateStatus('files.encrypting');

  // Fix: `filesCreateWorker()` (i.e. `new Worker('js/worker.js')`) can itself throw
  // synchronously — not just postMessage() below it. This happens, for example, whenever
  // the app is opened directly as a local file (file:///.../index.html) instead of being
  // served over http(s)/PWA: browsers refuse to construct a Worker from a 'null' origin,
  // so `new Worker(...)` throws immediately, before `w.onerror` can ever be attached. By
  // this point filesShowProgress(true) has already switched the UI to the "operation
  // running" chrome (progress bar + Cancel button + disabled trigger), so an uncaught
  // throw here — inside an async function with nothing awaiting it — became an invisible
  // unhandled promise rejection: permanently stuck "Encrypting..." UI, no error message,
  // Cancel/trigger buttons dead. Wrapping worker creation in the same try/catch as
  // postMessage() ensures *any* failure to start the operation is surfaced and cleaned up.
  try {
    filesWorker = filesCreateWorker();
    filesWorker.onmessage = async function (ev) {
      const msg = ev.data;
      if (msg.type === 'progress') {
        // See the comment on filesProgressPhase: a phase change means 'processed'/'total'
        // now refer to a different quantity, so the speed/ETA clock restarts from here.
        if (msg.phase !== filesProgressPhase) { filesProgressPhase = msg.phase; filesProgressStartTime = Date.now(); }
        renderProgress(msg.processed, msg.total, msg.fileName, msg.fileIndex, msg.fileCount, msg.phase);
      } else if (msg.type === 'done') {
        if (msg.mode === 'blob') {
          const blob = new Blob(msg.parts, { type: 'application/octet-stream' });
          downloadBlob(blob, opts.outputFilename || 'package.anigma');
        }
        finishOp();
        updateStatus('files.done.encrypt');
        if (opts.doneLogKey) addLog(opts.doneLogKey, opts.doneLogParams);
        playSound('lock');
        if (opts.onDone) opts.onDone();
      } else if (msg.type === 'cancelled') {
        finishOp();
        updateStatus('files.cancelled');
        addLog('log.msg.filesCancelled');
      } else if (msg.type === 'error') {
        finishOp();
        if (filesIsOutOfSpaceError(msg.message)) updateStatus('files.err.noSpace', null, true);
        else showError('status.unexpected', { msg: msg.message });
      }
    };
    filesWorker.postMessage({
      op: 'encrypt', files: opts.files, chunkSizeMB: opts.chunkSizeMB, cekBytes: opts.cekBytes, baseNonce: opts.baseNonce, authKeys: opts.authKeys || null,
      headerBytes: opts.headerBytes, compressMode: opts.compressMode, roundSize: opts.roundSize, destination: opts.destination
    });
  } catch (e) {
    finishOp();
    showError('status.unexpected', { msg: (e && e.message) ? e.message : 'worker-start-failed' });
  }
}

// Builds the file-worker's script from the bundle tools/embed-worker-bundle.js embedded
// into index.html (crypto.js + container.js + worker.js concatenated, worker.js's own
// importScripts() call stripped since crypto.js/container.js are already right above it
// in the same blob) rather than pointing new Worker() at js/worker.js on disk. A path-
// based Worker requires the browser to fetch that file as a separate resource, which is
// refused with a SecurityError when the app is opened as a local file (file://.../
// index.html) instead of served over http(s) — exactly how most people run a single-
// folder offline app: unzip it, double-click index.html. A Worker built from a Blob URL
// needs no such fetch (the code is already in memory), so it works either way. Built once
// and cached, since the embedded source is static for the life of the page.
let filesWorkerBlobUrl = null;
function filesGetWorkerBlobUrl() {
  if (filesWorkerBlobUrl) return filesWorkerBlobUrl;
  const cryptoSrc = document.getElementById('workerBundleCrypto').textContent;
  const containerSrc = document.getElementById('workerBundleContainer').textContent;
  // worker.js's own importScripts(...) call (loading crypto.js and container.js by name)
  // would try to fetch those as separate resources relative to the blob: URL, which fails
  // the same way a path-based Worker does — strip it, since crypto.js/container.js are
  // concatenated in just above.
  const workerSrc = document.getElementById('workerBundleWorker').textContent
    .replace(/importScripts\([^)]*\);?/, '');
  const bundle = cryptoSrc + '\n' + containerSrc + '\n' + workerSrc;
  const blob = new Blob([bundle], { type: 'application/javascript' });
  filesWorkerBlobUrl = URL.createObjectURL(blob);
  return filesWorkerBlobUrl;
}

// Security review #9: worker.js had no `onerror` handler anywhere it's created. If the
// worker script fails to load or throws outside a message handler (e.g. blocked by a
// restrictive CSP, a 404, a syntax error from a broken update), the main thread never heard
// about it — the UI sat on "Encrypting files..."/"Decrypting..." forever, its button
// disabled and `beforeunload` still armed, with no way out but reloading the page. Every
// `filesCreateWorker()` call site goes through this so a worker-level failure is always
// surfaced and the stuck UI state is always cleared.
function filesCreateWorker() {
  const w = new Worker(filesGetWorkerBlobUrl());
  w.onerror = function (ev) {
    filesOperationActive = false;
    filesShowProgress(false);
    filesReleaseWakeLock();
    showError('status.unexpected', { msg: (ev && ev.message) ? ev.message : 'worker-error' });
    if (filesWorker === w) filesWorker = null;
  };
  return w;
}

function filesCancelOperation() {
  if (!filesOperationActive || !filesWorker) return;
  if (!confirm(t('confirm.cancelOperation'))) return;
  filesWorker.postMessage({ op: 'cancel' });
}
function filesFinishOperation(hideProgressFn) {
  filesOperationActive = false;
  (hideProgressFn || filesShowProgress)(false);
  filesReleaseWakeLock();
  if (filesWorker) { filesWorker.terminate(); filesWorker = null; }
}

// ------------------------------------------------------------------ DECRYPT
let filesPendingDecrypt = null; // { file, headerInfo, cekBytes }

// Informational (not red) outside Advanced mode: "large files may take a while" is not an error.
function filesNote(key, params) {
  if (uiMode === 'advanced') showError(key, params);
  else { updateStatus(key, params, false); addLog(key, params); }
}

// overrideSenderRaw: a sender key pasted by hand after automatic matching found nobody.
async function filesHandleDecryptFile(file, overrideSenderRaw) {
  if (!idPrivateKey) { updateStatus('files.needUnlock', null, true); return; }
  // UI-race fix: filesStartEncrypt(), this preview step, and filesConfirmDecrypt() all
  // share the same `filesWorker`/`filesPendingDecrypt` module-level variables. Previously
  // only the two real transfer operations disabled their trigger buttons while running
  // (via filesShowProgress) — this preview/manifest step did not, so picking a second
  // package (or clicking Encrypt) while a first preview was still being generated started
  // a second worker that silently clobbered the first one's `filesWorker` reference: the
  // slower response's completion handler would then terminate the WRONG (newer) worker
  // and could show a manifest whose file list and claimed-sender info came from two
  // different packages. Guarding every entry point the same way closes that window.
  if (filesOperationActive) { updateStatus('files.busy', null, true); return; }
  const fbBox = document.getElementById('fileSenderFallback'); if (fbBox) fbBox.style.display = 'none';
  filesFallbackFile = null;
  try {
    // The header is read through AnigmaContainer.readHeader(): it understands both the current masked
    // layout (no recognisable bytes) and older containers that start with the plain "ANGMF" magic, and
    // grows its read until the whole header — however many recipients — has been parsed.
    let headerInfo, fullHeaderBytes;
    try {
      const rh = await AnigmaContainer.readHeader(file);
      headerInfo = rh.info; fullHeaderBytes = rh.headerBytes;
    } catch (e) {
      if (e.message === 'container-unknown-version') { updateStatus('files.err.badVersion', { v: e.foundVersion }, true); return; }
      updateStatus('files.err.badMagic', null, true); return;
    }
    // Security review #3c: chunkSizeMB is a raw, unauthenticated header byte (0-255) that
    // planCipherBlocks() later uses directly as a divisor/multiplier. An untouched value is
    // always 1-16 (this app never writes anything else — see AnigmaContainer.MIN_CHUNK_MB /
    // MAX_CHUNK_MB), but a corrupted or maliciously edited package could carry 0 (division
    // produces astronomical block counts — millions of tiny AES-GCM calls and hundreds of
    // MB of descriptor overhead for a modest file) or an oversized value. Reject anything
    // outside the range this build could ever have produced, before it ever reaches the
    // worker, rather than letting the worker discover it the expensive way.
    if (headerInfo.chunkSizeMB < AnigmaContainer.MIN_CHUNK_MB || headerInfo.chunkSizeMB > AnigmaContainer.MAX_CHUNK_MB) {
      updateStatus('files.err.badChunkSize', null, true); return;
    }

    let cekBytes = null, senderAlias = null, authInfo = null;
    // Unwraps the content key under one candidate sender and, for version-4 packages, derives the
    // key that checks that sender's authentication tag (see the version-4 note in container.js).
    async function tryUnwrap(senderRaw) {
      const pub = await AnigmaCrypto.importPublicKeyRaw(senderRaw);
      const r = await AnigmaContainer.unwrapCekIndexed(headerInfo.wraps, idPrivateKey, pub);
      if (!r) return null;
      const authKey = headerInfo.trailerLen > 0
        ? await AnigmaContainer.deriveFileAuthKey(idPrivateKey, pub, new Uint8Array(senderRaw), new Uint8Array(idPublicKeyRaw), headerInfo.baseNonce)
        : null;
      authInfo = { authKey: authKey, wrapIndex: r.index };
      return r.cek;
    }
    const manual = uiMode === 'advanced' && filesSenderMode !== 'auto' && !overrideSenderRaw;
    if (overrideSenderRaw) {
      // Sender key pasted by hand after automatic matching failed.
      cekBytes = await tryUnwrap(overrideSenderRaw);
    } else if (manual) {
      // The original, explicit choices — unchanged.
      let claimedRaw = null;
      if (filesSenderMode === 'contact') {
        const sid = document.getElementById('fileSenderContactSelect').value;
        const c = idContacts.find(function (x) { return x.id === sid; });
        if (c) { claimedRaw = AnigmaCrypto.b64ToBuf(c.pub); senderAlias = c.alias; }
      } else if (filesSenderMode === 'paste') {
        if (filesClaimedSenderRaw) claimedRaw = filesClaimedSenderRaw;
      }
      if (!claimedRaw) { updateStatus('status.secure.needSenderInfo', null, true); return; }
      cekBytes = await tryUnwrap(claimedRaw);
    } else {
      // Automatic: try each saved contact, then the user's own key, as the possible sender. unwrapCek
      // only succeeds under the true sender's key (AEAD tag), so this is the same check the user would
      // otherwise run by hand, one candidate at a time.
      for (const cand of secSenderCandidates()) {
        try { cekBytes = await tryUnwrap(AnigmaCrypto.b64ToBuf(cand.b64)); } catch (e) { continue; }
        if (cekBytes) { senderAlias = cand.alias; break; }
      }
    }
    if (!cekBytes) {
      updateStatus('files.err.badKey', null, true);
      if (!manual) { filesFallbackFile = file; document.getElementById('fileFallbackKey').value = ''; document.getElementById('fileSenderFallback').style.display = 'block'; }
      return;
    }

    filesPendingDecrypt = { file: file, headerInfo: headerInfo, cekBytes: cekBytes, senderAlias: senderAlias, auth: authInfo };
    filesOperationActive = true;
    filesShowProgress(true); // also disables fileEncryptBtn/filesDecryptTrigger — see the race-condition note above
    // Bug: unlike filesStartEncrypt() and filesConfirmDecrypt(), this preview/manifest-scan
    // step never reset filesProgressStartTime before starting its worker. filesRenderProgress()
    // computes elapsed time as (Date.now() - filesProgressStartTime): on the very first
    // operation of a session that's still its initial value of 0 (epoch), and on any later
    // session it's whatever a PREVIOUS operation left behind — either way `elapsedS` comes out
    // enormous, so `speed = processed / elapsedS` rounds to ~0 B/s and the ETA is garbage for
    // the entire preview scan (the percent bar itself was unaffected, since that's computed
    // straight from processed/total with no time term — only the speed/ETA text was wrong).
    filesProgressStartTime = Date.now();
    updateStatus('files.decrypting');

    filesWorker = filesCreateWorker();
    filesWorker.onmessage = function (ev) {
      const msg = ev.data;
      if (msg.type === 'progress') {
        filesRenderProgress(msg.processed, msg.total, msg.fileName);
      } else if (msg.type === 'manifest') {
        filesFinishOperation();
        filesShowManifestPreview(msg.files);
      } else if (msg.type === 'cancelled') {
        filesFinishOperation();
        updateStatus('files.cancelled');
        addLog('log.msg.filesCancelled');
      } else if (msg.type === 'error') {
        filesFinishOperation();
        filesMapDecryptError(msg.message);
      }
    };
    filesWorker.postMessage({
      op: 'decrypt', containerFile: file, headerLength: headerInfo.headerLength, chunkSizeMB: headerInfo.chunkSizeMB,
      baseNonce: headerInfo.baseNonce, cekBytes: cekBytes, previewOnly: true,
      trailerLen: headerInfo.trailerLen || 0, authKey: authInfo ? authInfo.authKey : null, wrapIndex: authInfo ? authInfo.wrapIndex : -1
    });
  } catch (e) {
    // If this throws after filesShowProgress(true)/filesOperationActive=true above (e.g. a
    // postMessage clone failure), showError alone left the progress UI stuck active forever
    // with no way to start another operation — filesFinishOperation() must run here too, the
    // same as the 'error' branch in the worker's own onmessage handler above does.
    filesFinishOperation();
    showError('status.unexpected', { msg: (e && e.message) ? e.message : '' });
  }
}

// A full drive / exhausted browser storage quota reaches the UI only as the browser's own
// English error text — the worker forwards e.message, not e.name — so without this a user
// with a full disk (in the Persian UI too) is told "Unexpected error: The operation failed
// because it would cause the application to exceed its storage quota." instead of what to do.
// Patterns cover Chromium ("storage quota"), Firefox ("quota has been exceeded" /
// NS_ERROR_FILE_NO_DEVICE_SPACE), Safari/WebKit (QuotaExceededError) and POSIX ENOSPC wording.
function filesIsOutOfSpaceError(message) {
  return /quota|no[ _]space|device[ _]space|disk[ _]full|enospc|not enough space/i.test(String(message || ''));
}

function filesMapDecryptError(message) {
  if (message === 'sender-auth-failed') updateStatus('files.err.senderAuth', null, true);
  else if (message === 'stream-tampered' || message === 'stream-truncated') updateStatus('files.err.tampered', null, true);
  else if (message === 'decompression-bomb') updateStatus('files.err.decompressionBomb', null, true);
  else if (message === 'compression-unsupported') updateStatus('files.err.compressionUnsupported', null, true);
  else if (message === 'bad-chunk-size') updateStatus('files.err.badChunkSize', null, true);
  else if (filesIsOutOfSpaceError(message)) updateStatus('files.err.noSpace', null, true);
  else showError('status.unexpected', { msg: message });
}

async function filesFallbackRetry() {
  playSound('click');
  if (!filesFallbackFile) return;
  const val = document.getElementById('fileFallbackKey').value.trim();
  let raw;
  try { raw = AnigmaCrypto.b64ToBuf(val); await AnigmaCrypto.importPublicKeyRaw(raw); }
  catch (e) { updateStatus('status.contact.badKey', null, true); return; }
  await filesHandleDecryptFile(filesFallbackFile, raw);
}

function filesShowManifestPreview(list) {
  const from = document.getElementById('filesManifestFrom');
  if (from) {
    const alias = filesPendingDecrypt && filesPendingDecrypt.senderAlias;
    from.textContent = alias ? t('files.manifestFrom', { alias: alias }) : '';
    from.style.display = alias ? 'block' : 'none';
  }
  const box = document.getElementById('filesManifestPreviewList');
  box.textContent = '';
  list.forEach(function (f) {
    const row = document.createElement('div');
    row.className = 'file-manifest-row';
    const name = document.createElement('span'); name.className = 'fm-name'; name.textContent = f.name;
    const size = document.createElement('span'); size.className = 'fm-size'; size.textContent = humanSize(f.size);
    row.appendChild(name); row.appendChild(size);
    box.appendChild(row);
  });
  openModal('filesManifestModal');
}

async function filesConfirmDecrypt() {
  closeModal('filesManifestModal');
  if (!filesPendingDecrypt) return;
  if (filesOperationActive) { updateStatus('files.busy', null, true); return; } // see the race-condition note in filesHandleDecryptFile()

  const hasDirApi = 'showDirectoryPicker' in window;
  let dirHandle = null;
  if (hasDirApi) {
    const pickerStartedAt = Date.now();
    try {
      dirHandle = await window.showDirectoryPicker();
    } catch (e) {
      // See the matching comment in filesStartEncrypt(): a picker that never opened at all
      // rejects with the same AbortError a real user-cancel does, in a fraction of the time —
      // only treat a slow AbortError as a genuine cancel.
      const pickerFailedInstantly = (Date.now() - pickerStartedAt) < FILES_PICKER_CANCEL_MIN_MS;
      if (e && e.name === 'AbortError' && !pickerFailedInstantly) { updateStatus('files.saveCancelled'); return; }
      // Picker unusable for some other reason (permissions/context, no user-activation
      // chain in an embedded browser, etc.) — fall back to the in-memory path below
      // instead of giving up, same principle as the encrypt-side fallback.
      dirHandle = null;
    }
  }
  // No directory handle, for any reason (API missing — every mobile browser today — or
  // the picker above couldn't be used): decrypt into memory instead and offer the result
  // as a download. This is what makes "Decrypt" work outside desktop Chromium/Edge.
  const memoryFiles = dirHandle ? null : [];

  if (memoryFiles) {
    const approxPlainBytes = Math.max(0, filesPendingDecrypt.file.size - filesPendingDecrypt.headerInfo.headerLength);
    if (approxPlainBytes > MEMORY_DECRYPT_WARN_BYTES) {
      if (!confirm(t('files.warn.memoryDecrypt', { size: humanSize(approxPlainBytes) }))) return;
    }
  }

  filesOperationActive = true;
  filesShowProgress(true);
  filesProgressStartTime = Date.now();
  await filesAcquireWakeLock();
  updateStatus('files.decrypting');

  const { file, headerInfo, cekBytes, auth } = filesPendingDecrypt;
  await filesRunDecryptOperation({
    file: file, headerInfo: headerInfo, cekBytes: cekBytes, auth: auth, destDirHandle: dirHandle, memoryFiles: memoryFiles,
    doneLogKey: 'log.msg.filesDecrypted', onError: filesMapDecryptError
  });
}

// Generic "run the file-decrypt worker to completion" — everything after a caller has
// already parsed the header and worked out the CEK (direct recipient vs a group).
// Extracted out of filesConfirmDecrypt() so group file decryption (js/groups-ui.js) can
// share it; the contacts/self path above is the only caller changed, only to call this at
// the same point it used to inline this exact code — no behavior change for it.
async function filesRunDecryptOperation(opts) {
  const showProgress = opts.showProgress || filesShowProgress;
  const renderProgress = opts.renderProgress || filesRenderProgress;
  const finishOp = function () { filesFinishOperation(opts.showProgress); };
  filesOperationActive = true;
  showProgress(true);
  filesProgressStartTime = Date.now();
  await filesAcquireWakeLock();
  updateStatus('files.decrypting');

  const memoryFiles = opts.memoryFiles;
  // Fix: same class of bug as filesStartEncrypt() — filesCreateWorker() (`new
  // Worker('js/worker.js')`) can throw synchronously (e.g. file:// origin, blocked by a
  // worker-src CSP, 404 on the script), and that throw must be caught, not just a later
  // postMessage() failure, or the UI is left stuck on "Decrypting..." forever with no
  // error and no way out but reloading.
  try {
    filesWorker = filesCreateWorker();
    filesWorker.onmessage = function (ev) {
      const msg = ev.data;
      if (msg.type === 'progress') {
        renderProgress(msg.processed, msg.total, msg.fileName);
      } else if (msg.type === 'file') {
        if (memoryFiles) memoryFiles.push({ name: msg.name, bytes: msg.bytes });
      } else if (msg.type === 'done') {
        finishOp();
        if (memoryFiles) {
          filesDeliverDecryptedBlobs(memoryFiles);
        } else {
          updateStatus('files.done.decrypt');
        }
        if (opts.doneLogKey) addLog(opts.doneLogKey, { count: memoryFiles ? memoryFiles.length : '?' });
        playSound('unlock');
        if (opts.onDone) opts.onDone();
      } else if (msg.type === 'cancelled') {
        finishOp();
        updateStatus('files.cancelled');
        addLog('log.msg.filesCancelled');
      } else if (msg.type === 'error') {
        finishOp();
        (opts.onError || function (m) { showError('status.unexpected', { msg: m }); })(msg.message);
      }
    };
    filesWorker.postMessage({
      op: 'decrypt', containerFile: opts.file, headerLength: opts.headerInfo.headerLength, chunkSizeMB: opts.headerInfo.chunkSizeMB,
      baseNonce: opts.headerInfo.baseNonce, cekBytes: opts.cekBytes, destDirHandle: opts.destDirHandle,
      trailerLen: opts.headerInfo.trailerLen || 0, authKey: opts.auth ? opts.auth.authKey : null, wrapIndex: opts.auth ? opts.auth.wrapIndex : -1
    });
  } catch (e) {
    // Same failure mode as filesStartEncrypt()'s postMessage — see the comment there.
    // `destDirHandle` here is a FileSystemDirectoryHandle, which is one more thing (besides
    // `containerFile`) that could fail to structured-clone into the worker.
    finishOp();
    showError('status.unexpected', { msg: (e && e.message) ? e.message : 'worker-start-failed' });
  }
}

// Offers decrypted-in-memory files as a normal browser download: a single file downloads
// directly under its own name; several files are bundled into one .zip (store method, no
// re-compression — Anigma's own compression, if any, was already undone) so the browser
// only has to allow one download instead of several at once (which many browsers block).
function filesDeliverDecryptedBlobs(files) {
  if (!files.length) { updateStatus('files.done.decrypt'); return; }
  if (files.length === 1) {
    downloadBlob(new Blob([files[0].bytes]), files[0].name.split('/').pop());
    updateStatus('files.done.decrypt');
    return;
  }
  const zipBlob = buildStoreZip(files);
  downloadBlob(zipBlob, 'anigma-decrypted.zip');
  updateStatus('files.done.decrypt.zip', { count: files.length });
}

function downloadBlob(blob, filename) {
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url; a.download = filename;
  document.body.appendChild(a); a.click(); document.body.removeChild(a);
  setTimeout(function () { URL.revokeObjectURL(url); }, 30000);
}

// ------------------------------------------------------------------ minimal ZIP (store method)
// A tiny, dependency-free ZIP writer used only for the "no folder-access API" decrypt
// fallback above. No compression (files are stored as-is — Anigma's own compression, if
// used, already ran before encryption), so this is just headers + a CRC32 per file.
const CRC32_TABLE = (function () {
  const t = new Uint32Array(256);
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) c = (c & 1) ? (0xEDB88320 ^ (c >>> 1)) : (c >>> 1);
    t[n] = c >>> 0;
  }
  return t;
})();
function crc32(bytes) {
  let c = 0xFFFFFFFF;
  for (let i = 0; i < bytes.length; i++) c = CRC32_TABLE[(c ^ bytes[i]) & 0xFF] ^ (c >>> 8);
  return (c ^ 0xFFFFFFFF) >>> 0;
}
function dosDateTime() {
  const d = new Date();
  const time = ((d.getHours() & 0x1F) << 11) | ((d.getMinutes() & 0x3F) << 5) | ((d.getSeconds() >> 1) & 0x1F);
  const date = (((d.getFullYear() - 1980) & 0x7F) << 9) | (((d.getMonth() + 1) & 0xF) << 5) | (d.getDate() & 0x1F);
  return { time: time & 0xFFFF, date: date & 0xFFFF };
}
function buildStoreZip(files) {
  const encoder = new TextEncoder();
  const UTF8_FLAG = 0x0800; // general-purpose bit 11: "file name and comment fields are UTF-8"
  const localParts = []; const centralParts = [];
  let offset = 0;
  const { time, date } = dosDateTime();
  files.forEach(function (f) {
    const nameBytes = encoder.encode(f.name.replace(/\\/g, '/'));
    const crc = crc32(f.bytes);
    const size = f.bytes.length;
    const localHeader = new Uint8Array(30 + nameBytes.length);
    const lv = new DataView(localHeader.buffer);
    lv.setUint32(0, 0x04034b50, true);
    lv.setUint16(4, 20, true); lv.setUint16(6, UTF8_FLAG, true); lv.setUint16(8, 0, true);
    lv.setUint16(10, time, true); lv.setUint16(12, date, true);
    lv.setUint32(14, crc, true); lv.setUint32(18, size, true); lv.setUint32(22, size, true);
    lv.setUint16(26, nameBytes.length, true); lv.setUint16(28, 0, true);
    localHeader.set(nameBytes, 30);
    localParts.push(localHeader, f.bytes);

    const centralHeader = new Uint8Array(46 + nameBytes.length);
    const cv = new DataView(centralHeader.buffer);
    cv.setUint32(0, 0x02014b50, true);
    cv.setUint16(4, 20, true); cv.setUint16(6, 20, true); cv.setUint16(8, UTF8_FLAG, true); cv.setUint16(10, 0, true);
    cv.setUint16(12, time, true); cv.setUint16(14, date, true);
    cv.setUint32(16, crc, true); cv.setUint32(20, size, true); cv.setUint32(24, size, true);
    cv.setUint16(28, nameBytes.length, true); cv.setUint16(30, 0, true); cv.setUint16(32, 0, true);
    cv.setUint16(34, 0, true); cv.setUint16(36, 0, true); cv.setUint32(38, 0, true);
    cv.setUint32(42, offset, true);
    centralHeader.set(nameBytes, 46);
    centralParts.push(centralHeader);

    offset += localHeader.length + f.bytes.length;
  });
  const centralStart = offset;
  let centralSize = 0;
  centralParts.forEach(function (p) { centralSize += p.length; });
  const end = new Uint8Array(22);
  const ev = new DataView(end.buffer);
  ev.setUint32(0, 0x06054b50, true);
  ev.setUint16(4, 0, true); ev.setUint16(6, 0, true);
  ev.setUint16(8, files.length, true); ev.setUint16(10, files.length, true);
  ev.setUint32(12, centralSize, true); ev.setUint32(16, centralStart, true);
  ev.setUint16(20, 0, true);
  return new Blob(localParts.concat(centralParts, [end]));
}

// ====================================================================================
// FILE INPUT WIRING (click, drag & drop)
// ====================================================================================
function wireFileInputs() {
  const filesInput = document.getElementById('filesInput');
  const folderInput = document.getElementById('folderInput');
  const dz = document.getElementById('filesDropzone');
  if (filesInput) filesInput.addEventListener('change', function (e) { filesAddEntries(Array.from(e.target.files || [])); filesInput.value = ''; });
  if (folderInput) folderInput.addEventListener('change', function (e) { filesAddEntries(Array.from(e.target.files || [])); folderInput.value = ''; });
  if (dz) {
    ['dragenter', 'dragover'].forEach(function (ev) { dz.addEventListener(ev, function (e) { e.preventDefault(); dz.classList.add('dragover'); }); });
    ['dragleave', 'drop'].forEach(function (ev) { dz.addEventListener(ev, function (e) { e.preventDefault(); dz.classList.remove('dragover'); }); });
    dz.addEventListener('drop', function (e) {
      if (e.dataTransfer && e.dataTransfer.files && e.dataTransfer.files.length) filesAddEntries(Array.from(e.dataTransfer.files));
    });
    dz.addEventListener('keydown', function (e) { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); filesInput.click(); } });
  }
  const decryptInput = document.getElementById('filesDecryptInput');
  if (decryptInput) decryptInput.addEventListener('change', function (e) { if (e.target.files && e.target.files[0]) filesHandleDecryptFile(e.target.files[0]); decryptInput.value = ''; });
}

// ====================================================================================
// PWA — service worker registration + update banner
// ====================================================================================
function setupServiceWorker() {
  if (!('serviceWorker' in navigator)) return;
  // Security/UX review #12: `controllerchange` fires the very FIRST time a service worker
  // ever takes control of an already-open page too — not only on a genuine version swap.
  // Without this distinction, the very first visit force-reloaded the page automatically,
  // directly contradicting the update banner's own text ("never applied automatically").
  // A real update means a controller already existed on this load and is being replaced;
  // capture that BEFORE registration can change it.
  const hadControllerAtLoad = !!navigator.serviceWorker.controller;
  navigator.serviceWorker.register('service-worker.js').then(function (reg) {
    function showUpdateBar(worker) {
      const bar = document.getElementById('updateBar');
      bar.classList.add('show');
      document.getElementById('updateReloadBtn').onclick = function () {
        worker.postMessage({ type: 'SKIP_WAITING' });
      };
    }
    if (reg.waiting) showUpdateBar(reg.waiting);
    reg.addEventListener('updatefound', function () {
      const nw = reg.installing;
      if (!nw) return;
      nw.addEventListener('statechange', function () {
        if (nw.state === 'installed' && navigator.serviceWorker.controller) showUpdateBar(nw);
      });
    });
  }).catch(function () { /* offline support degrades gracefully without a service worker */ });

  // If the service worker refused to install a cache because a fetched file's hash didn't
  // match what shipped with this version (see service-worker.js's INTEGRITY manifest), the
  // person is still running fine from the network — but should know their offline copy
  // wasn't updated, rather than silently keep an old (or find out much later that a new)
  // cache never took effect.
  navigator.serviceWorker.addEventListener('message', function (event) {
    if (event.data && event.data.type === 'INTEGRITY_FAILURE') {
      showError('status.sw.integrityFailure', { detail: event.data.detail || '' });
    }
  });

  let refreshed = false;
  navigator.serviceWorker.addEventListener('controllerchange', function () {
    if (refreshed) return;
    if (!hadControllerAtLoad) return; // first-ever install claiming control — nothing stale to refresh
    refreshed = true;
    window.location.reload();
  });
}

// ====================================================================================
// AUTO-LOCK — idle timeout + backgrounding. Only active while an identity is unlocked
// (armed on unlock/create/import, disarmed on lock/wipe). Backgrounding the tab (app
// switch, screen off) is treated the same as inactivity: the idle budget starts consuming
// immediately on visibilitychange to hidden, since that's exactly the moment an unattended
// unlocked identity is most exposed on a phone.
// ====================================================================================
let autolockTimer = null;
let autolockMins = 0; // 0 = disabled
const AUTOLOCK_ACTIVITY_EVENTS = ['pointerdown', 'keydown', 'touchstart', 'scroll'];

// Default is 5 minutes (secure by default); an explicit "Never" is stored as '0' and honored.
const AUTOLOCK_DEFAULT_MINS = 5;
function autolockGetStoredMins() {
  try {
    const raw = localStorage.getItem('anigma_autolock_mins');
    if (raw === null) return AUTOLOCK_DEFAULT_MINS;
    const n = parseInt(raw, 10);
    return Number.isFinite(n) && n >= 0 ? n : AUTOLOCK_DEFAULT_MINS;
  } catch (e) { return AUTOLOCK_DEFAULT_MINS; }
}
function autolockReset() {
  if (autolockTimer) clearTimeout(autolockTimer);
  autolockTimer = null;
  if (!idPrivateKey || autolockMins <= 0) return;
  autolockTimer = setTimeout(autolockTrigger, autolockMins * 60000);
}
function autolockTrigger() {
  if (!idPrivateKey) return;
  idLockIdentity();
  updateStatus('status.id.autoLocked', null, true);
  addLog('log.msg.idAutoLocked');
}
function autolockActivity() { if (idPrivateKey) autolockReset(); }
// Backgrounding must NOT restart the idle budget (the old code did, and background timers are
// throttled anyway). Remember when the page was hidden and compare REAL elapsed time on return.
let autolockHiddenAt = 0;
function autolockVisibilityChange() {
  if (!idPrivateKey) return;
  if (document.visibilityState === 'hidden') { autolockHiddenAt = Date.now(); return; }
  const hiddenFor = autolockHiddenAt ? Date.now() - autolockHiddenAt : 0;
  autolockHiddenAt = 0;
  if (autolockMins > 0 && hiddenFor >= autolockMins * 60000) { autolockTrigger(); return; }
  autolockReset();
}
function autolockArm() {
  autolockMins = autolockGetStoredMins();
  AUTOLOCK_ACTIVITY_EVENTS.forEach(function (evt) { document.addEventListener(evt, autolockActivity, { passive: true }); });
  document.addEventListener('visibilitychange', autolockVisibilityChange);
  autolockReset();
}
function autolockDisarm() {
  if (autolockTimer) clearTimeout(autolockTimer);
  autolockTimer = null;
  AUTOLOCK_ACTIVITY_EVENTS.forEach(function (evt) { document.removeEventListener(evt, autolockActivity); });
  document.removeEventListener('visibilitychange', autolockVisibilityChange);
}
function autolockSetMinutes(mins) {
  autolockMins = mins;
  try { localStorage.setItem('anigma_autolock_mins', String(mins)); } catch (e) {}
  if (idPrivateKey) autolockReset();
}

// ====================================================================================
// BACKUP REMINDER — a dismissible-for-this-session nudge if an identity has gone a week
// without ever being exported. Losing the passphrase with no backup means the identity is
// gone for good (there is deliberately no recovery path — see identity.pin.hint), so this
// is the one piece of nagging the app does.
// ====================================================================================
const BACKUP_REMIND_AFTER_MS = 7 * 24 * 60 * 60 * 1000;
function idNoteIdentityCreated() {
  try {
    localStorage.setItem('anigma_identity_created_ts', String(Date.now()));
    localStorage.removeItem('anigma_last_backup_ts');
  } catch (e) {}
}
function idNoteBackupDone() {
  try { localStorage.setItem('anigma_last_backup_ts', String(Date.now())); } catch (e) {}
  hideBackupBanner();
}
function idBackupReminderCheck() {
  if (!idPrivateKey) { hideBackupBanner(); return; }
  let createdTs = 0, backupTs = 0, dismissedTs = 0;
  try {
    createdTs = parseInt(localStorage.getItem('anigma_identity_created_ts'), 10) || 0;
    backupTs = parseInt(localStorage.getItem('anigma_last_backup_ts'), 10) || 0;
    dismissedTs = parseInt(sessionStorage.getItem('anigma_backup_banner_dismissed') || '0', 10);
  } catch (e) { return; }
  const overdue = createdTs > 0 && backupTs === 0 && (Date.now() - createdTs) > BACKUP_REMIND_AFTER_MS;
  if (overdue && !dismissedTs) showBackupBanner(); else hideBackupBanner();
}
function showBackupBanner() { const el = document.getElementById('backupReminderBanner'); if (el) el.style.display = 'flex'; }
function hideBackupBanner() { const el = document.getElementById('backupReminderBanner'); if (el) el.style.display = 'none'; }
function dismissBackupBanner() {
  playSound('click');
  try { sessionStorage.setItem('anigma_backup_banner_dismissed', String(Date.now())); } catch (e) {}
  hideBackupBanner();
}

// ====================================================================================
// FINGERPRINT COMPARE — a manual side-by-side diff for out-of-band verification (in
// person, on a call, over a channel you already trust) without needing a camera/QR
// decoder library. Paste the other side's fingerprint text; matching 4-hex-digit groups
// are highlighted green, mismatched ones red, so a single wrong group is easy to spot
// instead of eyeballing two long hex strings against each other.
// ====================================================================================
function fpToggleCompare() {
  playSound('click');
  const box = document.getElementById('fpCompareBox');
  box.style.display = (box.style.display === 'none' || !box.style.display) ? 'block' : 'none';
}
function fpNormalizeHex(s) { return (s || '').toUpperCase().replace(/[^0-9A-F]/g, ''); }
function fpDoCompare() {
  playSound('click');
  const resultEl = document.getElementById('fpCompareResult');
  const r = fpBuildCompare(idFingerprint, document.getElementById('fpCompareInput').value);
  if (!r.hasInput) { resultEl.textContent = ''; return; }
  resultEl.innerHTML = r.html + '<br><b class="' + (r.allMatch ? 'cmp-ok' : 'cmp-bad') + '">' + escapeHtml(r.allMatch ? t('fp.compare.match') : t('fp.compare.mismatch')) + '</b>';
}

// ====================================================================================
// SIMPLE / ADVANCED MODE
// Purely a presentation layer: it decides which controls are visible (CSS: .adv-only /
// .simple-only on <html data-mode>) and which wording is used (t() picks 'key@simple' in Simple
// mode). It never changes crypto.js, container.js, worker.js or any stored/wire format.
// ====================================================================================
function uiGetStoredMode() {
  try { return localStorage.getItem('anigma_mode') === 'advanced' ? 'advanced' : 'simple'; } catch (e) { return 'simple'; }
}
function uiApplyModeAttr(mode) {
  uiMode = (mode === 'advanced') ? 'advanced' : 'simple';
  document.documentElement.setAttribute('data-mode', uiMode);
  const sel = document.getElementById('menuModeSelect');
  if (sel) sel.value = uiMode;
}

// Advanced-only choices are held in the DOM/state, invisible in Simple mode. If they were left as the
// user last set them, a stale pasted claimed-sender key or an X25519 curve pick could silently steer
// what Simple mode does. So entering Simple mode puts every one of them back to its default. Recipient
// mode itself — paste / contacts / self — is visible in both modes now, so it is just reset to a sane
// default here rather than hidden state being cleared. "Send anonymously" is likewise visible in both
// modes, but it still gets reset to off on the way back to Simple: it is a real behavior change (who can
// tell you sent it), not just a layout detail, so a value left over from an Advanced session should never
// carry into a Simple-mode send without the user consciously choosing it again.
function resetAdvancedState() {
  secSetRecipientMode('paste', true);
  secSetSenderMode('auto', true);
  filesSetRecipientMode('paste', true);
  filesSetSenderMode('auto', true);
  secForceEncrypt = false;
  const anon = document.getElementById('secAnonToggle');
  if (anon) { anon.classList.remove('on'); anon.setAttribute('aria-checked', 'false'); }
  secSyncAnonUI();
  const round = document.getElementById('fileRoundSizeToggle');
  if (round) round.classList.remove('on');
  const setVal = function (id, v) { const el = document.getElementById(id); if (el) el.value = v; };
  setVal('idCurveSelect', 'p256'); setVal('fileCompressionSelect', 'none');
  setVal('fileChunkSizeRange', '4');
  ['secPastePubKey', 'fileRecipPasteKey', 'secSenderPasteKey', 'fileSenderPasteKey'].forEach(function (id) { setVal(id, ''); });
  secPastedRecipientRaw = null; filesPastedRecipientRaw = null; filesClaimedSenderRaw = null;
  const b1 = document.getElementById('secPasteFpBox'), b2 = document.getElementById('fileRecipPasteFpBox');
  if (b1) b1.style.display = 'none'; if (b2) b2.style.display = 'none';
  if (document.getElementById('fileChunkSizeLabelText')) filesUpdateChunkLabel();
}

function setMode(mode) {
  playSound('click');
  if (mode === uiMode) return;
  uiApplyModeAttr(mode);
  try { localStorage.setItem('anigma_mode', uiMode); } catch (e) {}
  if (uiMode === 'simple') resetAdvancedState();
  // Re-run the language pass: it re-applies every data-i18n string (now in the new mode's wording)
  // and re-renders the pieces built in JS (contact cards, help, smart button, tooltips, ...).
  applyLanguage(currentLang);
  idRenderContacts(); idRenderContactSelect(); idRenderClaimedSenderSelect(); idRenderFileContactCheckboxes();
  updateStatus(uiMode === 'simple' ? 'status.mode.simple' : 'status.mode.advanced');
  closeMenu();
}

// "More options" panels remember whether they were left open (all share one flag).
function initMoreOptions() {
  let open = false;
  try { open = localStorage.getItem('anigma_more_open') === '1'; } catch (e) {}
  const panels = Array.from(document.querySelectorAll('details.more-options'));
  panels.forEach(function (d) {
    d.open = open;
    d.addEventListener('toggle', function () {
      try { localStorage.setItem('anigma_more_open', d.open ? '1' : '0'); } catch (e) {}
      panels.forEach(function (o) { if (o.open !== d.open) o.open = d.open; });
    });
  });
}

// ====================================================================================
// TOOLTIPS — a small "?" next to each non-obvious control, one short sentence on tap/hover/focus.
// Markup: <button class="tip-btn" data-tip="tip.someKey">?</button>. One shared popover element.
// ====================================================================================
let tipActive = null, tipPinned = false;
function tipHide() {
  const pop = document.getElementById('tipPop');
  if (pop) pop.hidden = true;
  if (tipActive) { tipActive.setAttribute('aria-expanded', 'false'); tipActive.removeAttribute('aria-describedby'); }
  tipActive = null; tipPinned = false;
}
function tipShow(btn, pinned) {
  const pop = document.getElementById('tipPop');
  if (!pop) return;
  if (tipActive && tipActive !== btn) { tipActive.setAttribute('aria-expanded', 'false'); tipActive.removeAttribute('aria-describedby'); }
  tipActive = btn; tipPinned = !!pinned;
  pop.textContent = t(btn.getAttribute('data-tip'));
  pop.hidden = false;
  btn.setAttribute('aria-expanded', 'true'); btn.setAttribute('aria-describedby', 'tipPop');
  const r = btn.getBoundingClientRect();
  const w = pop.offsetWidth, h = pop.offsetHeight;
  const vw = document.documentElement.clientWidth, vh = document.documentElement.clientHeight;
  let left = r.left + r.width / 2 - w / 2;
  left = Math.max(8, Math.min(left, vw - w - 8));
  let top = r.bottom + 8;
  if (top + h > vh - 8) top = Math.max(8, r.top - h - 8);
  pop.style.left = left + 'px'; pop.style.top = top + 'px';
}
function refreshTips() {
  tipHide();
  document.querySelectorAll('.tip-btn').forEach(function (b) { b.setAttribute('aria-label', t(b.getAttribute('data-tip'))); });
}
function initTips() {
  const hoverCapable = window.matchMedia && window.matchMedia('(hover: hover) and (pointer: fine)').matches;
  const tipOf = function (ev) { return ev.target && ev.target.closest ? ev.target.closest('.tip-btn') : null; };
  // Capture phase + preventDefault: a "?" inside a <label> or <summary> must not also activate it.
  document.addEventListener('click', function (ev) {
    const b = tipOf(ev);
    if (b) {
      ev.preventDefault(); ev.stopPropagation();
      if (tipActive === b && tipPinned) tipHide(); else tipShow(b, true);
      return;
    }
    tipHide();
  }, true);
  if (hoverCapable) {
    document.addEventListener('mouseover', function (ev) { const b = tipOf(ev); if (b && !tipPinned) tipShow(b, false); });
    document.addEventListener('mouseout', function (ev) { const b = tipOf(ev); if (b && !tipPinned) tipHide(); });
  }
  document.addEventListener('focusin', function (ev) { const b = tipOf(ev); if (b && !tipPinned) tipShow(b, false); });
  document.addEventListener('focusout', function (ev) { if (tipOf(ev) && !tipPinned) tipHide(); });
  document.addEventListener('keydown', function (ev) { if (ev.key === 'Escape') tipHide(); });
  window.addEventListener('scroll', tipHide, true);
  window.addEventListener('resize', tipHide);
  refreshTips();
}

// ====================================================================================
// FIRST-RUN WELCOME — three short steps: (1) choose a password (2) here's your ID (3) go.
// Shown once, only when this device has no identity yet. Closable at any time; nothing in it is
// required reading, and everything it does is also reachable from the normal tabs.
// ====================================================================================
let onboardStep = 1;
function localizeDigits(n) {
  const s = String(n);
  return currentLang === 'fa' ? s.replace(/[0-9]/g, function (d) { return '\u06F0\u06F1\u06F2\u06F3\u06F4\u06F5\u06F6\u06F7\u06F8\u06F9'.charAt(+d); }) : s;
}
function onboardMarkSeen() { try { localStorage.setItem('anigma_onboarded', '1'); } catch (e) {} }
function onboardMaybeOpen() {
  let seen = false, hasIdentity = false;
  try { seen = localStorage.getItem('anigma_onboarded') === '1'; hasIdentity = !!localStorage.getItem('anigma_identity_v1'); } catch (e) { return; }
  if (seen || hasIdentity) return;
  onboardShowStep(1);
  openModal('onboardModal');
  const pw = document.getElementById('onboardPw'); if (pw) setTimeout(function () { pw.focus(); }, 50);
}
function onboardRefreshLabels() {
  const label = document.getElementById('onboardStepLabel');
  if (label) label.textContent = t('onboard.step', { n: localizeDigits(onboardStep) });
}
function onboardShowStep(n) {
  onboardStep = n;
  [1, 2, 3].forEach(function (i) { document.getElementById('onboardStep' + i).style.display = (i === n) ? 'block' : 'none'; });
  document.querySelectorAll('#onboardDots .dot').forEach(function (d, i) { d.classList.toggle('active', i === n - 1); });
  onboardRefreshLabels();
  if (n === 2) {
    const box = document.getElementById('onboardQr');
    box.textContent = '';
    try { AnigmaQR.render(box, idPublicKeyB64, { width: 180, correctLevel: 'L' }); } catch (e) { /* the copy/share buttons below still work */ }
    document.getElementById('onboardShareBtn').style.display = canWebShare() ? '' : 'none';
  }
}
function onboardShowError(key) {
  const el = document.getElementById('onboardError');
  el.textContent = key ? t(key) : ''; el.style.display = key ? 'block' : 'none';
}
async function onboardCreate() {
  playSound('click');
  const pw = document.getElementById('onboardPw').value, pw2 = document.getElementById('onboardPw2').value;
  if (pw.length < AnigmaCrypto.ID_PASSPHRASE_MIN_LENGTH) { onboardShowError('status.id.pinShort'); return; }
  if (AnigmaCrypto.estimatePasswordStrength(pw).className === 'weak') { onboardShowError('status.id.pinWeak'); return; }
  // Typing it twice matters here more than in most apps: there is no reset, so a typo would lock the
  // person out of their own ID for good.
  if (pw !== pw2) { onboardShowError('onboard.err.mismatch'); return; }
  onboardShowError(null);
  // Reuse the one real creation path (same KDF, same storage format) rather than a copy of it.
  document.getElementById('idPinInput').value = pw;
  await idCreateIdentity();
  if (!idPrivateKey) { onboardShowError(lastStatus.key); return; }
  document.getElementById('onboardPw').value = ''; document.getElementById('onboardPw2').value = '';
  idCheckPinStrength('onboardPw', 'onboardPwStrengthFill', 'onboardPwStrengthText');
  onboardShowStep(2);
}
function onboardClose() { document.getElementById('onboardModal').classList.remove('open'); onboardMarkSeen(); }
function onboardFinish() { playSound('click'); onboardClose(); switchMainTab('contacts'); }
async function onboardCopyId() {
  playSound('click');
  const ok = await copyToClipboard(idPublicKeyB64);
  updateStatus(ok ? 'status.id.pubCopied' : 'status.copy.failed', null, !ok);
}
async function onboardShareId() {
  playSound('click');
  const r = await shareTextOrCopy(idPublicKeyB64, t('identity.shareTitle'));
  if (r === 'copied') updateStatus('status.share.fallbackCopied');
}

// ====================================================================================
// QR SCANNING (add a contact by pointing the camera at their QR code)
// Decoding uses the browser's own BarcodeDetector where it exists. There is no bundled QR-decoding
// library (and none can be fetched offline), so on browsers without BarcodeDetector the Scan button is
// hidden and the paste fallback is shown open instead — see applyScanSupport().
// ====================================================================================
let scanSupported = false, scanStream = null, scanToken = 0;
async function scanDetectSupport() {
  try {
    if (!('BarcodeDetector' in window) || !navigator.mediaDevices || !navigator.mediaDevices.getUserMedia) return false;
    const formats = await window.BarcodeDetector.getSupportedFormats();
    return formats.indexOf('qr_code') !== -1;
  } catch (e) { return false; }
}
function applyScanSupport() {
  document.getElementById('scanQrBtn').style.display = scanSupported ? '' : 'none';
  document.getElementById('scanUnsupportedNote').style.display = scanSupported ? 'none' : 'block';
  if (!scanSupported) document.getElementById('contactPasteDetails').open = true;
}
function scanSetMsg(key) { document.getElementById('scanMsg').textContent = key ? t(key) : ''; }
async function scanStart() {
  playSound('click');
  if (!idPrivateKey) { updateStatus('status.contact.needUnlock', null, true); return; }
  scanSetMsg(null);
  openModal('scanModal');
  const myToken = ++scanToken;
  try {
    scanStream = await navigator.mediaDevices.getUserMedia({ video: { facingMode: { ideal: 'environment' } }, audio: false });
  } catch (e) {
    const name = e && e.name;
    scanSetMsg(name === 'NotAllowedError' || name === 'SecurityError' ? 'scan.err.denied' : (name === 'NotFoundError' || name === 'OverconstrainedError') ? 'scan.err.noCamera' : 'scan.err.generic');
    return;
  }
  if (myToken !== scanToken) { scanStopTracks(); return; } // cancelled while the permission prompt was up
  const video = document.getElementById('scanVideo');
  video.srcObject = scanStream;
  try { await video.play(); } catch (e) { /* autoplay quirks: the loop below just waits for frames */ }
  let detector;
  try { detector = new window.BarcodeDetector({ formats: ['qr_code'] }); } catch (e) { scanSetMsg('scan.err.generic'); return; }
  while (myToken === scanToken && scanStream) {
    try {
      if (video.readyState >= 2) {
        const codes = await detector.detect(video);
        if (codes && codes.length && codes[0].rawValue && await scanHandleValue(String(codes[0].rawValue))) return;
      }
    } catch (e) { /* a dropped frame is not an error */ }
    await new Promise(function (r) { setTimeout(r, 250); });
  }
}
function scanStopTracks() {
  if (scanStream) { scanStream.getTracks().forEach(function (tr) { try { tr.stop(); } catch (e) {} }); }
  scanStream = null;
  const video = document.getElementById('scanVideo'); if (video) video.srcObject = null;
}
function scanStop() { scanToken++; scanStopTracks(); document.getElementById('scanModal').classList.remove('open'); }
// Returns true when the code was accepted (and the scanner closed).
async function scanHandleValue(raw) {
  const val = raw.trim();
  try { await AnigmaCrypto.importPublicKeyRaw(AnigmaCrypto.b64ToBuf(val)); }
  catch (e) { scanSetMsg('scan.err.notId'); return false; }
  if (val === idPublicKeyB64) { scanSetMsg('scan.err.self'); return false; }
  scanStop();
  const ta = document.getElementById('idNewContactPubKey'), alias = document.getElementById('idNewContactAlias');
  ta.value = val;
  document.getElementById('idContactAddedBanner').style.display = 'none';
  playSound('unlock');
  if (alias.value.trim()) { await idAddContact(); return true; }
  document.getElementById('idGotIdBanner').style.display = 'flex';
  alias.focus();
  return true;
}

// ====================================================================================
// "How do I make sure this is really them?" — the verification-code check (Simple-mode home of the
// same fingerprint comparison that Advanced mode also offers inline under My key).
// ====================================================================================
function fpBuildCompare(targetFp, otherText) {
  const mine = fpNormalizeHex(targetFp);
  const other = fpNormalizeHex(otherText);
  if (!other) return { hasInput: false, html: '', allMatch: false };
  const groupCount = Math.ceil(Math.max(mine.length, other.length) / 4);
  let html = '';
  let allMatch = mine.length === other.length && mine.length > 0;
  for (let i = 0; i < groupCount; i++) {
    const a = mine.slice(i * 4, i * 4 + 4);
    const b = other.slice(i * 4, i * 4 + 4);
    const match = a.length === 4 && a === b;
    if (!match) allMatch = false;
    html += '<span class="' + (match ? 'cmp-ok' : 'cmp-bad') + '" style="margin-inline-end:8px;">' + escapeHtml(b || '····') + '</span>';
  }
  return { hasInput: true, html: html, allMatch: allMatch };
}
let verifyMarkId = null;
function fpOpenVerify(contactId) {
  playSound('click');
  if (!idPrivateKey) { updateStatus('status.contact.needUnlock', null, true); return; }
  document.getElementById('verifyMyCode').textContent = idFingerprint;
  const sel = document.getElementById('verifyContactSelect');
  sel.textContent = '';
  idContacts.forEach(function (c) { const o = document.createElement('option'); o.value = c.id; o.textContent = c.alias; sel.appendChild(o); });
  if (contactId && idContacts.some(function (c) { return c.id === contactId; })) sel.value = contactId;
  const has = idContacts.length > 0;
  document.getElementById('verifyForm').style.display = has ? 'block' : 'none';
  document.getElementById('verifyNoContacts').style.display = has ? 'none' : 'block';
  document.getElementById('verifyInput').value = '';
  document.getElementById('verifyResult').style.display = 'none';
  document.getElementById('verifyMarkBtn').style.display = 'none';
  verifyMarkId = null;
  openModal('verifyModal');
}
function fpVerifyCompare() {
  playSound('click');
  const c = idContacts.find(function (x) { return x.id === document.getElementById('verifyContactSelect').value; });
  const resEl = document.getElementById('verifyResult'), markBtn = document.getElementById('verifyMarkBtn');
  markBtn.style.display = 'none'; verifyMarkId = null;
  if (!c) return;
  const r = fpBuildCompare(c.fp, document.getElementById('verifyInput').value);
  if (!r.hasInput) { resEl.style.display = 'none'; return; }
  resEl.style.display = 'block';
  resEl.innerHTML = '<div class="code-display">' + r.html + '</div><div class="vr-msg ' + (r.allMatch ? 'vr-ok' : 'vr-bad') + '">' +
    escapeHtml(r.allMatch ? t('verify.match', { name: c.alias }) : t('verify.mismatch')) + '</div>';
  if (r.allMatch && !c.verified) {
    verifyMarkId = c.id;
    markBtn.textContent = t('verify.markVerified', { name: c.alias });
    markBtn.style.display = 'inline-flex';
  }
}
async function fpVerifyMark() {
  if (!verifyMarkId) return;
  const c = idContacts.find(function (x) { return x.id === verifyMarkId; });
  if (!c) return;
  playSound('click');
  c.verified = true;
  await idSaveContacts();
  idRenderContacts();
  updateStatus('status.contact.verified', { alias: c.alias });
  document.getElementById('verifyMarkBtn').style.display = 'none';
  verifyMarkId = null;
}

// ====================================================================================
// INLINE HANDLER BINDINGS — generated once from index.html's former onclick/onchange/
// oninput attributes so a strict Content-Security-Policy (script-src 'self', no
// 'unsafe-inline') can be enforced. Behavior is identical to the inline attributes that
// used to be here; only where the code lives changed. 'this' inside each handler still
// refers to the bound element, exactly as it did as an inline attribute, because these
// are regular function expressions (not arrow functions).
// ====================================================================================
function bindInlineHandlers() {
  let el;
  el = document.getElementById('menuOverlay'); if (el) el.addEventListener('click', function (event) { closeMenu() });
  el = document.getElementById('jsb1'); if (el) el.addEventListener('click', function (event) { closeMenu() });
  el = document.getElementById('menuThemeSelect'); if (el) el.addEventListener('change', function (event) { changeTheme(this.value) });
  el = document.getElementById('jsb2'); if (el) el.addEventListener('click', function (event) { toggleAudio() });
  el = document.getElementById('jsb3'); if (el) el.addEventListener('click', function (event) { openHelp() });
  el = document.getElementById('jsb4'); if (el) el.addEventListener('click', function (event) { toggleMenu() });
  el = document.getElementById('jsb5'); if (el) el.addEventListener('click', function (event) { toggleLanguage() });
  el = document.getElementById('jsb6'); if (el) el.addEventListener('click', function (event) { openHelp() });
  el = document.getElementById('tabMyKeyBtn'); if (el) el.addEventListener('click', function (event) { switchMainTab('mykey') });
  el = document.getElementById('tabSecureBtn'); if (el) el.addEventListener('click', function (event) { switchMainTab('secure') });
  el = document.getElementById('tabFilesBtn'); if (el) el.addEventListener('click', function (event) { switchMainTab('files') });
  el = document.getElementById('tabContactsBtn'); if (el) el.addEventListener('click', function (event) { switchMainTab('contacts') });
  el = document.getElementById('idPinInput'); if (el) el.addEventListener('input', function (event) { idCheckPinStrength() });
  el = document.getElementById('jsb7'); if (el) el.addEventListener('click', function (event) { idCreateIdentity() });
  el = document.getElementById('jsb8'); if (el) el.addEventListener('click', function (event) { idUnlockIdentity() });
  el = document.getElementById('jsb9'); if (el) el.addEventListener('click', function (event) { dismissBackupBanner() });
  el = document.getElementById('jsb10'); if (el) el.addEventListener('click', function (event) { fpToggleCompare() });
  el = document.getElementById('jsb11'); if (el) el.addEventListener('click', function (event) { fpDoCompare() });
  el = document.getElementById('jsb12'); if (el) el.addEventListener('click', function (event) { idCopyPublicKey() });
  el = document.getElementById('jsb13'); if (el) el.addEventListener('click', function (event) { idShowMyQR() });
  el = document.getElementById('jsb14'); if (el) el.addEventListener('click', function (event) { idLockIdentity() });
  el = document.getElementById('jsb15'); if (el) el.addEventListener('click', function (event) { idExportIdentity() });
  el = document.getElementById('jsb16'); if (el) el.addEventListener('click', function (event) { idImportIdentity() });
  el = document.getElementById('jsb17'); if (el) el.addEventListener('click', function (event) { idEmergencyWipe() });
  el = document.getElementById('jsb18'); if (el) el.addEventListener('click', function (event) { idDeleteAllData() });
  el = document.getElementById('jsb19'); if (el) el.addEventListener('click', function (event) { idAddContact() });
  el = document.getElementById('secRecipContactBtn'); if (el) el.addEventListener('click', function (event) { secSetRecipientMode('contact') });
  el = document.getElementById('secRecipPasteBtn'); if (el) el.addEventListener('click', function (event) { secSetRecipientMode('paste') });
  el = document.getElementById('secPastePubKey'); if (el) el.addEventListener('input', function (event) { secCheckPastedRecipient() });
  el = document.getElementById('jsb20'); if (el) el.addEventListener('click', function (event) { secSaveAsContact() });
  el = document.getElementById('secAnonToggle'); if (el) el.addEventListener('click', function (event) { secToggleAnonymous() });
  el = document.getElementById('secSenderContactBtn'); if (el) el.addEventListener('click', function (event) { secSetSenderMode('contact') });
  el = document.getElementById('secSenderPasteBtn'); if (el) el.addEventListener('click', function (event) { secSetSenderMode('paste') });
  el = document.getElementById('secSenderNoneBtn'); if (el) el.addEventListener('click', function (event) { secSetSenderMode('none') });
  el = document.getElementById('secSmartBtn'); if (el) el.addEventListener('click', function (event) { secSmartAction() });
  el = document.getElementById('secureInput'); if (el) el.addEventListener('input', function (event) { secOnInput() });
  el = document.getElementById('idContactSelect'); if (el) el.addEventListener('change', function () { pipeInvalidate(); });
  // Key/ID paste boxes grow with their content instead of clipping it or showing a scrollbar.
  document.addEventListener('input', function (event) {
    const ta = event.target;
    if (ta && ta.tagName === 'TEXTAREA' && ta.classList.contains('ta-compact')) taAutoGrow(ta);
  });
  el = document.getElementById('secForceEncBtn'); if (el) el.addEventListener('click', function (event) { playSound('click'); secForceEncrypt = true; secUpdateSmartUI(); });
  el = document.getElementById('secSenderAutoBtn'); if (el) el.addEventListener('click', function (event) { secSetSenderMode('auto') });
  el = document.getElementById('secShareBtn'); if (el) el.addEventListener('click', function (event) { secShareOutput() });
  el = document.getElementById('secFallbackRetryBtn'); if (el) el.addEventListener('click', function (event) { secFallbackRetry() });
  el = document.getElementById('secAddContactBtn'); if (el) el.addEventListener('click', function (event) { switchMainTab('contacts') });
  el = document.getElementById('jsb23'); if (el) el.addEventListener('click', function (event) { secCopyOutput() });
  el = document.getElementById('jsb24'); if (el) el.addEventListener('click', function (event) { showQRCodeModal() });
  el = document.getElementById('filesDropzone'); if (el) el.addEventListener('click', function (event) { document.getElementById('filesInput').click() });
  el = document.getElementById('jsb25'); if (el) el.addEventListener('click', function (event) { document.getElementById('filesInput').click() });
  el = document.getElementById('jsb26'); if (el) el.addEventListener('click', function (event) { document.getElementById('folderInput').click() });
  el = document.getElementById('jsb27'); if (el) el.addEventListener('click', function (event) { filesClearSelection() });
  el = document.getElementById('fileRecipContactsBtn'); if (el) el.addEventListener('click', function (event) { filesSetRecipientMode('contacts') });
  el = document.getElementById('fileRecipPasteBtn'); if (el) el.addEventListener('click', function (event) { filesSetRecipientMode('paste') });
  el = document.getElementById('fileRecipPasteKey'); if (el) el.addEventListener('input', function (event) { filesCheckPastedRecipient() });
  el = document.getElementById('fileChunkSizeRange'); if (el) el.addEventListener('input', function (event) { filesUpdateChunkLabel() });
  el = document.getElementById('fileRoundSizeToggle'); if (el) el.addEventListener('click', function (event) { this.classList.toggle('on') });
  el = document.getElementById('fileEncryptBtn'); if (el) el.addEventListener('click', function (event) { filesStartEncrypt() });
  el = document.getElementById('jsb28'); if (el) el.addEventListener('click', function (event) { filesCancelOperation() });
  el = document.getElementById('fileSenderContactBtn'); if (el) el.addEventListener('click', function (event) { filesSetSenderMode('contact') });
  el = document.getElementById('fileSenderPasteBtn'); if (el) el.addEventListener('click', function (event) { filesSetSenderMode('paste') });
  el = document.getElementById('fileSenderPasteKey'); if (el) el.addEventListener('input', function (event) { filesCheckPastedSender() });
  el = document.getElementById('filesDecryptTrigger'); if (el) el.addEventListener('click', function (event) { document.getElementById('filesDecryptInput').click() });
  el = document.getElementById('jsb29'); if (el) el.addEventListener('click', function (event) { toggleLogStatus() });
  el = document.getElementById('jsb30'); if (el) el.addEventListener('click', function (event) { clearLogs() });
  el = document.getElementById('jsb31'); if (el) el.addEventListener('click', function (event) { closeModal('helpModal') });
  el = document.getElementById('jsb32'); if (el) el.addEventListener('click', function (event) { closeModal('qrModal') });
  el = document.getElementById('jsb33'); if (el) el.addEventListener('click', function (event) { filesConfirmDecrypt() });
  el = document.getElementById('jsb34'); if (el) el.addEventListener('click', function (event) { closeModal('filesManifestModal') });

  // ---- added with the Simple/Advanced UX pass ----
  el = document.getElementById('menuModeSelect'); if (el) el.addEventListener('change', function (event) { setMode(this.value) });
  el = document.getElementById('modeFooterBtn'); if (el) el.addEventListener('click', function (event) { setMode(uiMode === 'simple' ? 'advanced' : 'simple') });
  el = document.getElementById('idShareBtn'); if (el) el.addEventListener('click', function (event) { idShareMyId() });
  el = document.getElementById('idStartOverBtn'); if (el) el.addEventListener('click', function (event) { idCreateIdentity() });
  el = document.getElementById('scanQrBtn'); if (el) el.addEventListener('click', function (event) { scanStart() });
  el = document.getElementById('scanCancelBtn'); if (el) el.addEventListener('click', function (event) { playSound('click'); scanStop() });
  el = document.getElementById('showMyQrBtn'); if (el) el.addEventListener('click', function (event) { idShowMyQR() });
  el = document.getElementById('idHowVerifyBtn'); if (el) el.addEventListener('click', function (event) { fpOpenVerify(lastAddedContactId) });
  el = document.getElementById('verifyCompareBtn'); if (el) el.addEventListener('click', function (event) { fpVerifyCompare() });
  el = document.getElementById('verifyInput'); if (el) el.addEventListener('keydown', function (event) { if (event.key === 'Enter') fpVerifyCompare() });
  el = document.getElementById('verifyMarkBtn'); if (el) el.addEventListener('click', function (event) { fpVerifyMark() });
  el = document.getElementById('verifyCloseBtn'); if (el) el.addEventListener('click', function (event) { closeModal('verifyModal') });
  el = document.getElementById('fileSenderAutoBtn'); if (el) el.addEventListener('click', function (event) { filesSetSenderMode('auto') });
  el = document.getElementById('fileFallbackRetryBtn'); if (el) el.addEventListener('click', function (event) { filesFallbackRetry() });
  el = document.getElementById('onboardPw'); if (el) el.addEventListener('input', function (event) { idCheckPinStrength('onboardPw', 'onboardPwStrengthFill', 'onboardPwStrengthText') });
  el = document.getElementById('onboardPw2'); if (el) el.addEventListener('keydown', function (event) { if (event.key === 'Enter') onboardCreate() });
  el = document.getElementById('onboardNext1'); if (el) el.addEventListener('click', function (event) { onboardCreate() });
  el = document.getElementById('onboardSkip1'); if (el) el.addEventListener('click', function (event) { playSound('click'); onboardClose() });
  el = document.getElementById('onboardNext2'); if (el) el.addEventListener('click', function (event) { playSound('click'); onboardShowStep(3) });
  el = document.getElementById('onboardSkip2'); if (el) el.addEventListener('click', function (event) { playSound('click'); onboardShowStep(3) });
  el = document.getElementById('onboardDone'); if (el) el.addEventListener('click', function (event) { onboardFinish() });
  el = document.getElementById('onboardCopyBtn'); if (el) el.addEventListener('click', function (event) { onboardCopyId() });
  el = document.getElementById('onboardShareBtn'); if (el) el.addEventListener('click', function (event) { onboardShareId() });
}

// ====================================================================================
// STARTUP
// ====================================================================================
(function init() {
  applyIcons(document);
  wireFileInputs();
  bindInlineHandlers();

  let storedLang = null, storedTheme = null, storedSound = null;
  try {
    storedLang = localStorage.getItem('anigma_lang');
    storedTheme = localStorage.getItem('anigma_theme');
    storedSound = localStorage.getItem('anigma_sound');
  } catch (e) { /* private mode: fall back to defaults */ }

  // Mode first, so the very first render already uses the right wording. First-time users get Simple.
  uiApplyModeAttr(uiGetStoredMode());

  if (storedSound === '0') audioEnabled = false;
  const theme = (storedTheme === 'light' || storedTheme === 'dark') ? storedTheme : 'dark';
  document.documentElement.setAttribute('data-theme', theme);
  document.getElementById('menuThemeSelect').value = theme;

  applyLanguage(storedLang === 'fa' ? 'fa' : 'en');
  filesUpdateChunkLabel();
  idRefreshView();
  if (unlockRemainingCooldownMs() > 0) unlockCountdownStart(); // a reload mid-cooldown must not look like a free retry
  initTips();
  initMoreOptions();
  secUpdateSmartUI();
  const shareBtn = document.getElementById('idShareBtn'); if (shareBtn) shareBtn.style.display = canWebShare() ? '' : 'none';
  scanDetectSupport().then(function (ok) { scanSupported = ok; applyScanSupport(); });

  const autolockSelect = document.getElementById('menuAutolockSelect');
  if (autolockSelect) {
    autolockSelect.value = String(autolockGetStoredMins());
    autolockSelect.addEventListener('change', function () { autolockSetMinutes(parseInt(autolockSelect.value, 10) || 0); });
  }

  // X25519 is only offered for NEW identities on browsers that actually support it in Web
  // Crypto (still not universal as of 2026) — feature-detected once here rather than
  // letting identity creation fail later. Existing P-256 identities are entirely unaffected.
  // 'deflate-raw' (de)compression streams are missing in older browsers: files are then stored uncompressed.
  (function () {
    const sel = document.getElementById('fileCompressionSelect');
    if (sel && !AnigmaContainer.deflateRawSupported()) {
      sel.value = 'none'; sel.disabled = true;
      sel.title = t('files.compression.unsupported');
    }
  })();
  AnigmaCrypto.supportsX25519().then(function (supported) {
    const row = document.getElementById('idCurveOptionRow');
    if (row) row.style.display = supported ? 'block' : 'none';
  });

  updateStatus('status.ready');
  addLog('log.msg.ready');

  // First run on this device: the short 3-step welcome (replaces the old auto-opened long guide).
  onboardMaybeOpen();

  // Soft light that follows the pointer on the background grid (purely cosmetic).
  (function () {
    let raf = 0, px = 0, py = 0;
    document.addEventListener('pointermove', function (e) {
      px = e.clientX; py = e.clientY;
      if (raf) return;
      raf = requestAnimationFrame(function () { raf = 0; const st = document.documentElement.style; st.setProperty('--mx', px + 'px'); st.setProperty('--my', py + 'px'); });
    }, { passive: true });
  })();

  window.__anigmaBooted = true; // js/compat-check.js watches for this
  setupServiceWorker();
  if (window.AnigmaUpdate) window.AnigmaUpdate.start(APP_VERSION); // signed, forced updates from GitHub (js/update.js)
})();
