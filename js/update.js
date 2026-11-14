// ====================================================================================
// ANIGMA — update.js
// Forced, signature-verified updates delivered from the project's GitHub repository.
//
// How it works
//   1. The page downloads two small files from the repo (never any code):
//        update/latest.json      the update manifest (version, notes, asset URL + SHA-256)
//        update/latest.json.sig  base64 ECDSA P-256 / SHA-256 signature over latest.json's exact bytes
//   2. The signature is checked against PUBLIC_KEY_JWK, which ships INSIDE the app. A manifest that is
//      unsigned, signed by another key, tampered with, or older than one already seen is rejected, so
//      a hacked GitHub account / CDN cannot push an update the app will accept.
//   3. If the verified version is newer than the installed one (and the manifest is mandatory, which
//      is the default), a full-screen, non-dismissable "Update required" gate blocks the app until the
//      update is installed. The verified manifest is remembered, so the gate stays up while offline.
//   4. "Update now" hands { url, sha256, size, version } to the native shell (window.AnigmaNative
//      .installUpdate — see docs/update-system.md), which downloads, checks the SHA-256 and installs
//      the APK / EXE. Without a native shell the signed download link is opened in the browser.
//
// A network failure never locks anyone out: only a *verified* newer version can raise the gate.
// ====================================================================================
(function (root) {
  'use strict';

  const REPO = 'amirjkkjhk-ux/Anigma-Modern';
  const BRANCH = 'main';
  const BASE_URL = 'https://raw.githubusercontent.com/' + REPO + '/' + BRANCH + '/update/';
  const MANIFEST_URL = BASE_URL + 'latest.json';
  const SIGNATURE_URL = MANIFEST_URL + '.sig';
  const ASSET_PREFIX = 'https://github.com/' + REPO + '/releases/download/';

  // Public half of the update-signing key (tools/gen-update-key.js writes this block). While x/y are
  // null the updater is switched off, so an unconfigured build can never gate anyone.
  // BEGIN PUBKEY
  const PUBLIC_KEY_JWK = { kty: 'EC', crv: 'P-256', x: 'yBtNTxSwSdxCYaTYh2dPlvZGyi3z9Nhynl9MaWYfghs', y: 'oMdB_70ld3FqbRbeih2kqPbxKxP0uSn7A9HvVoLr3vo' };
  // END PUBKEY

  const MAX_ASSET_BYTES = 1024 * 1024 * 1024;       // sanity cap on the announced installer size (1 GiB)
  const ASSET_EXT = { android: /\.apk$/i, windows: /\.(exe|msi)$/i };
  const MAX_BYTES = 64 * 1024;
  const FETCH_TIMEOUT_MS = 10000;
  const RECHECK_MS = 6 * 60 * 60 * 1000;
  const LS_REQUIRED = 'anigma_update_required'; // { m: base64(manifest bytes), s: signature } — re-verified on every read
  const LS_SEEN = 'anigma_update_seen';          // { m, s } of the highest verified manifest ever seen (rollback guard) — re-verified on every read, so storage tampering can neither fake nor block it

  // ---------- pure helpers (unit-tested) ----------
  function parseVersion(v) {
    if (typeof v !== 'string' || !/^\d{1,6}(\.\d{1,6}){0,3}$/.test(v)) return null;
    return v.split('.').map(Number);
  }
  function compareVersions(a, b) {
    const pa = parseVersion(a), pb = parseVersion(b);
    if (!pa || !pb) throw new Error('bad-version');
    for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
      const x = pa[i] || 0, y = pb[i] || 0;
      if (x !== y) return x < y ? -1 : 1;
    }
    return 0;
  }
  function b64ToBytes(b64) {
    const bin = atob(String(b64).replace(/\s+/g, ''));
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }
  function bytesToB64(bytes) {
    let s = '';
    for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
    return btoa(s);
  }
  function keyConfigured(jwk) { return !!(jwk && typeof jwk.x === 'string' && typeof jwk.y === 'string'); }

  async function verifySignature(manifestBytes, signatureBytes, jwk) {
    if (!keyConfigured(jwk)) throw new Error('no-key');
    if (signatureBytes.length !== 64) throw new Error('bad-signature');
    const key = await crypto.subtle.importKey('jwk', { kty: 'EC', crv: 'P-256', x: jwk.x, y: jwk.y, ext: true }, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify']);
    const ok = await crypto.subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, key, signatureBytes, manifestBytes);
    if (!ok) throw new Error('bad-signature');
  }

  // Strict schema check on the (already signature-verified) manifest. Defence in depth: the URL must
  // still point into this project's GitHub releases, so even a mis-signed manifest cannot redirect.
  function validateManifest(m) {
    if (!m || typeof m !== 'object' || m.schema !== 1) throw new Error('bad-manifest');
    if (!parseVersion(m.version)) throw new Error('bad-manifest');
    const notes = { en: '', fa: '' };
    if (m.notes && typeof m.notes === 'object') {
      ['en', 'fa'].forEach(function (k) { if (typeof m.notes[k] === 'string') notes[k] = m.notes[k].slice(0, 2000); });
    }
    const assets = {};
    if (m.assets && typeof m.assets === 'object') {
      // The signed URL must sit in THIS version's own release folder (.../releases/download/v<version>/<file>), so a
      // manifest signed for one version can never be repurposed to point at another release's file.
      const tagPrefix = ASSET_PREFIX + 'v' + m.version + '/';
      ['android', 'windows'].forEach(function (k) {
        const a = m.assets[k];
        if (!a) return;
        if (typeof a.url !== 'string' || a.url.indexOf(tagPrefix) !== 0 || a.url.length > 400 || /[\s"'<>\\?#%]|\.\./.test(a.url)) throw new Error('bad-manifest');
        const file = a.url.slice(tagPrefix.length);
        if (!/^[A-Za-z0-9._-]{1,120}$/.test(file) || !ASSET_EXT[k].test(file)) throw new Error('bad-manifest');
        if (typeof a.sha256 !== 'string' || !/^[0-9a-f]{64}$/.test(a.sha256)) throw new Error('bad-manifest');
        if (!Number.isInteger(a.size) || a.size <= 0 || a.size > MAX_ASSET_BYTES) throw new Error('bad-manifest');
        assets[k] = { url: a.url, sha256: a.sha256, size: a.size };
      });
    }
    return { version: m.version, mandatory: m.mandatory !== false, notes: notes, assets: assets };
  }

  // A native shell (APK / EXE) can only update by installing a new installer. A verified manifest that carries none
  // for THIS shell's platform is not actionable here, so it must never lock that app behind a gate it cannot clear.
  // (Web / PWA copies update through the service worker and need no installer.)
  function applicable(m, nativePlatform) {
    if (nativePlatform === 'android' || nativePlatform === 'windows') return !!m.assets[nativePlatform];
    return true;
  }

  async function openVerified(manifestBytes, signatureBytes, jwk) {
    await verifySignature(manifestBytes, signatureBytes, jwk);
    let parsed;
    try { parsed = JSON.parse(new TextDecoder().decode(manifestBytes)); } catch (e) { throw new Error('bad-manifest'); }
    return validateManifest(parsed);
  }

  // ---------- network ----------
  async function fetchLimited(url) {
    const ctl = typeof AbortController !== 'undefined' ? new AbortController() : null;
    const timer = ctl ? setTimeout(function () { ctl.abort(); }, FETCH_TIMEOUT_MS) : null;
    try {
      const resp = await fetch(url, { cache: 'no-store', credentials: 'omit', referrerPolicy: 'no-referrer', redirect: 'error', signal: ctl ? ctl.signal : undefined });
      if (!resp.ok) throw new Error('http-' + resp.status);
      const buf = new Uint8Array(await resp.arrayBuffer());
      if (buf.length === 0 || buf.length > MAX_BYTES) throw new Error('bad-size');
      return buf;
    } finally { if (timer) clearTimeout(timer); }
  }

  function lsGet(k) { try { return localStorage.getItem(k); } catch (e) { return null; } }
  function lsSet(k, v) { try { localStorage.setItem(k, v); } catch (e) { /* storage unavailable: fall back to online-only enforcement */ } }
  function lsDel(k) { try { localStorage.removeItem(k); } catch (e) { /* ignore */ } }

  // Highest version this device has ever seen in a SIGNATURE-VERIFIED manifest, or null. The stored record is
  // re-verified against the shipped public key every time; anything forged, corrupt or in the old bare-string
  // format is discarded (never trusted), so a write to localStorage cannot plant a fake "seen" version.
  async function seenVersion(jwk) {
    const raw = lsGet(LS_SEEN);
    if (!raw) return null;
    try {
      const o = JSON.parse(raw);
      const m = await openVerified(b64ToBytes(o.m), b64ToBytes(o.s), jwk);
      return m.version;
    } catch (e) { lsDel(LS_SEEN); return null; }
  }

  // Returns { status: 'disabled' | 'current' | 'update' | 'error', manifest?, error? }
  async function check(localVersion, opts) {
    opts = opts || {};
    const jwk = opts.jwk || PUBLIC_KEY_JWK;
    if (!keyConfigured(jwk)) return { status: 'disabled' };
    try {
      const getter = opts.fetchBytes || fetchLimited;
      const results = await Promise.all([getter(opts.manifestUrl || MANIFEST_URL), getter(opts.signatureUrl || SIGNATURE_URL)]);
      const manifestBytes = results[0];
      const signatureBytes = b64ToBytes(new TextDecoder().decode(results[1]));
      const m = await openVerified(manifestBytes, signatureBytes, jwk);

      const seen = await seenVersion(jwk);
      if (seen && compareVersions(m.version, seen) < 0) throw new Error('rollback'); // replayed older manifest
      if (!seen || compareVersions(m.version, seen) > 0) lsSet(LS_SEEN, JSON.stringify({ m: bytesToB64(manifestBytes), s: bytesToB64(signatureBytes) }));

      if (compareVersions(m.version, localVersion) > 0 && applicable(m, opts.nativePlatform)) {
        if (m.mandatory) lsSet(LS_REQUIRED, JSON.stringify({ m: bytesToB64(manifestBytes), s: bytesToB64(signatureBytes) }));
        return { status: 'update', manifest: m };
      }
      lsDel(LS_REQUIRED);
      return { status: 'current', manifest: m };
    } catch (e) {
      return { status: 'error', error: String((e && e.message) || e) };
    }
  }

  // A previously verified mandatory update that is still newer than what is installed. Works offline.
  async function storedRequirement(localVersion, jwk, nativePlatform) {
    jwk = jwk || PUBLIC_KEY_JWK;
    const raw = lsGet(LS_REQUIRED);
    if (!raw || !keyConfigured(jwk)) return null;
    try {
      const o = JSON.parse(raw);
      const m = await openVerified(b64ToBytes(o.m), b64ToBytes(o.s), jwk);
      if (m.mandatory && compareVersions(m.version, localVersion) > 0 && applicable(m, nativePlatform)) return m;
    } catch (e) { /* corrupt or forged storage entry — ignore it */ }
    lsDel(LS_REQUIRED);
    return null;
  }

  // ---------- UI (browser only) ----------
  function detectPlatform() {
    const n = root.AnigmaNative;
    if (n && typeof n.platform === 'string') return n.platform === 'android' || n.platform === 'windows' ? n.platform : 'web';
    const ua = (root.navigator && root.navigator.userAgent) || '';
    if (/android/i.test(ua)) return 'android';
    if (/windows/i.test(ua)) return 'windows';
    return 'web';
  }

  let gateShown = false;
  let currentManifest = null;
  let localVer = '0';

  function $(id) { return document.getElementById(id); }
  function tt(key, params) { return typeof root.t === 'function' ? root.t(key, params) : key; }
  function pickNotes(m) {
    const lang = (document.documentElement.lang || 'en').slice(0, 2);
    return (m.notes[lang] || m.notes.en || m.notes.fa || '').trim();
  }
  function renderGate() {
    const m = currentManifest;
    if (!m || !$('fuOverlay')) return;
    $('fuNew').textContent = m.version;
    $('fuCur').textContent = localVer;
    const notes = pickNotes(m);
    $('fuNotes').textContent = notes;
    $('fuNotesWrap').style.display = notes ? '' : 'none';
    $('fuLater').style.display = m.mandatory ? 'none' : '';
  }
  function setStatus(key, params) { const s = $('fuStatus'); if (s) s.textContent = key ? tt(key, params) : ''; }

  function showGate(m) {
    currentManifest = m;
    const overlay = $('fuOverlay');
    if (!overlay) return;
    renderGate();
    if (gateShown) return;
    gateShown = true;
    // Everything behind the gate becomes inert: no focus, no clicks, no screen-reader access.
    Array.prototype.forEach.call(document.body.children, function (el) {
      if (el !== overlay && el.tagName !== 'SCRIPT') el.setAttribute('inert', '');
    });
    overlay.classList.add('show');
    $('fuBtn').focus();
    overlay.addEventListener('keydown', function (ev) {
      if (ev.key === 'Escape' && currentManifest.mandatory) { ev.preventDefault(); ev.stopPropagation(); }
    }, true);
    try { new MutationObserver(renderGate).observe(document.documentElement, { attributes: true, attributeFilter: ['lang'] }); } catch (e) { /* older engines: notes keep the language they opened in */ }
  }
  function hideGate() {
    const overlay = $('fuOverlay');
    if (!overlay) return;
    overlay.classList.remove('show');
    Array.prototype.forEach.call(document.body.children, function (el) { el.removeAttribute('inert'); });
    gateShown = false;
  }

  function install() {
    const m = currentManifest;
    if (!m) return;
    const plat = detectPlatform();
    const asset = m.assets[plat];
    const native = root.AnigmaNative;
    $('fuSha').style.display = 'none';
    if (asset && native && typeof native.installUpdate === 'function') {
      try {
        native.installUpdate(JSON.stringify({ platform: plat, version: m.version, url: asset.url, sha256: asset.sha256, size: asset.size }));
        setStatus('update.started');
        return;
      } catch (e) { /* fall through to the browser route */ }
    }
    // On the Android / Windows app an update means a new installer. If the verified manifest carries no installer
    // for this platform, say so — reloading the page would not update anything and would loop forever on the gate.
    if (!asset && (plat === 'android' || plat === 'windows') && native) { setStatus('update.noAsset'); return; }
    if (asset) {
      $('fuShaVal').textContent = asset.sha256;
      $('fuSha').style.display = '';
      setStatus('update.opened');
      root.open(asset.url, '_blank', 'noopener,noreferrer');
      return;
    }
    // Installed as a website / PWA: pull the new build through the (hash-pinned) service worker.
    setStatus('update.reloading');
    const done = function () { root.location.reload(); };
    if (root.navigator.serviceWorker && root.navigator.serviceWorker.getRegistration) {
      root.navigator.serviceWorker.getRegistration().then(function (reg) {
        if (!reg) return done();
        return reg.update().then(function () { if (reg.waiting) reg.waiting.postMessage({ type: 'SKIP_WAITING' }); setTimeout(done, 1500); });
      }).catch(done);
    } else done();
  }

  // 'android' | 'windows' only when a real native shell is present (a phone's plain browser is just 'web').
  function nativePlatform() {
    const n = root.AnigmaNative;
    return n && (n.platform === 'android' || n.platform === 'windows') ? n.platform : null;
  }
  async function runCheck() {
    const r = await check(localVer, { nativePlatform: nativePlatform() });
    if (r.status === 'update') showGate(r.manifest);
    else if (r.status === 'current' && gateShown) hideGate();
    return r;
  }

  function start(localVersion) {
    localVer = String(localVersion);
    if (!keyConfigured(PUBLIC_KEY_JWK) || !root.document) return;
    $('fuBtn').addEventListener('click', install);
    $('fuLater').addEventListener('click', hideGate);
    // 1) a remembered mandatory update gates the app immediately, even offline
    storedRequirement(localVer, null, nativePlatform()).then(function (m) { if (m) showGate(m); }).catch(function () {});
    // 2) then ask GitHub (now, whenever the app returns to the foreground, and every few hours)
    runCheck();
    document.addEventListener('visibilitychange', function () { if (document.visibilityState === 'visible') runCheck(); });
    setInterval(runCheck, RECHECK_MS);
  }

  const api = {
    applicable: applicable, start: start, check: check, storedRequirement: storedRequirement, seenVersion: seenVersion, verifySignature: verifySignature,
    validateManifest: validateManifest, openVerified: openVerified, parseVersion: parseVersion, compareVersions: compareVersions,
    constants: { MANIFEST_URL: MANIFEST_URL, SIGNATURE_URL: SIGNATURE_URL, ASSET_PREFIX: ASSET_PREFIX, REPO: REPO, LS_REQUIRED: LS_REQUIRED, LS_SEEN: LS_SEEN }
  };
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
  else root.AnigmaUpdate = api;
})(typeof window !== 'undefined' ? window : globalThis);