// ====================================================================================
// ANIGMA — crypto.js
// Identity (ECDH P-256 or X25519), key derivation (HKDF; Argon2id for passphrases, PBKDF2 for older data),
// and the secure-message engine. Everything here runs through the browser's native Web
// Crypto API. No cryptographic primitive is implemented by hand; only composition of
// primitives happens here.
//
// Curve support: P-256 remains the default/compatible curve (65-byte raw public key,
// uncompressed point). X25519 is offered as an opt-in "modern" curve for NEW identities
// on browsers that support it (32-byte raw public key). Every function below that takes
// a raw public key detects which curve it is by that length difference, so callers never
// need to track curve choice themselves, and old P-256 identities/contacts keep working
// unchanged. See CURVE_X25519 / CURVE_P256 and curveFromRawPubLen().
// ====================================================================================

const AnigmaCrypto = (function () {
  'use strict';

  const ID_PASSPHRASE_MIN_LENGTH = 12; // creating/exporting only; unlocking never checks it, so shorter existing passwords still open
  // OWASP's current guidance for PBKDF2-HMAC-SHA256 is 600,000 iterations (310,000 was the 2021
  // figure). Every stored identity/backup records its own `iter`, so older blobs still open.
  const PBKDF2_ITERATIONS = 600000;
  const PBKDF2_MIN_ITER = 100000;      // accepted range when READING a stored/backup blob:
  const PBKDF2_MAX_ITER = 5000000;     // a lying/corrupt `iter` must not become a DoS or a downgrade
  // Argon2id (memory-hard; see js/argon2-client.js + vendor/argon2id.js). Defaults used when CREATING a key:
  // 128 MiB, 3 passes, 1 lane (RFC 9106 §4 "second recommended option" is 64 MiB; this is deliberately stronger).
  // If a device cannot allocate that, creation steps down through ARGON2_FALLBACK_M (never below 32 MiB).
  // READING a stored/backup blob accepts only the range below, so a lying file cannot demand gigabytes of RAM.
  const ARGON2_DEFAULT = { m: 131072, t: 3, p: 1 };   // m is in KiB
  const ARGON2_FALLBACK_M = [65536, 32768];
  const ARGON2_MIN_M = 8192, ARGON2_MAX_M = 262144, ARGON2_MIN_T = 1, ARGON2_MAX_T = 12;
  function validArgon2Params(kp) {
    return !!kp && Number.isInteger(kp.m) && Number.isInteger(kp.t) && kp.p === 1 &&
      kp.m >= ARGON2_MIN_M && kp.m <= ARGON2_MAX_M && kp.t >= ARGON2_MIN_T && kp.t <= ARGON2_MAX_T;
  }
  // LEGACY (read-only): messages made before the "no fixed prefix" format began with this text, and
  // every one of them then continued with the same base64 of `{"v":3` — a constant any filter could
  // match. New messages are never written with it (see encryptMessage); it is only recognised on input
  // so old messages still open.
  const MSG_MAGIC = 'ANGM3:';
  const MSG_INFO_LEGACY = 'anigma-message-v3';
  const MSG_INFO = 'anigma-message-v4';     // HKDF domain separation for the prefix-less binary format
  // Version of the passphrase normalisation (see normalizePassphrase). Stored next to every identity /
  // backup as `pn`; a blob without it was made before normalisation existed and is read as raw text.
  const PASSPHRASE_NORM_VERSION = 1;

  const CURVE_P256 = 'P-256';
  const CURVE_X25519 = 'X25519';
  const RAW_PUB_LEN = { 'P-256': 65, 'X25519': 32 };

  // ------------------------------------------------------------------ base64 helpers
  function bufToB64(buf) {
    const bytes = new Uint8Array(buf);
    let bin = '';
    for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
    return btoa(bin);
  }
  function b64ToBuf(str) {
    const bin = atob(str);
    const bytes = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
    return bytes.buffer;
  }

  // ------------------------------------------------------------------ curve helpers
  // Identifies the curve of a raw public key purely from its byte length. This is safe
  // because the two supported curves have non-overlapping raw-export lengths (65 vs 32).
  function curveFromRawPubLen(rawBuffer) {
    const len = (rawBuffer && rawBuffer.byteLength !== undefined) ? rawBuffer.byteLength : rawBuffer.length;
    if (len === RAW_PUB_LEN[CURVE_X25519]) return CURVE_X25519;
    if (len === RAW_PUB_LEN[CURVE_P256]) return CURVE_P256;
    throw new Error('unknown-curve-length');
  }

  function keyAlgoFor(curve) {
    return curve === CURVE_X25519 ? { name: 'X25519' } : { name: 'ECDH', namedCurve: 'P-256' };
  }

  // Feature-detects X25519 support once per session (some browsers as of 2026 still lack
  // it in Web Crypto). Callers should use this to decide whether to offer the "modern
  // curve" choice at identity-creation time, rather than letting generateKey fail later.
  let _x25519Support = null;
  async function supportsX25519() {
    if (_x25519Support !== null) return _x25519Support;
    try {
      await crypto.subtle.generateKey({ name: 'X25519' }, true, ['deriveBits']);
      _x25519Support = true;
    } catch (e) {
      _x25519Support = false;
    }
    return _x25519Support;
  }

  // ------------------------------------------------------------------ fingerprint
  // SHA-256 over the raw public key, first 16 bytes, shown as hex groups. Curve-agnostic:
  // a P-256 key and an X25519 key never collide because their raw encodings differ in
  // length (and thus hash differently) well before this truncation.
  async function computeFingerprint(pubKeyRawBuffer) {
    const hash = await crypto.subtle.digest('SHA-256', pubKeyRawBuffer);
    const bytes = new Uint8Array(hash).slice(0, 16);
    const hex = Array.from(bytes).map(function (b) { return b.toString(16).padStart(2, '0').toUpperCase(); }).join('');
    return hex.match(/.{1,4}/g).join(' ');
  }

  async function importPublicKeyRaw(rawBuffer) {
    const curve = curveFromRawPubLen(rawBuffer);
    return crypto.subtle.importKey('raw', rawBuffer, keyAlgoFor(curve), true, []);
  }

  function generateIdentityKeyPair(curve) {
    return crypto.subtle.generateKey(keyAlgoFor(curve || CURVE_P256), true, ['deriveBits']);
  }

  function generateEphemeralKeyPair(curve) {
    return crypto.subtle.generateKey(keyAlgoFor(curve || CURVE_P256), true, ['deriveBits']);
  }

  // ------------------------------------------------------------------ public-key derivation from a private key
  // Security review #6: an identity blob's `pub` field was stored as plaintext, outside the
  // AES-GCM envelope that protects the private key, and trusted as-is on unlock. Anything
  // able to write to localStorage (XSS, a rogue browser extension, a shared/compromised
  // device) could swap that one field and get the victim's own app to display an
  // attacker-chosen fingerprint/public key as "my identity" — QR code, "My ID" panel, and
  // "message to myself" would all then use the attacker's key while the PIN still unlocks
  // the victim's real private key.
  //
  // The fix is to never trust a stored public key: always re-derive it from the private
  // key that was just decrypted, and use that as the identity's public key everywhere. An
  // EC (P-256) or OKP (X25519) private key's JWK export always includes its public
  // coordinates alongside 'd', so this needs no extra ECDH operation — it's a pure format
  // conversion, not a new cryptographic step.
  function b64urlToBuf(b64url) {
    let s = b64url.replace(/-/g, '+').replace(/_/g, '/');
    while (s.length % 4) s += '=';
    return new Uint8Array(b64ToBuf(s));
  }
  async function derivePublicRawFromPrivateKey(privateKey, curve) {
    const jwk = await crypto.subtle.exportKey('jwk', privateKey);
    if (curve === CURVE_X25519) {
      return b64urlToBuf(jwk.x); // OKP: 32-byte public 'x'
    }
    // EC P-256: raw uncompressed point = 0x04 || x(32) || y(32)
    const x = b64urlToBuf(jwk.x), y = b64urlToBuf(jwk.y);
    const out = new Uint8Array(65);
    out[0] = 0x04; out.set(x, 1); out.set(y, 33);
    return out;
  }

  // ------------------------------------------------------------------ passphrase-derived key (identity at rest)
  async function keyFromPassphrase(pin, saltBytes, iterations) {
    const keyMaterial = await crypto.subtle.importKey('raw', new TextEncoder().encode(pin), { name: 'PBKDF2' }, false, ['deriveKey']);
    return crypto.subtle.deriveKey(
      { name: 'PBKDF2', salt: saltBytes, iterations: iterations || PBKDF2_ITERATIONS, hash: 'SHA-256' },
      keyMaterial,
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt']
    );
  }

  // ------------------------------------------------------------------ pluggable KDF dispatch
  // deriveMasterKey() is the one entry point ui.js should call for turning a passphrase
  // into the AES-GCM key that wraps an identity (device unlock or backup export/import).
  // 'kdfName' and 'iterations' are read back from the stored blob, never assumed, so a
  // change in defaults here never breaks unlocking something encrypted under the old
  // defaults — see idKdfParamsFor() usage in ui.js.
  //
  // Argon2id: new identities and backups use it (js/argon2-client.js runs the vendored, RFC-9106-compatible
  // implementation from vendor/argon2id.js in a worker and hands back a non-extractable AES-GCM key through
  // self.AnigmaArgon2idKDF(pass, salt, {m,t,p})). Identities made by earlier releases are stored with
  // kdf:'pbkdf2' and keep opening exactly as before — nothing is migrated or re-written behind the user's back.
  // Reading a blob that says argon2id when the module is absent throws 'argon2id-unavailable' (never a silent
  // PBKDF2 fallback under a misleading label). Creation goes through deriveNewKey(), which only steps the
  // memory down on a genuine out-of-memory, refuses to go below 32 MiB, and refuses to fall back to PBKDF2 at all
  // (it throws 'argon2id-unavailable' instead) unless a test explicitly passes { allowPbkdf2: true }.
  // Persian/Arabic keyboards type the SAME visible letters as different code points: Arabic yeh/kaf
  // (U+064A, U+0643), alef maksura (U+0649), and three different digit sets (ASCII, Arabic-Indic
  // U+0660.., Persian U+06F0..). Hashed as raw bytes those are different passwords, so switching
  // keyboard or device could lock someone out of their own identity. This maps every variant to one
  // canonical form (Persian yeh/kaf, ASCII digits) after Unicode NFKC. Versioned via `pn` so blobs
  // made before it existed (raw bytes) keep opening — see openWithPassphrase.
  function normalizePassphrase(pw) {
    let out = String(pw === undefined || pw === null ? '' : pw);
    if (typeof out.normalize === 'function') out = out.normalize('NFKC');
    out = out.replace(/[\u064A\u0649]/g, '\u06CC').replace(/\u0643/g, '\u06A9');
    out = out.replace(/[\u0660-\u0669]/g, function (c) { return String.fromCharCode(c.charCodeAt(0) - 0x0660 + 48); });
    out = out.replace(/[\u06F0-\u06F9]/g, function (c) { return String.fromCharCode(c.charCodeAt(0) - 0x06F0 + 48); });
    return out;
  }

  // `pn` (optional): PASSPHRASE_NORM_VERSION to normalise the passphrase first; anything else = raw
  // (the legacy behaviour, which is why omitting it is still valid for old stored blobs and tests).
  async function deriveMasterKey(pin, saltBytes, iterations, kdfName, pn, kdfParams) {
    const kdf = kdfName || 'pbkdf2';
    const pass = pn === PASSPHRASE_NORM_VERSION ? normalizePassphrase(pin) : pin;
    if (kdf === 'pbkdf2') {
      const it = iterations || PBKDF2_ITERATIONS;
      if (!Number.isInteger(it) || it < PBKDF2_MIN_ITER || it > PBKDF2_MAX_ITER) throw new Error('bad-format');
      return keyFromPassphrase(pass, saltBytes, it);
    }
    if (kdf === 'argon2id') {
      if (!validArgon2Params(kdfParams)) throw new Error('bad-format');
      if (typeof self !== 'undefined' && typeof self.AnigmaArgon2idKDF === 'function') {
        return self.AnigmaArgon2idKDF(pass, saltBytes, { m: kdfParams.m, t: kdfParams.t, p: kdfParams.p });
      }
      throw new Error('argon2id-unavailable');
    }
    throw new Error('unknown-kdf');
  }

  // Creates a brand-new passphrase-derived key with Argon2id (stepping the memory down only when the device cannot
  // allocate it, never below ARGON2_FALLBACK_M's floor). Returns { key, kdfFields } where kdfFields is what the
  // caller stores next to the salt: { kdf:'argon2id', kp:{m,t,p} }.
  //
  // There is NO silent downgrade: if Argon2id is not loaded (script blocked, failed integrity check, very old
  // engine…) this throws Error('argon2id-unavailable') and the UI tells the user plainly that nothing was created.
  // PBKDF2 is used for NEW data only when the caller explicitly passes { allowPbkdf2: true } — that switch exists
  // for the Node unit tests and is never set by the app. PBKDF2 stays fully supported for READING old data.
  async function deriveNewKey(pin, saltBytes, opts) {
    if (typeof self !== 'undefined' && typeof self.AnigmaArgon2idKDF === 'function') {
      const tries = [ARGON2_DEFAULT.m].concat(ARGON2_FALLBACK_M);
      for (let i = 0; i < tries.length; i++) {
        const kp = { m: tries[i], t: ARGON2_DEFAULT.t, p: ARGON2_DEFAULT.p };
        try {
          const key = await deriveMasterKey(pin, saltBytes, 0, 'argon2id', PASSPHRASE_NORM_VERSION, kp);
          return { key: key, kdfFields: { kdf: 'argon2id', kp: kp } };
        } catch (e) { if (!e || e.message !== 'argon2id-memory' || i === tries.length - 1) throw e; }
      }
    }
    if (!(opts && opts.allowPbkdf2 === true)) throw new Error('argon2id-unavailable');
    const key = await deriveMasterKey(pin, saltBytes, PBKDF2_ITERATIONS, 'pbkdf2', PASSPHRASE_NORM_VERSION);
    return { key: key, kdfFields: { kdf: 'pbkdf2', iter: PBKDF2_ITERATIONS } };
  }

  // Everything kept in localStorage (identity key, contacts, groups) is sealed under ONE master key.
  // Without more, a blob is valid in any slot, so someone who can write to storage could swap the
  // contacts blob into the groups slot (or the reverse). The slot name is therefore bound into the
  // AES-GCM tag as additional authenticated data. Blobs written before this carry no `aad: 1` flag
  // and are still read without it, then rewritten with it. NOT covered: replaying an OLDER copy of the
  // same slot (rollback) — detecting that needs a counter kept somewhere the attacker can't write.
  function storageAad(label) { return new TextEncoder().encode('anigma-storage|' + label); }
  async function sealStored(masterKey, label, plainBytes) {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv: iv, additionalData: storageAad(label) }, masterKey, plainBytes);
    return { iv: iv, ct: ct };
  }
  async function openStored(masterKey, label, blob) {
    const alg = { name: 'AES-GCM', iv: new Uint8Array(b64ToBuf(blob.iv)) };
    if (blob.aad === 1) alg.additionalData = storageAad(label);
    return crypto.subtle.decrypt(alg, masterKey, b64ToBuf(blob.ct));
  }

  // Opens an AES-GCM blob that was sealed under a passphrase-derived key (stored identity, or a
  // backup's payload). `params`: { salt, iv, ct (Uint8Array/ArrayBuffer), iter, kdf, pn }.
  // pn === 1: the passphrase is normalised. No pn (legacy blob): the passphrase is tried exactly as
  // typed first, then — only if that differs — in normalised form, which rescues someone who now
  // types their (ASCII-equivalent) passphrase on a different keyboard. Returns { masterKey, plain }.
  // Throws Error('wrong-passphrase') when nothing opens it; KDF problems ('bad-format',
  // 'argon2id-unavailable', 'unknown-kdf') propagate unchanged so callers can tell them apart.
  async function openWithPassphrase(pin, params) {
    const variants = params.pn === PASSPHRASE_NORM_VERSION
      ? [normalizePassphrase(pin)]
      : (normalizePassphrase(pin) !== pin ? [pin, normalizePassphrase(pin)] : [pin]);
    for (let i = 0; i < variants.length; i++) {
      const masterKey = await deriveMasterKey(variants[i], params.salt, params.iter, params.kdf, 0, params.kp);
      try {
        const alg = { name: 'AES-GCM', iv: params.iv };
        if (params.aad) alg.additionalData = params.aad;
        const plain = await crypto.subtle.decrypt(alg, masterKey, params.ct);
        return { masterKey: masterKey, plain: plain };
      } catch (e) { /* try next variant */ }
    }
    throw new Error('wrong-passphrase');
  }

  // A few of the passwords attackers try first, in English and Persian. Deliberately short: this is a
  // sanity filter for the meter, not a dictionary attack model (a real one is megabytes). Matching is
  // done after lower-casing, mapping look-alikes (@->a, 0->o, 1->l, 3->e, $/5->s) and normalising
  // Persian/Arabic letter and digit variants.
  const COMMON_PASSWORD_WORDS = [
    'password', 'passw0rd', 'qwerty', 'qwertyuiop', 'asdfgh', 'zxcvbn', 'letmein', 'welcome', 'admin', 'login',
    'iloveyou', 'monkey', 'dragon', 'master', 'sunshine', 'princess', 'football', 'baseball', 'secret', 'shadow',
    'michael', 'superman', 'batman', 'trustno', 'whatever', 'freedom', 'hello', 'anigma', 'changeme', 'google',
    'summer', 'winter', 'spring', 'autumn', 'love', 'test', 'user', 'abc', '1234', '0000', '1111', '2020', '2021',
    '2022', '2023', '2024', '2025', '2026',
    '\u0631\u0645\u0632', '\u067E\u0633\u0648\u0631\u062F', '\u067E\u0627\u0633\u0648\u0631\u062F', '\u0639\u0634\u0642',
    '\u0633\u0644\u0627\u0645', '\u0627\u06CC\u0631\u0627\u0646', '\u0645\u062D\u0645\u062F', '\u0639\u0644\u06CC'
  ];
  function containsCommonWord(pw) {
    const low = normalizePassphrase(pw).toLowerCase().replace(/[@]/g, 'a').replace(/0/g, 'o').replace(/[1!|]/g, 'l').replace(/3/g, 'e').replace(/[$5]/g, 's');
    const plain = normalizePassphrase(pw).toLowerCase();
    return COMMON_PASSWORD_WORDS.some(function (w) { return low.indexOf(w) !== -1 || plain.indexOf(w) !== -1; });
  }

  // Estimate, in "bits", of how long an attacker who knows typical human habits would need. Not a
  // guarantee: it only knows the short word list above, so a password that merely LOOKS random but is
  // built from your own name or birthday will still score too well. Rules: length counts only for
  // characters that aren't a repetition or an ascending/descending run; the alphabet size is taken from
  // the character classes used; a recognised common word caps the result very low; and ordinary typed
  // text is assumed to carry far fewer bits per character than random characters would.
  //   weak < 36 bits, medium < 56, strong >= 56 (about: 4 unrelated words, or 14 random mixed characters).
  function estimatePasswordStrength(pw) {
    if (!pw) return { key: '', className: '', percent: 0 };
    const norm = normalizePassphrase(pw);
    const chars = Array.from(norm);
    let pool = 0, variety = 0;
    if (/[a-z]/.test(norm)) { pool += 26; variety++; }
    if (/[A-Z]/.test(norm)) { pool += 26; variety++; }
    if (/[0-9]/.test(norm)) { pool += 10; variety++; }
    if (/[^a-zA-Z0-9\u0600-\u06FF]/.test(norm)) { pool += 33; variety++; }
    if (/[\u0600-\u06FF]/.test(norm)) { pool += 36; variety++; }
    const distinct = new Set(chars).size;
    let seq = 0; // characters that merely continue a run or an ascending/descending sequence
    for (let i = 2; i < chars.length; i++) {
      const a = chars[i - 2].codePointAt(0), b = chars[i - 1].codePointAt(0), c = chars[i].codePointAt(0);
      if ((b - a === c - b) && Math.abs(c - b) <= 1) seq++;
    }
    const effLen = Math.max(0, Math.min(distinct * 2, chars.length - seq)); // few distinct chars = repetition
    let bits = effLen * Math.log2(Math.max(pool, 2));
    if (containsCommonWord(pw)) bits = Math.min(bits, 14 + Math.max(0, effLen - 8) * 1.5);
    else if (variety < 3) bits = Math.min(bits, effLen * 3.2);
    else bits = Math.min(bits, effLen * 4);
    const percent = Math.max(5, Math.min(100, (bits / 70) * 100));
    if (pw.length < ID_PASSPHRASE_MIN_LENGTH) return { key: 'key.strength.weak', className: 'weak', percent: Math.min(percent, 30) };
    if (bits < 36) return { key: 'key.strength.weak', className: 'weak', percent: Math.min(percent, 35) };
    if (bits < 56) return { key: 'key.strength.medium', className: 'medium', percent: percent };
    return { key: 'key.strength.strong', className: 'strong', percent: percent };
  }

  // ------------------------------------------------------------------ ECDH/X25519 + HKDF (shared by messages and file wraps)
  // The deriveBits algorithm name must match the key's own curve (ECDH for P-256, X25519
  // for X25519); read it off the private key rather than assuming, so a DH between two
  // same-curve keys always works regardless of which curve the identity picked.
  async function ecdhBits(privateKey, publicKey) {
    const algoName = privateKey.algorithm && privateKey.algorithm.name === 'X25519' ? 'X25519' : 'ECDH';
    const bits = algoName === 'X25519' ? 256 : 256; // both curves used here yield a 256-bit shared secret
    return new Uint8Array(await crypto.subtle.deriveBits({ name: algoName, public: publicKey }, privateKey, bits));
  }

  // Static-static DH -> HKDF -> a non-extractable HMAC-SHA-256 key. Used for the file package's
  // sender-authentication tags: only the two holders of the (sender, recipient) long-term key pair can
  // compute it, which is what a key shared by ALL recipients (the content key) can never prove.
  async function deriveStaticHmacKey(myPrivateKey, theirPublicKey, saltBytes, infoStr) {
    const bits = await ecdhBits(myPrivateKey, theirPublicKey);
    const hkdfKey = await crypto.subtle.importKey('raw', bits, { name: 'HKDF' }, false, ['deriveKey']);
    return crypto.subtle.deriveKey(
      { name: 'HKDF', hash: 'SHA-256', salt: saltBytes, info: new TextEncoder().encode(infoStr) },
      hkdfKey, { name: 'HMAC', hash: 'SHA-256', length: 256 }, false, ['sign', 'verify']
    );
  }

  // X3DH-style shared key: DH1 (an ephemeral private key against a static/ephemeral public
  // key, for forward secrecy) and DH2 (a second ECDH pair whose meaning depends on the
  // caller — the long-term keys for sender authentication, or a second ephemeral for
  // anonymity) are concatenated and run through HKDF-SHA-256. If either party used the
  // wrong key, the derived AES-GCM key is wrong and decryption fails on the tag check —
  // that failure IS the authentication.
  async function deriveSharedAesKey(dh1PrivateKey, dh1PublicKey, dh2PrivateKey, dh2PublicKey, saltBytes, infoStr) {
    const bits1 = await ecdhBits(dh1PrivateKey, dh1PublicKey);
    const bits2 = await ecdhBits(dh2PrivateKey, dh2PublicKey);
    const combined = new Uint8Array(bits1.length + bits2.length);
    combined.set(bits1, 0);
    combined.set(bits2, bits1.length);
    const hkdfKey = await crypto.subtle.importKey('raw', combined, { name: 'HKDF' }, false, ['deriveKey']);
    return crypto.subtle.deriveKey(
      { name: 'HKDF', hash: 'SHA-256', salt: saltBytes, info: new TextEncoder().encode(infoStr) },
      hkdfKey,
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt']
    );
  }

  // ------------------------------------------------------------------ padding (section 5)
  // Pads the JSON envelope's UTF-8 byte length up to the next power of two (min 256,
  // capped at 16 MiB — beyond that, padding overhead stops being worth it). Padding lives
  // inside the encrypted, authenticated plaintext, and its content is never zero bytes.
  const PAD_MIN = 256;
  const PAD_MAX = 16 * 1024 * 1024;
  const PAD_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';

  function nextPow2(n) {
    let p = PAD_MIN;
    while (p < n) p *= 2;
    return p;
  }

  function randomPadString(len) {
    if (len <= 0) return '';
    const bytes = new Uint8Array(len);
    crypto.getRandomValues(bytes);
    let out = '';
    for (let i = 0; i < len; i++) out += PAD_ALPHABET[bytes[i] % PAD_ALPHABET.length]; // never zero-valued
    return out;
  }

  // Builds the final JSON string for an envelope object, adding a `pad` field sized so
  // the total UTF-8 byte length lands exactly on a power-of-two bucket.
  function buildPaddedJson(envelopeWithoutPad) {
    const base = Object.assign({}, envelopeWithoutPad, { pad: '' });
    const baseLen = new TextEncoder().encode(JSON.stringify(base)).length;
    if (baseLen >= PAD_MAX) {
      return JSON.stringify(envelopeWithoutPad); // too large to pad meaningfully
    }
    // Bucket (power of two) plus a random 0-25% extra, so message lengths are not all of the form
    // 2^k + constant — that regularity alone would mark a stream of messages as Anigma's. The bucket
    // still hides the true length to within a factor of two; the jitter only blurs the bucket edges.
    const bucket = nextPow2(baseLen);
    const jr = crypto.getRandomValues(new Uint32Array(1))[0];
    const target = bucket + (jr % (Math.floor(bucket / 4) + 1));
    let needed = target - baseLen;
    // Adding characters to `pad` grows the JSON by 1 byte per ASCII character, but if the
    // count itself changes digit-width in some pathological edge case we re-check once.
    base.pad = randomPadString(needed);
    let real = new TextEncoder().encode(JSON.stringify(base)).length;
    while (real > target && needed > 0) { needed--; base.pad = randomPadString(needed); real = new TextEncoder().encode(JSON.stringify(base)).length; }
    while (real < target) { base.pad += randomPadString(target - real); real = new TextEncoder().encode(JSON.stringify(base)).length; }
    return JSON.stringify(base);
  }

  // HKDF "info" for the prefix-less format. In authenticated mode both long-term public keys are bound
  // into the key (not just implied by the two DH results), so a ciphertext can only ever be opened as
  // "from THIS sender to THIS recipient" — it cannot be re-attributed to a different identity pair.
  function messageInfo(mode, senderPubRaw, recipientPubRaw) {
    if (mode !== 'auth') return MSG_INFO + '|anon';
    return MSG_INFO + '|auth|' + bufToB64(senderPubRaw) + '|' + bufToB64(recipientPubRaw);
  }
  // Public key to bind: the caller passes it explicitly (a non-extractable key cannot reveal it);
  // otherwise it is read off an extractable key (tests, group node keys). null = not available.
  async function resolvePublicRaw(explicitRaw, privateKey) {
    if (explicitRaw) return new Uint8Array(explicitRaw);
    try {
      const curve = (privateKey.algorithm && privateKey.algorithm.name === 'X25519') ? CURVE_X25519 : CURVE_P256;
      return new Uint8Array(await derivePublicRawFromPrivateKey(privateKey, curve));
    } catch (e) { return null; }
  }

  // ------------------------------------------------------------------ wire helpers (prefix-less message format)
  function concatBytes(parts) {
    let n = 0;
    for (let i = 0; i < parts.length; i++) n += parts[i].length;
    const out = new Uint8Array(n);
    let o = 0;
    for (let i = 0; i < parts.length; i++) { out.set(parts[i], o); o += parts[i].length; }
    return out;
  }
  // P-256 raw points start with the constant 0x04 — drop it on the wire (it would be a fixed byte at
  // the very front of every message) and restore it on read. X25519 keys are already bare 32 bytes.
  function rawToWire(rawBytes) {
    const b = new Uint8Array(rawBytes);
    return b.length === 65 ? b.slice(1) : b;
  }
  function wireToRaw(wireBytes, curve) {
    if (curve !== CURVE_P256) return wireBytes.slice();
    const out = new Uint8Array(65);
    out[0] = 0x04; out.set(wireBytes, 1);
    return out;
  }

  // ------------------------------------------------------------------ secure message engine (section 2, 4, 5, 6)
  // Recipient/sender selection:
  //   recipientPubRaw   - ArrayBuffer, the recipient's raw ECDH public key (from a saved
  //                       contact, a pasted key, or the user's own key for self-encryption)
  //   opts.senderPrivateKey / opts.senderPublicKeyRaw - the user's own unlocked identity
  //   opts.anonymous    - if true, DH2 uses a fresh second ephemeral instead of the
  //                       long-term identity, so the recipient cannot authenticate the sender
  async function encryptMessage(plainText, recipientPubRaw, opts) {
    opts = opts || {};
    const recipientCurve = curveFromRawPubLen(recipientPubRaw);
    const recipientPubKey = await importPublicKeyRaw(recipientPubRaw);
    const eph = await generateEphemeralKeyPair(recipientCurve);
    const ephPubRaw = new Uint8Array(await crypto.subtle.exportKey('raw', eph.publicKey));
    const salt = crypto.getRandomValues(new Uint8Array(16));

    let dh2PrivateKey, dh2PublicKey, eph2PubRaw = null, info;
    const mode = opts.anonymous ? 'anon' : 'auth';
    if (mode === 'anon') {
      const eph2 = await generateEphemeralKeyPair(recipientCurve);
      eph2PubRaw = new Uint8Array(await crypto.subtle.exportKey('raw', eph2.publicKey));
      dh2PrivateKey = eph2.privateKey;
      dh2PublicKey = recipientPubKey;
      info = messageInfo('anon');
    } else {
      // Authenticated mode does a real ECDH/X25519 between the sender's own identity key
      // and the recipient's identity key, so both must be on the same curve — there is no
      // cross-curve DH. Anonymous mode never touches the sender's identity key, so it has
      // no such restriction (see above).
      const senderCurve = (opts.senderPrivateKey && opts.senderPrivateKey.algorithm && opts.senderPrivateKey.algorithm.name === 'X25519') ? CURVE_X25519 : CURVE_P256;
      if (senderCurve !== recipientCurve) throw new Error('curve-mismatch');
      dh2PrivateKey = opts.senderPrivateKey;
      dh2PublicKey = recipientPubKey;
      const senderPubRaw = await resolvePublicRaw(opts.senderPublicKeyRaw, opts.senderPrivateKey);
      if (!senderPubRaw) throw new Error('sender-pub-required');
      info = messageInfo('auth', senderPubRaw, new Uint8Array(recipientPubRaw));
    }

    const aesKey = await deriveSharedAesKey(eph.privateKey, recipientPubKey, dh2PrivateKey, dh2PublicKey, salt, info);

    // `id` + `ts` sit inside the authenticated plaintext: the receiving device remembers ids it has
    // opened and flags a second appearance of the same one (a recorded message being re-sent).
    const innerPlain = {
      mode: mode,
      text: plainText,
      id: bufToB64(crypto.getRandomValues(new Uint8Array(12))),
      ts: Date.now()
    };
    const paddedJson = buildPaddedJson(innerPlain);

    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, aesKey, new TextEncoder().encode(paddedJson)));

    // Wire format (no magic, no version byte, no JSON keys — every byte is a public key, a random
    // salt/IV, or ciphertext, so nothing in it is constant across messages):
    //   eph (L) | [eph2 (L), anonymous mode only] | salt (16) | iv (12) | ciphertext+tag
    // where L = 32 (X25519) or 64 (P-256 as x||y; the constant 0x04 point-format byte is dropped
    // and put back on read). The reader knows L from its own key's curve and finds out whether eph2
    // is present by trial decryption — "this is an Anigma message" is therefore proved only by the
    // AES-GCM tag verifying, never by a recognisable header.
    const parts = [rawToWire(ephPubRaw)];
    if (eph2PubRaw) parts.push(rawToWire(eph2PubRaw));
    parts.push(salt, iv, ct);
    return bufToB64(concatBytes(parts));
  }

  // opts.myPrivateKey - unlocked identity of the person decrypting.
  // opts.claimedSenderPubRaw - optional; the public key of whoever is claimed/selected as
  //   the sender, used to attempt the authenticated branch. May be omitted if only an
  //   anonymous decryption is expected.
  // Returns { text, mode } — mode is read from the AUTHENTICATED plaintext, not from any
  // outer flag, so it cannot be forged in transit.
  async function decryptMessage(packedText, opts) {
    opts = opts || {};
    const text = String(packedText === undefined || packedText === null ? '' : packedText).trim();
    if (text.startsWith(MSG_MAGIC)) return decryptLegacyV3(text, opts);

    let bytes;
    try { bytes = new Uint8Array(b64ToBuf(text)); } catch (e) { throw new Error('not-anigma'); }
    if (!opts.myPrivateKey) throw new Error('no-candidate');
    const L = (opts.myPrivateKey.algorithm && opts.myPrivateKey.algorithm.name === 'X25519') ? 32 : 64;
    const MIN_CT = 16; // GCM tag alone
    if (bytes.length < L + 28 + MIN_CT) throw new Error('not-anigma');

    const layouts = []; // candidate parsings of the same bytes; only the one that authenticates wins
    if (bytes.length >= 2 * L + 28 + MIN_CT) layouts.push({ branch: 'anon', ephLen: 2 * L, info: messageInfo('anon') });
    if (opts.claimedSenderPubRaw) {
      const myPub = await resolvePublicRaw(opts.myPublicKeyRaw, opts.myPrivateKey);
      if (myPub) layouts.push({ branch: 'auth', ephLen: L, info: messageInfo('auth', new Uint8Array(opts.claimedSenderPubRaw), myPub) });
    }
    if (!layouts.length) throw new Error('no-candidate');

    const curve = L === 32 ? CURVE_X25519 : CURVE_P256;
    let plainObj = null, matchedBranch = null;
    for (const lay of layouts) {
      try {
        const ephPubKey = await importPublicKeyRaw(wireToRaw(bytes.subarray(0, L), curve));
        const dh2Pub = lay.branch === 'anon'
          ? await importPublicKeyRaw(wireToRaw(bytes.subarray(L, 2 * L), curve))
          : await importPublicKeyRaw(opts.claimedSenderPubRaw);
        const salt = bytes.slice(lay.ephLen, lay.ephLen + 16);
        const iv = bytes.slice(lay.ephLen + 16, lay.ephLen + 28);
        const ctBuf = bytes.slice(lay.ephLen + 28);
        const aesKey = await deriveSharedAesKey(opts.myPrivateKey, ephPubKey, opts.myPrivateKey, dh2Pub, salt, lay.info);
        const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, aesKey, ctBuf);
        plainObj = JSON.parse(new TextDecoder().decode(pt));
        matchedBranch = lay.branch;
        break;
      } catch (e) { /* not this layout / key — try the next candidate */ }
    }
    if (!plainObj) throw new Error('decrypt-failed');

    // Defense in depth: the mode claimed inside the authenticated plaintext must match
    // which key actually unlocked it. A mismatch means something is inconsistent/tampered.
    if (plainObj.mode !== matchedBranch) throw new Error('mode-mismatch');
    return { text: plainObj.text, mode: plainObj.mode, id: plainObj.id, ts: plainObj.ts };
  }

  // Reader for the old "ANGM3:" + base64(JSON) messages, kept so nothing already sent becomes unreadable.
  async function decryptLegacyV3(packedText, opts) {
    const envelope = JSON.parse(atob(packedText.slice(MSG_MAGIC.length)));
    if (envelope.v !== 3) throw new Error('unsupported-version');

    const ephPubKey = await importPublicKeyRaw(b64ToBuf(envelope.eph));
    const salt = new Uint8Array(b64ToBuf(envelope.salt));
    const iv = new Uint8Array(b64ToBuf(envelope.iv));
    const ctBuf = b64ToBuf(envelope.ct);

    const attempts = [];
    if (envelope.eph2) {
      attempts.push({ branch: 'anon', dh2Priv: opts.myPrivateKey, dh2Pub: await importPublicKeyRaw(b64ToBuf(envelope.eph2)) });
    }
    if (opts.claimedSenderPubRaw) {
      attempts.push({ branch: 'auth', dh2Priv: opts.myPrivateKey, dh2Pub: await importPublicKeyRaw(opts.claimedSenderPubRaw) });
    }
    if (!attempts.length) throw new Error('no-candidate');

    let plainObj = null, matchedBranch = null;
    for (const a of attempts) {
      try {
        const aesKey = await deriveSharedAesKey(opts.myPrivateKey, ephPubKey, a.dh2Priv, a.dh2Pub, salt, MSG_INFO_LEGACY);
        const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, aesKey, ctBuf);
        plainObj = JSON.parse(new TextDecoder().decode(pt));
        matchedBranch = a.branch;
        break;
      } catch (e) { /* try next candidate */ }
    }
    if (!plainObj) throw new Error('decrypt-failed');
    if (plainObj.mode !== matchedBranch) throw new Error('mode-mismatch');
    return { text: plainObj.text, mode: plainObj.mode };
  }

  // ------------------------------------------------------------------ identity export/import (section 9)
  // The backup file is protected by its own password (independent of the device unlock
  // passphrase, though the user may reuse it). It carries the private key (PKCS#8) and the
  // contact list, AES-GCM-encrypted under a PBKDF2-derived key.
  // v2 stores its own KDF params (`kdf`, `iter`) so a future change to defaults never
  // breaks importing a backup made under the old ones. v1 backups (no `kdf`/`iter` fields)
  // are still accepted for import, read back as pbkdf2 @ 200000 — the values the app used
  // to hardcode before this field existed.
  async function exportIdentityBackup(privateKeyPkcs8Buf, publicKeyRawBuf, contactsArray, exportPassword, opts) {
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const made = await deriveNewKey(exportPassword, salt, opts);
    const key = made.key;
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const payload = JSON.stringify({
      priv: bufToB64(privateKeyPkcs8Buf),
      pub: bufToB64(publicKeyRawBuf),
      contacts: contactsArray || []
    });
    const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, new TextEncoder().encode(payload));
    const isArgon = made.kdfFields.kdf === 'argon2id';
    return JSON.stringify(Object.assign({
      app: 'anigma-identity-backup',
      v: isArgon ? 3 : 2
    }, made.kdfFields, {
      pn: PASSPHRASE_NORM_VERSION,
      salt: bufToB64(salt),
      iv: bufToB64(iv),
      ct: bufToB64(ct)
    }), null, 2);
  }

  async function importIdentityBackup(jsonText, importPassword) {
    const blob = JSON.parse(jsonText);
    if (!blob || typeof blob !== 'object' || Array.isArray(blob)) throw new Error('bad-format');
    if (blob.app !== 'anigma-identity-backup' || (blob.v !== 1 && blob.v !== 2 && blob.v !== 3)) throw new Error('bad-format');
    // Every field must be the right TYPE and size before anything is decoded, so a malformed file is reported as a bad
    // file (not as a "wrong password") and cannot make the decoder chew on gigabytes.
    if (typeof blob.salt !== 'string' || typeof blob.iv !== 'string' || typeof blob.ct !== 'string' ||
        blob.salt.length > 64 || blob.iv.length > 64 || blob.ct.length > 64 * 1024 * 1024) throw new Error('bad-format');
    const salt = new Uint8Array(b64ToBuf(blob.salt));
    const iv = new Uint8Array(b64ToBuf(blob.iv));
    const kdf = blob.kdf || 'pbkdf2';
    const iterations = blob.iter || 200000; // legacy v1 default, before this field existed
    if (kdf === 'argon2id') { if (blob.v !== 3 || !validArgon2Params(blob.kp)) throw new Error('bad-format'); }
    else if (!Number.isInteger(iterations) || iterations < PBKDF2_MIN_ITER || iterations > PBKDF2_MAX_ITER) throw new Error('bad-format');
    if (salt.length !== 16 || iv.length !== 12) throw new Error('bad-format');
    let pt;
    try {
      pt = (await openWithPassphrase(importPassword, { salt: salt, iv: iv, ct: b64ToBuf(blob.ct), iter: iterations, kdf: kdf, kp: blob.kp, pn: blob.pn })).plain;
    } catch (e) {
      if (e && e.message === 'wrong-passphrase') throw new Error('decrypt-failed');
      throw e;
    }
    const payload = JSON.parse(new TextDecoder().decode(pt));
    return {
      privPkcs8: b64ToBuf(payload.priv),
      pubRaw: b64ToBuf(payload.pub),
      contacts: payload.contacts || []
    };
  }

  return {
    MSG_MAGIC: MSG_MAGIC,
    ID_PASSPHRASE_MIN_LENGTH: ID_PASSPHRASE_MIN_LENGTH,
    PBKDF2_ITERATIONS: PBKDF2_ITERATIONS,
    CURVE_P256: CURVE_P256,
    CURVE_X25519: CURVE_X25519,
    curveFromRawPubLen: curveFromRawPubLen,
    supportsX25519: supportsX25519,
    bufToB64: bufToB64,
    b64ToBuf: b64ToBuf,
    computeFingerprint: computeFingerprint,
    importPublicKeyRaw: importPublicKeyRaw,
    generateIdentityKeyPair: generateIdentityKeyPair,
    generateEphemeralKeyPair: generateEphemeralKeyPair,
    derivePublicRawFromPrivateKey: derivePublicRawFromPrivateKey,
    keyFromPassphrase: keyFromPassphrase,
    deriveMasterKey: deriveMasterKey,
    deriveNewKey: deriveNewKey,
    ARGON2_DEFAULT: ARGON2_DEFAULT,
    validArgon2Params: validArgon2Params,
    normalizePassphrase: normalizePassphrase,
    deriveStaticHmacKey: deriveStaticHmacKey,
    storageAad: storageAad,
    sealStored: sealStored,
    openStored: openStored,
    openWithPassphrase: openWithPassphrase,
    PASSPHRASE_NORM_VERSION: PASSPHRASE_NORM_VERSION,
    estimatePasswordStrength: estimatePasswordStrength,
    ecdhBits: ecdhBits,
    deriveSharedAesKey: deriveSharedAesKey,
    encryptMessage: encryptMessage,
    decryptMessage: decryptMessage,
    exportIdentityBackup: exportIdentityBackup,
    importIdentityBackup: importIdentityBackup
  };
})();
