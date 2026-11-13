// ====================================================================================
// ANIGMA — container.js
// The streaming file-container format used for bulk file encryption (section 3).
// Shared between the main thread and the worker, so it is a plain script (no ES modules)
// that both index.html and worker.js load with importScripts()/<script>.
//
// Layout on disk (version 2):
//   "ANGMF" (5) | version (1) | chunkSizeMB (1) | baseNonce (7) | recipientCount (1)
//   [recipient wrap]*recipientCount   -- each wrap is now VARIABLE length (see below),
//                                        so recipients can mix curves (P-256 and X25519)
//   -------------------------------- header ends here -----------------------------
//   STREAM-encrypted body: a sequence of AES-256-GCM chunks. Decrypted, the body is a
//   flat sequence of [4-byte BE header length][JSON header][file bytes] records.
//
// Version 2 recipient wrap (variable length):
//   ephPubLen (1) | ephPubRaw (ephPubLen: 65 for P-256, 32 for X25519) | salt (16) |
//   iv (12) | ct+tag (48)   -- total = 1 + ephPubLen + 76
// Version 1 recipient wrap (still parsed, for containers made by older builds):
//   ephPubRaw (65, P-256 only) | salt (16) | iv (12) | ct+tag (48) -- fixed 141 bytes.
// New plain (single/multi-recipient) containers are always written as version 2; version 1
// is read-only compatibility.
//
// Version 3 (GROUP containers, see docs/groups-spec-v1.md section 5) = the exact version-2
// layout above, followed by ONE extra "group section" appended right after the direct
// wraps. It is written ONLY when the caller passes opts.group to buildHeader(); every
// ordinary file keeps being written as byte-identical version 2, so older builds still
// open them. recipientCount (the direct wraps) may be 0 in a version-3 file.
//   groupIdLen (1) | groupId (UTF-8) | cardVersion (4, BE) | groupWrapCount (2, BE) |
//   [ nodeId (2, BE) | wrappedLen (2, BE) | wrapped (wrappedLen bytes, opaque) ]*groupWrapCount
// `wrapped` is opaque to this module (the group engine puts the AnigmaCrypto.encryptMessage
// output for the CEK there). Each entry is self-delimiting, so flipping bytes INSIDE one
// `wrapped` blob only breaks that node's wrap — the other entries still parse and unwrap.
// The group section is NOT authenticated by the body chunks (groupId/cardVersion are
// routing hints); the real binding is each wrap's own AEAD.
//
// Version 4 (SENDER-AUTHENTICATED containers) = the exact version-2 layout, plus a TRAILER of
// recipientCount x 32 bytes appended after the last body chunk (tag i belongs to wrap i):
//   tag_i = HMAC-SHA-256( K_i, H_final ),  K_i = HKDF( DH(sender static, recipient_i static) )
//   H_0 = SHA-256("anigma-file-body-v1" || every header byte);
//   H_n = SHA-256( H_{n-1} || counter(4) || lastFlag(1) || ciphertext chunk n )
// Why: the body is encrypted under ONE content key that every recipient knows, so by itself it only
// proves "made by someone holding the key" — any co-recipient could rebuild a different body that
// the others would accept as from the original sender. K_i can be computed only by the sender and
// recipient i, so a valid tag proves the sender made this exact header + body for THAT recipient.
// The reader verifies the tag over the whole ciphertext BEFORE writing any plaintext.
//
// STREAM chunk construction (section 3.2):
//   nonce   = baseNonce(7) || counter(4, big-endian) || lastFlag(1)
//   AAD     = counter(4, big-endian) || lastFlag(1)          (redundant with the nonce
//             on purpose — belt and suspenders against nonce-construction mistakes)
//   lastFlag is 1 only for the true final chunk of the body. Chunks must be produced and
//   consumed strictly in order; an unexpected counter or a stream that ends before a
//   lastFlag=1 chunk is an explicit failure, never a silently truncated plaintext.
// ====================================================================================

const AnigmaContainer = (function () {
  'use strict';

  const MAGIC = 'ANGMF';
  const MAGIC_BYTES = [0x41, 0x4E, 0x47, 0x4D, 0x46]; // "ANGMF"
  const VERSION = 2;           // version written for every non-group container
  const VERSION_GROUP = 3;     // version written when a group section is present
  const VERSION_AUTH = 4;      // version written for direct-recipient containers with per-recipient sender tags
  const AUTH_TAG_SIZE = 32;
  const MAX_RECIPIENTS = 255;   // recipientCount is a single byte
  const MAX_GROUP_WRAPS = 256; // sanity cap (a 128-leaf tree needs at most 64 covering nodes)
  const MAX_GROUP_WRAP_BYTES = 4096;
  const WRAP_SIZE_V1 = 65 + 16 + 12 + 48; // legacy fixed-size (P-256 only) = 141
  const WRAP_FIXED_PART = 16 + 12 + 48; // salt + iv + (cek + tag) = 76, same for v2
  const TAG_SIZE = 16;
  const DEFAULT_CHUNK_MB = 4;
  const MIN_CHUNK_MB = 1;
  const MAX_CHUNK_MB = 16;
  const ROUND_TO_BYTES = 16 * 1024 * 1024;

  // ------------------------------------------------------------------ small binary helpers
  function u32be(n) {
    const b = new Uint8Array(4);
    b[0] = (n >>> 24) & 0xff; b[1] = (n >>> 16) & 0xff; b[2] = (n >>> 8) & 0xff; b[3] = n & 0xff;
    return b;
  }
  function readU32be(bytes, offset) {
    return ((bytes[offset] << 24) | (bytes[offset + 1] << 16) | (bytes[offset + 2] << 8) | bytes[offset + 3]) >>> 0;
  }
  function concatBytes(parts) {
    let len = 0;
    for (const p of parts) len += p.length;
    const out = new Uint8Array(len);
    let off = 0;
    for (const p of parts) { out.set(p, off); off += p.length; }
    return out;
  }

  // ------------------------------------------------------------------ header
  // Writes version 2 (variable-length wraps, so recipients on different curves — P-256 and
  // X25519 — can be mixed in one container) UNLESS opts.group is given, in which case it
  // writes version 3 (the same bytes plus the group section). opts.group =
  //   { groupId: string, cardVersion: uint32, wraps: [{ nodeId: uint16, wrapped: string|Uint8Array }] }
  // `wrapped` strings are UTF-8 encoded. opts.wraps (direct recipients) may be empty only
  // for a group container.
  function buildHeader(opts) {
    const group = opts.group || null;
    // recipientCount is ONE byte on the wire; `& 0xff` used to silently wrap 256+ recipients
    // into a header that no longer matched its own wraps.
    if (opts.wraps.length > MAX_RECIPIENTS) throw new Error('container-too-many-recipients');
    const parts = [
      new Uint8Array(MAGIC_BYTES),
      new Uint8Array([group ? VERSION_GROUP : (opts.senderAuth ? VERSION_AUTH : VERSION), opts.chunkSizeMB & 0xff]),
      opts.baseNonce, // 7 bytes
      new Uint8Array([opts.wraps.length & 0xff])
    ];
    for (const w of opts.wraps) {
      parts.push(new Uint8Array([w.ephPubRaw.length & 0xff]), w.ephPubRaw, w.salt, w.iv, w.ct);
    }
    if (group) parts.push(encodeGroupSection(group));
    return concatBytes(parts);
  }

  function encodeGroupSection(group) {
    const enc = new TextEncoder();
    const idBytes = enc.encode(String(group.groupId));
    if (idBytes.length < 1 || idBytes.length > 255) throw new Error('container-bad-group-id');
    const cardVersion = group.cardVersion;
    if (!Number.isInteger(cardVersion) || cardVersion < 0 || cardVersion > 0xffffffff) throw new Error('container-bad-card-version');
    const gw = group.wraps || [];
    if (gw.length < 1 || gw.length > MAX_GROUP_WRAPS) throw new Error('container-bad-group-wrap-count');
    const parts = [new Uint8Array([idBytes.length]), idBytes, u32be(cardVersion), new Uint8Array([(gw.length >> 8) & 0xff, gw.length & 0xff])];
    for (const w of gw) {
      if (!Number.isInteger(w.nodeId) || w.nodeId < 1 || w.nodeId > 0xffff) throw new Error('container-bad-node-id');
      const wrapped = typeof w.wrapped === 'string' ? enc.encode(w.wrapped) : w.wrapped;
      if (!(wrapped instanceof Uint8Array) || wrapped.length < 1 || wrapped.length > MAX_GROUP_WRAP_BYTES) throw new Error('container-bad-group-wrap');
      parts.push(new Uint8Array([(w.nodeId >> 8) & 0xff, w.nodeId & 0xff, (wrapped.length >> 8) & 0xff, wrapped.length & 0xff]), wrapped);
    }
    return concatBytes(parts);
  }

  // Parses the version-3 group section starting at `off`. Returns { group, end }.
  function parseGroupSection(bytes, off) {
    const need = (n) => { if (off + n > bytes.length) throw new Error('container-too-short'); };
    need(1);
    const idLen = bytes[off++];
    if (idLen < 1) throw new Error('container-bad-group-id');
    need(idLen + 6);
    const groupId = new TextDecoder().decode(bytes.slice(off, off + idLen)); off += idLen;
    const cardVersion = readU32be(bytes, off); off += 4;
    const count = (bytes[off] << 8) | bytes[off + 1]; off += 2;
    if (count < 1 || count > MAX_GROUP_WRAPS) throw new Error('container-bad-group-wrap-count');
    const wraps = [];
    for (let i = 0; i < count; i++) {
      need(4);
      const nodeId = (bytes[off] << 8) | bytes[off + 1];
      const len = (bytes[off + 2] << 8) | bytes[off + 3];
      off += 4;
      if (len < 1 || len > MAX_GROUP_WRAP_BYTES) throw new Error('container-bad-group-wrap');
      need(len);
      wraps.push({ nodeId, wrapped: bytes.slice(off, off + len) });
      off += len;
    }
    return { group: { groupId, cardVersion, wraps }, end: off };
  }

  // Convenience: a group wrap's opaque bytes as the UTF-8 string they were built from
  // (the "ANIGMA-MSG:..." text of AnigmaCrypto.encryptMessage).
  function groupWrapToString(w) { return new TextDecoder().decode(w.wrapped); }

  // Throws a descriptive error for an unrecognized magic or version (section 3.8) instead
  // of a generic parse failure. Understands both the current version-2 layout (variable-
  // length wraps) and version-1 containers made by older builds (fixed 141-byte, P-256-
  // only wraps), so a file encrypted before this update still opens.
  function parseHeader(bytes) {
    if (bytes.length < 8) throw new Error('container-too-short');
    for (let i = 0; i < 5; i++) if (bytes[i] !== MAGIC_BYTES[i]) throw new Error('container-bad-magic');
    const version = bytes[5];
    if (version !== 1 && version !== 2 && version !== VERSION_GROUP && version !== VERSION_AUTH) {
      const e = new Error('container-unknown-version');
      e.foundVersion = version;
      throw e;
    }
    const chunkSizeMB = bytes[6];
    const baseNonce = bytes.slice(7, 14);
    const recipientCount = bytes[14];
    const wraps = [];
    let off = 15;
    if (version === 1) {
      const headerLength = 15 + recipientCount * WRAP_SIZE_V1;
      if (bytes.length < headerLength) throw new Error('container-too-short');
      for (let i = 0; i < recipientCount; i++) {
        wraps.push({
          ephPubRaw: bytes.slice(off, off + 65),
          salt: bytes.slice(off + 65, off + 81),
          iv: bytes.slice(off + 81, off + 93),
          ct: bytes.slice(off + 93, off + 141)
        });
        off += WRAP_SIZE_V1;
      }
      return { version, chunkSizeMB, baseNonce, wraps, group: null, headerLength, trailerLen: 0 };
    }
    // version 2 (and 3, whose direct-wrap part is identical): each wrap is prefixed with
    // its own public-key length.
    for (let i = 0; i < recipientCount; i++) {
      if (off + 1 > bytes.length) throw new Error('container-too-short');
      const ephLen = bytes[off];
      const wrapLen = 1 + ephLen + WRAP_FIXED_PART;
      if (off + wrapLen > bytes.length) throw new Error('container-too-short');
      wraps.push({
        ephPubRaw: bytes.slice(off + 1, off + 1 + ephLen),
        salt: bytes.slice(off + 1 + ephLen, off + 1 + ephLen + 16),
        iv: bytes.slice(off + 1 + ephLen + 16, off + 1 + ephLen + 28),
        ct: bytes.slice(off + 1 + ephLen + 28, off + 1 + ephLen + 76)
      });
      off += wrapLen;
    }
    if (version === VERSION_GROUP) {
      const g = parseGroupSection(bytes, off);
      // `group` is only ever set for version 3; for version 1/2 it is null.
      return { version, chunkSizeMB, baseNonce, wraps, group: g.group, headerLength: g.end, trailerLen: 0 };
    }
    return { version, chunkSizeMB, baseNonce, wraps, group: null, headerLength: off, trailerLen: version === VERSION_AUTH ? wraps.length * AUTH_TAG_SIZE : 0 };
  }

  // ------------------------------------------------------------------ masked header (no constant bytes)
  // The layout above starts with the fixed text "ANGMF" and a small version number — a signature any
  // scanner can match. New containers therefore store the header as
  //     salt (16 random bytes) | header XOR keystream(salt)
  // so that the whole file (header, STREAM body, trailer) looks like random bytes. The keystream needs
  // NO secret (AES-CTR under SHA-256 of a fixed label + the salt): this hides the structure from
  // pattern matching, it is not encryption — anyone who knows the scheme can strip it. Real
  // confidentiality still comes from the wraps and the body. Old containers (starting with the plain
  // magic) are still read as before.
  const MASK_SALT_LEN = 16;
  async function maskKeystream(salt, length) {
    const keyBytes = new Uint8Array(await crypto.subtle.digest('SHA-256', concatBytes([new TextEncoder().encode('anigma-hdr-mask-v1'), salt])));
    const key = await crypto.subtle.importKey('raw', keyBytes, { name: 'AES-CTR' }, false, ['encrypt']);
    const zeros = new Uint8Array(Math.max(length, 1));
    return new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-CTR', counter: new Uint8Array(16), length: 64 }, key, zeros)).subarray(0, length);
  }
  function xorBytes(a, b) { const out = new Uint8Array(a.length); for (let i = 0; i < a.length; i++) out[i] = a[i] ^ b[i]; return out; }
  async function maskBytes(salt, bytes) { return xorBytes(bytes, await maskKeystream(salt, bytes.length)); }

  // Same options as buildHeader(); returns the masked bytes (what must be written to the file).
  async function buildMaskedHeader(opts) {
    const inner = buildHeader(opts);
    const salt = crypto.getRandomValues(new Uint8Array(MASK_SALT_LEN));
    return concatBytes([salt, await maskBytes(salt, inner)]);
  }

  // Blob.arrayBuffer() does not exist before Chrome 76 / Firefox 69 / Safari 14: read through FileReader there.
  function blobToBuffer(blob) {
    if (typeof blob.arrayBuffer === 'function') return blob.arrayBuffer();
    return new Promise(function (resolve, reject) {
      const r = new FileReader();
      r.onload = function () { resolve(r.result); };
      r.onerror = function () { reject(r.error || new Error('read-failed')); };
      r.readAsArrayBuffer(blob);
    });
  }
  // Blob.stream() is missing before Chrome 76 / Firefox 69 / Safari 14.1: hand out 1 MiB slices with the same read()/cancel() shape.
  function blobReader(blob) {
    if (typeof blob.stream === 'function') return blob.stream().getReader();
    let off = 0; const CH = 1048576;
    return {
      read: function () {
        if (off >= blob.size) return Promise.resolve({ done: true, value: undefined });
        const end = Math.min(off + CH, blob.size), part = blob.slice(off, end); off = end;
        return blobToBuffer(part).then(function (b) { return { done: false, value: new Uint8Array(b) }; });
      },
      cancel: function () { off = blob.size; return Promise.resolve(); },
      releaseLock: function () {}
    };
  }
  // 'deflate-raw' streams exist from Chrome 103 / Safari 16.4 / Firefox 113 on. Without them files are stored uncompressed
  // (encrypting still works) and a compressed package from someone else reports "compression-unsupported" instead of failing oddly.
  let deflateRawOk = null;
  function deflateRawSupported() {
    if (deflateRawOk === null) {
      try { new CompressionStream('deflate-raw'); new DecompressionStream('deflate-raw'); deflateRawOk = true; } catch (e) { deflateRawOk = false; }
    }
    return deflateRawOk;
  }

  // Reads and parses the header of a File/Blob, masked or legacy. Returns
  //   { info, headerBytes }  where info = parseHeader() result with headerLength = bytes to skip IN THE FILE
  // (including the salt for masked containers) and headerBytes = those raw file bytes (the value the
  // version-4 authentication hash covers). Throws 'container-bad-magic' for anything that is not ours.
  async function readHeader(file) {
    const MAX_HEADER = 1200000; // 256 group wraps x 4 KiB + slack
    const first = new Uint8Array(await blobToBuffer(file.slice(0, 15)));
    let legacy = first.length >= 5;
    for (let i = 0; i < 5 && legacy; i++) if (first[i] !== MAGIC_BYTES[i]) legacy = false;
    let want = Math.min(file.size, 4096);
    for (;;) {
      const raw = new Uint8Array(await blobToBuffer(file.slice(0, want)));
      let inner, offset;
      if (legacy) { inner = raw; offset = 0; }
      else {
        if (raw.length < MASK_SALT_LEN + 15) throw new Error('container-bad-magic');
        const salt = raw.slice(0, MASK_SALT_LEN);
        inner = await maskBytes(salt, raw.slice(MASK_SALT_LEN));
        offset = MASK_SALT_LEN;
        for (let i = 0; i < 5; i++) if (inner[i] !== MAGIC_BYTES[i]) throw new Error('container-bad-magic');
      }
      try {
        const info = parseHeader(inner);
        info.headerLength += offset;
        return { info: info, headerBytes: raw.slice(0, info.headerLength) };
      } catch (e) {
        if (e.message !== 'container-too-short' || want >= file.size || want >= MAX_HEADER) throw e;
        want = Math.min(file.size, MAX_HEADER, want * 4);
      }
    }
  }

  // ------------------------------------------------------------------ STREAM chunk cipher
  function chunkNonce(baseNonce7, counter, lastFlag) {
    return concatBytes([baseNonce7, u32be(counter), new Uint8Array([lastFlag ? 1 : 0])]);
  }
  function chunkAad(counter, lastFlag) {
    return concatBytes([u32be(counter), new Uint8Array([lastFlag ? 1 : 0])]);
  }

  async function importCekKey(cekBytes) {
    return crypto.subtle.importKey('raw', cekBytes, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
  }

  async function encryptChunk(cekKey, baseNonce, counter, lastFlag, plaintextBytes) {
    const iv = chunkNonce(baseNonce, counter, lastFlag);
    const aad = chunkAad(counter, lastFlag);
    const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv, additionalData: aad }, cekKey, plaintextBytes);
    return new Uint8Array(ct);
  }

  // Throws 'stream-tampered' on any authentication failure, including a wrong lastFlag
  // guess caused by truncation/reordering/splicing — this is the anti-truncation property
  // STREAM is designed to give us.
  async function decryptChunk(cekKey, baseNonce, counter, lastFlag, ciphertextBytes) {
    const iv = chunkNonce(baseNonce, counter, lastFlag);
    const aad = chunkAad(counter, lastFlag);
    try {
      const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv, additionalData: aad }, cekKey, ciphertextBytes);
      return new Uint8Array(pt);
    } catch (e) {
      const err = new Error('stream-tampered');
      throw err;
    }
  }

  // Splits a known total plaintext length into chunk descriptors {counter, size, isLast}.
  function planPlainChunks(totalLen, chunkSizeMB) {
    const chunkSize = chunkSizeMB * 1024 * 1024;
    if (totalLen === 0) return [{ counter: 0, size: 0, isLast: true }];
    const n = Math.ceil(totalLen / chunkSize);
    const plan = [];
    for (let i = 0; i < n; i++) {
      const isLast = i === n - 1;
      const size = isLast ? (totalLen - i * chunkSize) : chunkSize;
      plan.push({ counter: i, size, isLast });
    }
    return plan;
  }

  // Splits a known total ciphertext length into block descriptors for decryption. Relies
  // on the fact that every non-final plaintext chunk is exactly chunkSize bytes, so the
  // boundary arithmetic is unambiguous; an inconsistent total length simply fails to
  // decrypt the assumed-final block (see decryptChunk's lastFlag binding).
  function planCipherBlocks(totalCipherLen, chunkSizeMB) {
    const full = chunkSizeMB * 1024 * 1024 + TAG_SIZE;
    if (totalCipherLen <= TAG_SIZE) return [{ counter: 0, offset: 0, size: totalCipherLen, isLast: true }];
    const numFull = Math.floor(totalCipherLen / full);
    const remainder = totalCipherLen - numFull * full;
    const plan = [];
    let offset = 0;
    const totalBlocks = remainder === 0 ? numFull : numFull + 1;
    for (let i = 0; i < totalBlocks; i++) {
      const isLast = i === totalBlocks - 1;
      const size = (!isLast) ? full : (remainder === 0 ? full : remainder);
      plan.push({ counter: i, offset, size, isLast });
      offset += size;
    }
    return plan;
  }

  // ------------------------------------------------------------------ recipient CEK wraps
  // Uses the same X3DH-style construction as text messages (AnigmaCrypto.deriveSharedAesKey)
  // so a forged sender or a mismatched recipient simply fails to unwrap, rather than
  // silently producing garbage. This is always an authenticated wrap (file sharing has no
  // anonymous-sender mode), so senderPrivateKey and recipientPublicKey must be on the same
  // curve — same X3DH constraint as encryptMessage()'s 'auth' mode, and enforced the same
  // way (an early, clear 'curve-mismatch' rather than letting deriveBits fail obscurely).
  async function wrapCekForRecipient(cekBytes, recipientPublicKey, senderPrivateKey) {
    const recipientCurve = recipientPublicKey.algorithm.name === 'X25519' ? AnigmaCrypto.CURVE_X25519 : AnigmaCrypto.CURVE_P256;
    const senderCurve = senderPrivateKey.algorithm.name === 'X25519' ? AnigmaCrypto.CURVE_X25519 : AnigmaCrypto.CURVE_P256;
    if (recipientCurve !== senderCurve) throw new Error('curve-mismatch');
    const eph = await AnigmaCrypto.generateEphemeralKeyPair(recipientCurve);
    const ephPubRaw = new Uint8Array(await crypto.subtle.exportKey('raw', eph.publicKey));
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const wrapKey = await AnigmaCrypto.deriveSharedAesKey(eph.privateKey, recipientPublicKey, senderPrivateKey, recipientPublicKey, salt, 'anigma-file-wrap-v1');
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, wrapKey, cekBytes));
    return { ephPubRaw, salt, iv, ct };
  }

  // Tries every wrap entry in the header against the local identity and a claimed sender
  // public key, returning the first CEK that unwraps successfully, or null.
  async function unwrapCek(wraps, myPrivateKey, claimedSenderPublicKey) {
    for (const w of wraps) {
      try {
        const ephPubKey = await AnigmaCrypto.importPublicKeyRaw(w.ephPubRaw.buffer.slice(w.ephPubRaw.byteOffset, w.ephPubRaw.byteOffset + w.ephPubRaw.byteLength));
        const wrapKey = await AnigmaCrypto.deriveSharedAesKey(myPrivateKey, ephPubKey, myPrivateKey, claimedSenderPublicKey, w.salt, 'anigma-file-wrap-v1');
        const cek = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: w.iv }, wrapKey, w.ct);
        return new Uint8Array(cek);
      } catch (e) { /* not this recipient's wrap, or wrong claimed sender — try the next */ }
    }
    return null;
  }

  // ------------------------------------------------------------------ sender authentication (version 4)
  async function sha256(bytes) { return new Uint8Array(await crypto.subtle.digest('SHA-256', bytes)); }
  // Start of the running hash over header + ciphertext (see the version-4 note at the top).
  async function bodyHashInit(headerBytes) {
    return sha256(concatBytes([new TextEncoder().encode('anigma-file-body-v1'), headerBytes]));
  }
  async function bodyHashStep(prevHash, counter, lastFlag, cipherBytes) {
    return sha256(concatBytes([prevHash, u32be(counter), new Uint8Array([lastFlag ? 1 : 0]), cipherBytes]));
  }
  // The per-(sender, recipient) key. `senderPubRaw`/`recipientPubRaw` are bound into the derivation, and
  // baseNonce (unique per container) is the HKDF salt, so a key is never reusable across files.
  async function deriveFileAuthKey(myPrivateKey, theirPublicKey, senderPubRaw, recipientPubRaw, baseNonce) {
    const info = 'anigma-file-auth-v1|' + AnigmaCrypto.bufToB64(senderPubRaw) + '|' + AnigmaCrypto.bufToB64(recipientPubRaw);
    return AnigmaCrypto.deriveStaticHmacKey(myPrivateKey, theirPublicKey, baseNonce, info);
  }
  async function senderAuthTag(authKey, finalHash) {
    return new Uint8Array(await crypto.subtle.sign('HMAC', authKey, finalHash));
  }
  async function verifySenderAuthTag(authKey, finalHash, tagBytes) {
    if (!tagBytes || tagBytes.length !== AUTH_TAG_SIZE) return false;
    return crypto.subtle.verify('HMAC', authKey, tagBytes, finalHash);
  }

  // Same as unwrapCek, but also reports WHICH wrap opened (its index is also the index of this
  // recipient's sender-authentication tag in a version-4 trailer). Returns { cek, index } or null.
  async function unwrapCekIndexed(wraps, myPrivateKey, claimedSenderPublicKey) {
    for (let i = 0; i < wraps.length; i++) {
      const w = wraps[i];
      try {
        const ephPubKey = await AnigmaCrypto.importPublicKeyRaw(w.ephPubRaw.buffer.slice(w.ephPubRaw.byteOffset, w.ephPubRaw.byteOffset + w.ephPubRaw.byteLength));
        const wrapKey = await AnigmaCrypto.deriveSharedAesKey(myPrivateKey, ephPubKey, myPrivateKey, claimedSenderPublicKey, w.salt, 'anigma-file-wrap-v1');
        const cek = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: w.iv }, wrapKey, w.ct);
        return { cek: new Uint8Array(cek), index: i };
      } catch (e) { /* not this recipient's wrap, or wrong claimed sender */ }
    }
    return null;
  }

  // ------------------------------------------------------------------ path safety (section 3.7)
  // Rejects (rather than rewrites) anything that is unsafe on at least one mainstream OS:
  // traversal, absolute paths, control characters, Windows drive/stream syntax (':'), Windows
  // reserved device names, trailing dot/space (Windows strips them, which can alias another
  // name), and absurd segment/total lengths.
  const WIN_RESERVED = /^(con|prn|aux|nul|com[1-9]|lpt[1-9])(\..*)?$/i;
  function sanitizeRelativePath(name) {
    const norm = String(name).replace(/\\/g, '/');
    if (/[\u0000-\u001f\u007f]/.test(norm)) throw new Error('bad-path');
    // Bidi override/embedding/isolate controls (U+202A-202E, U+2066-2069) let a name such as
    // "invoice<RLO>gnp.exe" DISPLAY as "invoiceexe.png" while really ending in ".exe". Refuse them on both
    // sides. (ZWNJ/ZWJ and LRM/RLM are deliberately still allowed: Persian file names use them legitimately.)
    if (/[\u202a-\u202e\u2066-\u2069]/.test(norm)) throw new Error('bad-path');
    const parts = norm.split('/').filter(function (p) { return p.length > 0; });
    if (!parts.length) throw new Error('bad-path');
    for (const p of parts) {
      if (p === '..' || p === '.') throw new Error('bad-path');
      if (p.length > 255 || p.indexOf(':') !== -1 || /[. ]$/.test(p) || WIN_RESERVED.test(p)) throw new Error('bad-path');
    }
    if (norm.startsWith('/') || /^[a-zA-Z]:/.test(norm)) throw new Error('bad-path'); // absolute path
    const out = parts.join('/');
    if (out.length > 1024) throw new Error('bad-path');
    return out;
  }

  // ------------------------------------------------------------------ per-file record framing
  function encodeFileHeaderRecord(meta) {
    const json = JSON.stringify(meta);
    const jsonBytes = new TextEncoder().encode(json);
    return concatBytes([u32be(jsonBytes.length), jsonBytes]);
  }

  // A small incremental byte queue used while decoding: chunks arrive one at a time from
  // the STREAM decryptor, but file-record boundaries rarely line up with chunk boundaries.
  function createByteQueue() {
    let parts = [];
    let total = 0;
    return {
      push(bytes) { if (bytes.length) { parts.push(bytes); total += bytes.length; } },
      get length() { return total; },
      // Returns exactly n bytes and removes them, or null if not enough is buffered yet.
      readExact(n) {
        if (total < n) return null;
        if (parts.length === 1 && parts[0].length === n) { const r = parts[0]; parts = []; total = 0; return r; }
        const out = new Uint8Array(n);
        let off = 0, i = 0;
        while (off < n) {
          const p = parts[i];
          const take = Math.min(p.length - 0, n - off);
          out.set(p.subarray(0, take), off);
          off += take;
          if (take === p.length) { i++; } else { parts[i] = p.subarray(take); }
        }
        parts = parts.slice(i);
        total -= n;
        return out;
      },
      isEmpty() { return total === 0; }
    };
  }

  function planPaddingEntrySize(realTotalLen) {
    if (realTotalLen <= 0) return 0;
    const rounded = Math.ceil(realTotalLen / ROUND_TO_BYTES) * ROUND_TO_BYTES;
    return rounded - realTotalLen;
  }

  return {
    blobToBuffer: blobToBuffer,
    blobReader: blobReader,
    deflateRawSupported: deflateRawSupported,
    MAGIC, VERSION, VERSION_GROUP, VERSION_AUTH, AUTH_TAG_SIZE, MAX_RECIPIENTS, MAX_GROUP_WRAPS, MAX_GROUP_WRAP_BYTES, WRAP_SIZE_V1, WRAP_FIXED_PART, TAG_SIZE,
    DEFAULT_CHUNK_MB, MIN_CHUNK_MB, MAX_CHUNK_MB, ROUND_TO_BYTES,
    u32be, readU32be, concatBytes,
    buildHeader, buildMaskedHeader, readHeader, maskKeystream, maskBytes, parseHeader, groupWrapToString,
    chunkNonce, chunkAad, importCekKey, encryptChunk, decryptChunk,
    planPlainChunks, planCipherBlocks,
    wrapCekForRecipient, unwrapCek, unwrapCekIndexed,
    bodyHashInit, bodyHashStep, deriveFileAuthKey, senderAuthTag, verifySenderAuthTag,
    sanitizeRelativePath, encodeFileHeaderRecord, createByteQueue,
    planPaddingEntrySize
  };
})();
