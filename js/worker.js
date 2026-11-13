// ====================================================================================
// ANIGMA — worker.js
// Runs the heavy part of bulk file encryption/decryption off the main thread: reading
// File streams, optional per-file compression, STREAM chunk encryption/decryption, and
// (when a File System Access handle is available) writing the result straight to disk.
// Only file/handle references and small progress messages cross the thread boundary;
// bulk bytes travel as transferable ArrayBuffers.
// ====================================================================================

importScripts('crypto.js', 'container.js');

let cancelled = false;

self.onmessage = async function (ev) {
  const msg = ev.data;
  if (msg.op === 'cancel') { cancelled = true; return; }
  cancelled = false;
  try {
    if (msg.op === 'encrypt') {
      await runEncrypt(msg);
    } else if (msg.op === 'decrypt') {
      await runDecrypt(msg);
    }
  } catch (e) {
    post({ type: 'error', message: (e && e.message) ? e.message : String(e) });
  }
};

function post(obj, transfer) {
  self.postMessage(obj, transfer || []);
}

const COMPRESSIBLE_SKIP_EXT = ['jpg', 'jpeg', 'png', 'gif', 'webp', 'mp4', 'mkv', 'mov', 'avi', 'mp3', 'aac',
  'ogg', 'flac', 'zip', '7z', 'rar', 'gz', 'bz2', 'xz', 'pdf', 'docx', 'xlsx', 'pptx', 'heic', 'webm'];

function extOf(name) {
  const i = name.lastIndexOf('.');
  return i === -1 ? '' : name.slice(i + 1).toLowerCase();
}
function shouldCompress(name, mode) {
  if (mode === 'none') return false;
  if (!AnigmaContainer.deflateRawSupported()) return false; // old browser: store uncompressed (still encrypted)
  if (mode === 'all') return true;
  return COMPRESSIBLE_SKIP_EXT.indexOf(extOf(name)) === -1; // 'smart'
}

async function readWholeStream(stream) {
  const reader = stream.getReader();
  const parts = [];
  let total = 0;
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    parts.push(value);
    total += value.length;
  }
  const out = new Uint8Array(total);
  let off = 0;
  for (const p of parts) { out.set(p, off); off += p.length; }
  return out;
}

// Bug report follow-up (encrypt UI appears to "freeze" on file selection): the previous
// version of this pre-pass read + compressed each file that needs compression in one
// uninterruptible pair of awaits (readWholeStream then a one-shot compressBytes), with no
// reportProgress() call anywhere in the loop and no `cancelled` check once a file's
// compression had begun. For any file large enough (or a compression ratio poor enough)
// that this takes more than a second or two, the UI showed the "operation in progress"
// chrome (wake-lock note + Cancel button) with a permanently empty progress bar/stats —
// measured at ~9.3s of total silence for a single 350MB low-compressibility file — and
// Cancel did nothing until that file's compression finished, because the only cancellation
// checkpoint was between files, not inside one. Both are fixed by streaming the read and
// the compression concurrently, chunk by chunk, checking `cancelled` and reporting progress
// (via `onChunk`) after every source chunk instead of only after the whole file is done.
function makeCancelledSignal() { const e = new Error('cancelled-during-prepare'); e.cancelledDuringPrepare = true; return e; }

async function compressFileStreaming(file, onChunk) {
  const cs = new CompressionStream('deflate-raw');
  const writer = cs.writable.getWriter();
  const outReader = cs.readable.getReader();
  const outParts = [];
  let outTotal = 0;

  // Drains the compressed side concurrently with writing to it — required so a highly
  // compressible large file doesn't stall on writable backpressure while nobody is
  // reading the other end.
  const drainOut = (async () => {
    while (true) {
      const { done, value } = await outReader.read();
      if (done) return;
      outParts.push(value);
      outTotal += value.length;
    }
  })();

  const srcReader = AnigmaContainer.blobReader(file);
  try {
    while (true) {
      if (cancelled) throw makeCancelledSignal();
      const { done, value } = await srcReader.read();
      if (done) break;
      await writer.write(value);
      onChunk(value.length);
    }
    await writer.close();
  } catch (e) {
    try { await srcReader.cancel(); } catch (e2) {}
    try { await writer.abort(e); } catch (e2) {}
    // Aborting the writable side also errors/closes the readable side, which makes the
    // still-running `drainOut` pump above reject too. Nothing else will ever await that
    // rejection once we throw `e` below, so left alone it becomes an unhandled promise
    // rejection (observed: crashes the whole page/worker instead of just this operation).
    // We already know why it failed — swallow drainOut's rejection here instead.
    try { await drainOut; } catch (e2) {}
    throw e;
  }
  await drainOut;

  const out = new Uint8Array(outTotal);
  let off = 0;
  for (const p of outParts) { out.set(p, off); off += p.length; }
  return out;
}

// ------------------------------------------------------------------ ENCRYPT
async function runEncrypt(msg) {
  // msg: { files: [{file, relPath}], chunkSizeMB, cekBytes, baseNonce, headerBytes,
  //        compressMode, roundSize, destination: {mode:'fsapi', handle} | {mode:'blob'} }
  const cekKey = await AnigmaContainer.importCekKey(msg.cekBytes);
  const chunkSizeMB = msg.chunkSizeMB;
  // defence in depth: the UI already checks, but the worker never trusts a size it is handed
  if (!Number.isInteger(chunkSizeMB) || chunkSizeMB < AnigmaContainer.MIN_CHUNK_MB || chunkSizeMB > AnigmaContainer.MAX_CHUNK_MB) throw new Error('bad-chunk-size');
  const chunkSize = chunkSizeMB * 1024 * 1024;

  // Pass 1: build per-file metadata. Compressed files must be fully materialized here to
  // learn their final stored size (a documented trade-off — see help text); uncompressed
  // files are described by their already-known size and stream through untouched.
  //
  // Progress during this pass is reported against original (pre-compression) bytes read,
  // not the not-yet-known compressed size — the best honest signal available before
  // compression finishes. `phase: 'preparing'` lets the UI show distinct wording (see
  // ui.js/i18n.js) instead of silently reusing the "encrypting" numbers for a different
  // quantity.
  const totalOriginalAllFiles = msg.files.reduce(function (s, f) { return s + f.file.size; }, 0);
  let prepBytesRead = 0;
  let prepLastReport = 0;
  function reportPrepProgress(fileName, fileIndex) {
    const now = Date.now();
    if (now - prepLastReport < 120 && prepBytesRead < totalOriginalAllFiles) return;
    prepLastReport = now;
    post({
      type: 'progress', phase: 'preparing', processed: prepBytesRead, total: totalOriginalAllFiles,
      fileName: fileName || '', fileIndex: fileIndex || 0, fileCount: msg.files.length
    });
  }

  const entries = [];
  let totalOriginal = 0;
  for (let fi = 0; fi < msg.files.length; fi++) {
    if (cancelled) return post({ type: 'cancelled' });
    const f = msg.files[fi];
    const relPath = AnigmaContainer.sanitizeRelativePath(f.relPath || f.file.name);
    const compress = shouldCompress(relPath, msg.compressMode);
    let storedBytes = null, storedSize = f.file.size;
    if (compress) {
      try {
        storedBytes = await compressFileStreaming(f.file, function (n) {
          prepBytesRead += n;
          reportPrepProgress(relPath, fi + 1);
        });
      } catch (e) {
        if (e && e.cancelledDuringPrepare) return post({ type: 'cancelled' });
        throw e;
      }
      storedSize = storedBytes.length;
    } else {
      // Not compressed: still counts toward the "preparing" bar so multi-file selections
      // with a mix of compressed/uncompressed files show continuous progress instead of
      // jumps, and so a lone uncompressed file doesn't leave the bar at 0% through Pass 1.
      prepBytesRead += f.file.size;
      reportPrepProgress(relPath, fi + 1);
    }
    // `size` is the original (display) size; `stored` is the exact byte length of the data
    // run that follows this header in the plaintext stream (compressed length if applicable).
    const meta = { name: relPath, size: f.file.size, type: f.file.type || '', compressed: compress, stored: storedSize };
    const headerRecord = AnigmaContainer.encodeFileHeaderRecord(meta);
    entries.push({ file: f.file, meta, headerRecord, storedSize, storedBytes });
    totalOriginal += headerRecord.length + storedSize;
  }

  let padSize = 0;
  if (msg.roundSize) padSize = AnigmaContainer.planPaddingEntrySize(totalOriginal + 200 /* rough header slack */);
  let padRecord = null;
  if (padSize > 0) {
    padRecord = AnigmaContainer.encodeFileHeaderRecord({ name: '__padding__', size: padSize, stored: padSize, type: '', compressed: false, pad: true });
  }
  const totalPlainLen = totalOriginal + (padRecord ? padRecord.length + padSize : 0);

  // Destination
  let writable = null;
  const blobParts = [];
  if (msg.destination.mode === 'fsapi') {
    writable = await msg.destination.handle.createWritable();
    await writable.write(msg.headerBytes);
  } else {
    blobParts.push(msg.headerBytes);
  }

  async function emit(bytes) {
    if (writable) await writable.write(bytes);
    else blobParts.push(bytes);
  }

  // Version-4 sender authentication: one running hash over header + every ciphertext chunk, tagged per
  // recipient at the end (see the version-4 note in container.js). authKeys[i] belongs to wrap i.
  const authKeys = msg.authKeys && msg.authKeys.length ? msg.authKeys : null;
  let chainHash = authKeys ? await AnigmaContainer.bodyHashInit(msg.headerBytes) : null;
  async function emitChunk(ct, counter, isLast) {
    if (authKeys) chainHash = await AnigmaContainer.bodyHashStep(chainHash, counter, isLast, ct);
    await emit(ct);
  }

  // A rolling buffer that accumulates plaintext bytes until a full chunk is ready.
  let pending = new Uint8Array(0);
  let bytesConsumedTotal = 0;
  let chunkCounter = 0;
  const startTime = Date.now();

  async function pushPlain(bytes) {
    if (!bytes.length) return;
    const merged = new Uint8Array(pending.length + bytes.length);
    merged.set(pending, 0); merged.set(bytes, pending.length);
    pending = merged;
    while (true) {
      const remainingTotal = totalPlainLen - bytesConsumedTotal - pending.length;
      // Every NON-final chunk must be exactly `chunkSize` plaintext bytes — the decrypt
      // side's planCipherBlocks() relies on that to re-slice the ciphertext. So: split off
      // a full chunk whenever more than one chunk's worth has piled up (pending.length >
      // chunkSize), regardless of remainingTotal — otherwise a single large push (e.g. a
      // fully-compressed file) could leave several chunks' worth sitting in `pending` and
      // get dumped into flushFinal() as one oversized "final" block, which the decryptor
      // cannot correctly re-slice (silent corruption — bug #1). Only when pending is
      // *exactly* one chunk do we still require remainingTotal > 0 before splitting it
      // off, so that a plaintext whose length is an exact multiple of chunkSize is instead
      // left whole for flushFinal(), matching how planCipherBlocks() expects the true
      // final block to be sized.
      if (pending.length > chunkSize || (pending.length === chunkSize && remainingTotal > 0)) {
        const chunk = pending.subarray(0, chunkSize);
        const ct = await AnigmaContainer.encryptChunk(cekKey, msg.baseNonce, chunkCounter, false, chunk);
        await emitChunk(ct, chunkCounter, false);
        bytesConsumedTotal += chunkSize;
        chunkCounter++;
        pending = pending.slice(chunkSize);
        reportProgress();
      } else {
        break;
      }
    }
  }

  async function flushFinal() {
    const ct = await AnigmaContainer.encryptChunk(cekKey, msg.baseNonce, chunkCounter, true, pending);
    await emitChunk(ct, chunkCounter, true);
    if (authKeys) {
      const tags = [];
      for (const k of authKeys) tags.push(await AnigmaContainer.senderAuthTag(k, chainHash));
      await emit(AnigmaContainer.concatBytes(tags));
    }
    bytesConsumedTotal += pending.length;
    pending = new Uint8Array(0);
    reportProgress();
  }

  let lastReport = 0;
  function reportProgress(fileName, fileIndex) {
    const now = Date.now();
    if (now - lastReport < 120 && bytesConsumedTotal < totalPlainLen) return;
    lastReport = now;
    post({
      type: 'progress', processed: bytesConsumedTotal, total: totalPlainLen,
      fileName: fileName || '', fileIndex: fileIndex || 0, fileCount: entries.length,
      elapsedMs: now - startTime
    });
  }

  for (let i = 0; i < entries.length; i++) {
    if (cancelled) { if (writable) await writable.abort(); return post({ type: 'cancelled' }); }
    const e = entries[i];
    try {
      await pushPlain(e.headerRecord);
      if (e.storedBytes) {
        await pushPlain(e.storedBytes);
      } else {
        const reader = AnigmaContainer.blobReader(e.file);
        while (true) {
          if (cancelled) { if (writable) await writable.abort(); return post({ type: 'cancelled' }); }
          const { done, value } = await reader.read();
          if (done) break;
          await pushPlain(value);
          reportProgress(e.meta.name, i + 1);
        }
      }
    } catch (err) {
      // Resource-cleanup bug found during a wider review: on any failure partway through
      // (a File no longer readable because it changed/was deleted after selection, a
      // QuotaExceededError writing to disk, etc.) this used to leave `writable` — an open
      // FileSystemWritableFileStream already holding data on disk — neither closed nor
      // aborted. The self.onmessage try/catch around runEncrypt() still reported the error
      // to the UI, but the partial file itself was left behind, sometimes with the browser
      // still holding a write lock on it until the tab/worker was gone. Abort it here (which
      // discards the partial write, matching what the cancellation path above already does)
      // before letting the error propagate to that same top-level handler.
      if (writable) { try { await writable.abort(); } catch (e2) {} }
      throw err;
    }
  }
  try {
    if (padRecord) {
      // crypto.getRandomValues() is capped at 65,536 bytes per call by every browser
      // (Web Crypto spec) — requesting more throws QuotaExceededError immediately. This loop
      // used to request up to 1 MiB per call, so any padding target above ~64KB (e.g. the
      // "Round size to 16MB" option) failed on the very first call (security review #8).
      const MAX_RANDOM_PER_CALL = 65536;
      await pushPlain(padRecord);
      let remaining = padSize;
      while (remaining > 0) {
        const take = Math.min(remaining, MAX_RANDOM_PER_CALL);
        await pushPlain(crypto.getRandomValues(new Uint8Array(take)));
        remaining -= take;
      }
    }
    await flushFinal();
  } catch (err) {
    if (writable) { try { await writable.abort(); } catch (e2) {} }
    throw err;
  }

  if (writable) {
    await writable.close();
    post({ type: 'done', mode: 'fsapi' });
  } else {
    post({ type: 'done', mode: 'blob', parts: blobParts }, blobParts.map(function (p) { return p.buffer; }));
  }
}

// ------------------------------------------------------------------ DECRYPT
async function runDecrypt(msg) {
  // msg: { containerFile, headerLength, chunkSizeMB, baseNonce, cekBytes, destDirHandle,
  //        totalCipherLen }
  const cekKey = await AnigmaContainer.importCekKey(msg.cekBytes);
  // Version-4 containers end with one 32-byte sender-authentication tag per recipient (not part of the
  // STREAM body). `trailerLen` is 0 for older containers, which have no such proof.
  const trailerLen = msg.trailerLen || 0;
  if (msg.containerFile.size < msg.headerLength + trailerLen) return post({ type: 'error', message: 'stream-truncated' });
  const bodyEnd = msg.containerFile.size - trailerLen;
  const body = msg.containerFile.slice(msg.headerLength, bodyEnd);
  const totalCipherLen = body.size;
  if (!Number.isInteger(msg.chunkSizeMB) || msg.chunkSizeMB < AnigmaContainer.MIN_CHUNK_MB || msg.chunkSizeMB > AnigmaContainer.MAX_CHUNK_MB) throw new Error('bad-chunk-size');
  const plan = AnigmaContainer.planCipherBlocks(totalCipherLen, msg.chunkSizeMB);

  if (trailerLen > 0) {
    // Check "this exact header + ciphertext was made by the claimed sender for ME" before a single byte
    // of plaintext is produced. Otherwise a co-recipient's rebuilt body (same content key) would be
    // decrypted and written out before the mismatch showed. Costs one extra read of the file.
    if (!msg.authKey || !(msg.wrapIndex >= 0)) return post({ type: 'error', message: 'sender-auth-failed' });
    const headerBytes = new Uint8Array(await AnigmaContainer.blobToBuffer(msg.containerFile.slice(0, msg.headerLength)));
    let h = await AnigmaContainer.bodyHashInit(headerBytes);
    for (const block of plan) {
      if (cancelled) return post({ type: 'cancelled' });
      const cb = new Uint8Array(await AnigmaContainer.blobToBuffer(msg.containerFile.slice(msg.headerLength + block.offset, msg.headerLength + block.offset + block.size)));
      h = await AnigmaContainer.bodyHashStep(h, block.counter, block.isLast, cb);
    }
    const tags = new Uint8Array(await AnigmaContainer.blobToBuffer(msg.containerFile.slice(bodyEnd, msg.containerFile.size)));
    const mine = tags.slice(msg.wrapIndex * AnigmaContainer.AUTH_TAG_SIZE, (msg.wrapIndex + 1) * AnigmaContainer.AUTH_TAG_SIZE);
    if (!(await AnigmaContainer.verifySenderAuthTag(msg.authKey, h, mine))) return post({ type: 'error', message: 'sender-auth-failed' });
  }

  const queue = AnigmaContainer.createByteQueue();
  const startTime = Date.now();
  let processed = 0;
  let lastReport = 0;
  function reportProgress(fileName) {
    const now = Date.now();
    if (now - lastReport < 120) return;
    lastReport = now;
    post({ type: 'progress', processed, total: totalCipherLen, fileName: fileName || '', elapsedMs: now - startTime });
  }

  // File-writing state machine: we may be mid-way through writing a file's data when a
  // decrypted chunk boundary falls inside it, so state persists across chunk iterations.
  let currentWriter = null; // { sink, decomp, name }
  let sawFinalFlag = false;
  const manifestList = [];
  const usingFsApi = !!msg.destDirHandle;

  // Finds a leaf name that doesn't already exist in dirHandle, appending " (1)", " (2)",
  // etc. before the extension — same convention browsers use for downloads. Bounded at 999
  // attempts so a pathological package (or directory) can't spin forever.
  async function uniqueLeafName(dirHandle, leaf) {
    async function exists(name) {
      try { await dirHandle.getFileHandle(name, { create: false }); return true; }
      catch (e) { return false; }
    }
    if (!(await exists(leaf))) return leaf;
    const dot = leaf.lastIndexOf('.');
    const base = dot > 0 ? leaf.slice(0, dot) : leaf;
    const ext = dot > 0 ? leaf.slice(dot) : '';
    for (let i = 1; i <= 999; i++) {
      const candidate = base + ' (' + i + ')' + ext;
      if (!(await exists(candidate))) return candidate;
    }
    // Astronomically unlikely, but never loop forever — fall back to a random suffix.
    return base + ' (' + Date.now().toString(36) + ')' + ext;
  }

  // Security review #3b: a compressed file's stored (compressed) length is small, but the
  // decompressed output has no size limit at all — a crafted package can expand a package a
  // few hundred KB in size into hundreds of MB or more (a "decompression bomb"), all before
  // any size warning fires, because that warning is computed from the PACKAGE size, not the
  // eventual decompressed size. Cap actual decompressed bytes per file, independent of
  // whatever the (unauthenticated) 'size' field in the file's own header claims.
  const MAX_DECOMPRESSED_BYTES_PER_FILE = 512 * 1024 * 1024; // 512 MiB — generous for normal use, finite in the worst case
  // ...and a cap across ALL files of one package, since many small bombs add up just as well.
  const MAX_DECOMPRESSED_BYTES_TOTAL = 4 * 1024 * 1024 * 1024; // 4 GiB
  let decompressedTotal = 0;

  async function openWriterFor(meta) {
    if (meta.pad) return null; // padding: bytes are simply discarded, nothing to write
    if (msg.previewOnly) return null;
    // Security review #2: sanitizeRelativePath() was only ever called on the ENCRYPT side
    // (worker.js's runEncrypt, via container.js). A package's per-file name is plaintext,
    // unauthenticated JSON that travels inside the encrypted body but is never checked
    // against the recipient's own identity — a malicious *or* corrupted package could carry
    // '../../elsewhere/file' (path traversal, on browsers without the File System Access
    // API — every mobile browser today) or otherwise-dangerous names. Reject the same way
    // encryption already does, rather than trusting a name that only ever passed through
    // the sender's copy of this check.
    const safeName = AnigmaContainer.sanitizeRelativePath(meta.name);
    let sink;
    if (usingFsApi) {
      const parts = safeName.split('/');
      let dirHandle = msg.destDirHandle;
      for (let i = 0; i < parts.length - 1; i++) {
        dirHandle = await dirHandle.getDirectoryHandle(parts[i], { create: true });
      }
      // getFileHandle({create:true}) silently truncates an existing file with the same
      // name (security review #2). The worker has no UI to ask "overwrite?", so instead of
      // either silently destroying an existing file or blocking the whole decrypt on a
      // round-trip to the main thread, auto-rename the way browser downloads do: "name.ext"
      // -> "name (1).ext" -> "name (2).ext" ... The manifest (shown to the user before this
      // point, and in the 'file' progress messages) still reports the package's original
      // name, so nothing is hidden — only silent data loss is avoided.
      const finalLeaf = await uniqueLeafName(dirHandle, parts[parts.length - 1]);
      const fileHandle = await dirHandle.getFileHandle(finalLeaf, { create: true });
      const writable = await fileHandle.createWritable();
      sink = {
        write: function (b) { return writable.write(b); },
        close: function () { return writable.close(); },
        // Used only on tamper/truncation/cancellation, never on success: abort() discards
        // whatever was written instead of finalizing it, so a failed decrypt never leaves
        // behind a file that *looks* complete but is actually truncated/corrupted data.
        abort: function () { return writable.abort(); }
      };
    } else {
      // No destination folder handle — either the browser has no File System Access API
      // at all (every mobile browser today) or the caller chose not to use it. Buffer
      // this file's decrypted bytes in memory instead and hand them back to the main
      // thread as one message per finished file, so it can offer them as a download
      // (single file) or bundle them into a .zip (several files) — either way, decrypt
      // still works instead of being unavailable outside desktop Chromium/Edge.
      const memParts = []; let memTotal = 0;
      sink = {
        write: function (b) { memParts.push(b); memTotal += b.length; return Promise.resolve(); },
        close: function () {
          const out = new Uint8Array(memTotal);
          let off = 0;
          for (const p of memParts) { out.set(p, off); off += p.length; }
          post({ type: 'file', name: safeName, bytes: out }, [out.buffer]);
          return Promise.resolve();
        },
        // Discard silently: on error there is no destination handle to abort, and posting
        // a 'file' message with partial/unauthenticated bytes here would let a failed
        // (tampered/truncated) decrypt still hand the caller data as if it were trustworthy.
        abort: function () { memParts.length = 0; memTotal = 0; return Promise.resolve(); }
      };
    }
    let decomp = null;
    if (meta.compressed) {
      if (!AnigmaContainer.deflateRawSupported()) throw new Error('compression-unsupported');
      decomp = new DecompressionStream('deflate-raw');
      pumpDecompression(decomp, sink); // fire-and-forget pump; awaited via closeWriter
    }
    return { sink: sink, decomp: decomp, name: safeName };
  }

  // Pipes a DecompressionStream's output into the destination sink in the background.
  // Enforces MAX_DECOMPRESSED_BYTES_PER_FILE (security review #3b, decompression bomb).
  function pumpDecompression(decomp, sink) {
    const reader = decomp.readable.getReader();
    let total = 0;
    async function pump() {
      while (true) {
        const { done, value } = await reader.read();
        if (done) return;
        total += value.length;
        decompressedTotal += value.length;
        if (total > MAX_DECOMPRESSED_BYTES_PER_FILE || decompressedTotal > MAX_DECOMPRESSED_BYTES_TOTAL) {
          await reader.cancel('decompression-bomb').catch(function () {});
          throw new Error('decompression-bomb');
        }
        await sink.write(value);
      }
    }
    decomp._pumpPromise = pump();
  }

  async function writeToCurrent(state, bytes) {
    if (!state) return; // padding
    if (state.decomp) {
      const w = state.decomp.writable.getWriter();
      await w.write(bytes);
      w.releaseLock();
    } else {
      await state.sink.write(bytes);
    }
  }

  async function closeWriter(state) {
    if (!state) return;
    if (state.decomp) {
      await state.decomp.writable.getWriter().close().catch(function () {});
      await state.decomp._pumpPromise;
    }
    await state.sink.close();
  }

  // Error-path counterpart to closeWriter(): used when a file was left mid-write by a
  // tamper/truncation error or a cancellation, where the correct outcome is discarding
  // that partial data, not finalizing it as if it were a complete, trustworthy file.
  async function abortWriter(state) {
    if (!state) return;
    if (state.decomp) {
      await state.decomp.writable.getWriter().abort().catch(function () {});
      await state.decomp._pumpPromise.catch(function () {});
    }
    await state.sink.abort();
  }

  // Holds a peeked-but-not-yet-consumed 4-byte length prefix when the queue doesn't yet
  // have the full JSON header that follows it.
  const MAX_RECORD_JSON_BYTES = 64 * 1024; // real per-file metadata is a few dozen bytes at most
  let peekedLen = null;
  let pendingMeta = null; // {meta, remaining}
  async function drainRecords() {
    while (true) {
      if (!pendingMeta) {
        if (peekedLen === null) {
          const lenBytes = queue.readExact(4);
          if (!lenBytes) return;
          peekedLen = AnigmaContainer.readU32be(lenBytes, 0);
          // A legitimate encoder never writes a record header this large (security review
          // #3, same family as the missing-`stored` bug below): reject up front rather than
          // stalling drainRecords until enough ciphertext has arrived to even attempt it.
          if (peekedLen > MAX_RECORD_JSON_BYTES) throw new Error('stream-tampered');
        }
        const jsonBytes = queue.readExact(peekedLen);
        if (!jsonBytes) return; // wait for more chunks; peekedLen is retained
        peekedLen = null;
        let meta;
        try { meta = JSON.parse(new TextDecoder().decode(jsonBytes)); }
        catch (e) { throw new Error('stream-tampered'); }
        // Security review #3a: a record missing (or lying about) `stored` used to become
        // `pendingMeta.remaining = NaN`. `NaN === 0` is false and `Math.min(NaN, n)` is
        // NaN, which is also not `=== 0`, so the loop below never terminated and never took
        // any bytes either — an infinite spin that pegs a CPU core and grows the queue
        // forever (observed: ~2GB heap / OOM within seconds on a malicious package).
        // Validate every field this code actually depends on before trusting it.
        const nameOk = meta.pad ? true : (typeof meta.name === 'string' && meta.name.length > 0);
        const storedOk = Number.isInteger(meta.stored) && meta.stored >= 0;
        if (!nameOk || !storedOk) throw new Error('stream-tampered');
        if (!meta.pad) manifestList.push({ name: meta.name, size: meta.size, compressed: !!meta.compressed });
        pendingMeta = { meta, remaining: meta.stored };
        currentWriter = await openWriterFor(meta);
        reportProgress(meta.name);
      }
      if (pendingMeta.remaining === 0) {
        await closeWriter(currentWriter);
        currentWriter = null; pendingMeta = null;
        continue;
      }
      const take = Math.min(pendingMeta.remaining, queue.length);
      if (take === 0) return;
      const bytes = queue.readExact(take);
      await writeToCurrent(currentWriter, bytes);
      pendingMeta.remaining -= take;
      if (pendingMeta.remaining === 0) {
        await closeWriter(currentWriter);
        currentWriter = null; pendingMeta = null;
      }
    }
  }

  for (const block of plan) {
    if (cancelled) { if (currentWriter) { try { await abortWriter(currentWriter); } catch (e2) {} } return post({ type: 'cancelled' }); }
    const cipherBytes = new Uint8Array(await AnigmaContainer.blobToBuffer(msg.containerFile.slice(msg.headerLength + block.offset, msg.headerLength + block.offset + block.size)));
    let plain;
    try {
      plain = await AnigmaContainer.decryptChunk(cekKey, msg.baseNonce, block.counter, block.isLast, cipherBytes);
    } catch (e) {
      // Resource-cleanup bug found during a wider review: tamper detection used to `return`
      // immediately here, leaving `currentWriter` (an open FileSystemWritableFileStream —
      // and, for a compressed file, its DecompressionStream pump) neither closed nor
      // aborted whenever tampering was detected partway through writing a file. The UI still
      // correctly reported the error, but the partial file on disk was left behind with a
      // write lock the browser might hold until the tab/worker was gone — and worse,
      // `closeWriter()` finalizes a file rather than discarding it, so using that here would
      // have left a corrupted file that *looks* complete. `abortWriter()` discards it
      // instead (best-effort: not worth failing the already-failed operation over a
      // secondary abort error).
      if (currentWriter) { try { await abortWriter(currentWriter); } catch (e2) {} }
      return post({ type: 'error', message: 'stream-tampered' });
    }
    if (block.isLast) sawFinalFlag = true;
    queue.push(plain);
    processed += block.size;
    try {
      await drainRecords();
    } catch (err) {
      // Any failure while writing records (bad name, decompression bomb, corrupt deflate data,
      // disk error) must discard the half-written file, not leave it open/finalized.
      if (currentWriter) { try { await abortWriter(currentWriter); } catch (e2) {} currentWriter = null; }
      throw err;
    }
    reportProgress();
  }

  if (!sawFinalFlag || pendingMeta || peekedLen !== null) {
    // The stream ended without ever authenticating a lastFlag=1 chunk, ended mid-record, or
    // ended with an unconsumed length prefix waiting on a JSON header that never fully
    // arrived: treat all three as a truncated/tampered package, never as a silently short
    // result. Same cleanup note as the tamper-detection catch above: `currentWriter` may
    // still be open here (mid-file when the stream ran out), and abortWriter() (not
    // closeWriter()) is what correctly discards it instead of finalizing a truncated file.
    if (currentWriter) { try { await abortWriter(currentWriter); } catch (e2) {} }
    return post({ type: 'error', message: 'stream-truncated' });
  }

  if (msg.previewOnly) post({ type: 'manifest', files: manifestList });
  else post({ type: 'done' });
}
