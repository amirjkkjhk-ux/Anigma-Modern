// ====================================================================================
// ANIGMA — js/argon2-client.js  (main thread only)
// Connects the vendored Argon2id (vendor/argon2id.js, @noble/hashes) to AnigmaCrypto.deriveMasterKey.
//
//  * The computation runs in a Web Worker built from the SAME text that is embedded in index.html
//    (<script type="text/plain" id="workerBundleArgon2">) — a Blob worker, so it also works when the app is
//    opened straight from a file (file://) where `new Worker('some.js')` is refused. Each call uses a fresh
//    worker that is terminated afterwards, so the 128 MiB it allocates is given back immediately.
//  * If a Worker cannot be created at all, it falls back to running the same code on the main thread
//    (the page is unresponsive for a couple of seconds, but it works).
//  * Out-of-memory is reported as Error('argon2id-memory'), never as "wrong password".
//  * The 32 raw output bytes become a NON-extractable AES-GCM CryptoKey and are zeroed right away.
// ====================================================================================
(function () {
  'use strict';
  const BUNDLE_ELEMENT_ID = 'workerBundleArgon2';

  function runInWorker(passBytes, saltBytes, params) {
    return new Promise(function (resolve, reject) {
      let url = null, w = null, done = false;
      function finish(fn, val) { if (done) return; done = true; try { if (w) w.terminate(); } catch (e) { /* ignore */ } if (url) { try { URL.revokeObjectURL(url); } catch (e2) { /* ignore */ } } fn(val); }
      try {
        const el = typeof document !== 'undefined' ? document.getElementById(BUNDLE_ELEMENT_ID) : null;
        if (!el || typeof Worker === 'undefined' || typeof Blob === 'undefined') { reject(new Error('no-worker')); return; }
        url = URL.createObjectURL(new Blob([el.textContent], { type: 'text/javascript' }));
        w = new Worker(url);
      } catch (e) { finish(reject, new Error('no-worker')); return; }
      w.onmessage = function (ev) {
        const d = ev.data || {};
        if (d.ok) finish(resolve, new Uint8Array(d.key));
        else finish(reject, new Error(d.err === 'argon2id-memory' ? 'argon2id-memory' : 'argon2id-failed'));
      };
      w.onerror = function () { finish(reject, new Error('no-worker')); };
      w.postMessage({ id: 1, pass: passBytes, salt: saltBytes, m: params.m, t: params.t, p: params.p });
    });
  }

  async function rawArgon2id(passBytes, saltBytes, params) {
    try {
      return await runInWorker(passBytes, saltBytes, params);
    } catch (e) {
      if (!e || e.message !== 'no-worker') throw e;
    }
    // No Worker available: same code, main thread.
    if (typeof self.AnigmaArgon2idRaw !== 'function') throw new Error('argon2id-unavailable');
    try { return self.AnigmaArgon2idRaw(passBytes, saltBytes, params.m, params.t, params.p); }
    catch (err) {
      const msg = String(err && err.message || err);
      throw new Error((err && err.name === 'RangeError') || /allocation|memory|array buffer/i.test(msg) ? 'argon2id-memory' : 'argon2id-failed');
    }
  }

  // Contract used by AnigmaCrypto.deriveMasterKey: (normalised passphrase, salt, {m,t,p}) -> AES-GCM CryptoKey.
  self.AnigmaArgon2idKDF = async function (pass, saltBytes, params) {
    const passBytes = new TextEncoder().encode(pass);
    const salt = new Uint8Array(saltBytes);
    const raw = await rawArgon2id(passBytes, salt, params);
    try {
      return await crypto.subtle.importKey('raw', raw, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
    } finally { raw.fill(0); passBytes.fill(0); }
  };
})();
