// ====================================================================================
// ANIGMA — service-worker.js
// Cache-first offline support. The cache name is versioned so a new deployment gets a
// fresh cache; the old one is removed on activate so nobody gets stuck on a stale build.
//
// Integrity check: the ten files below are hash-pinned to the exact bytes shipped with
// this version (see tools/compute-integrity.js, run once at build time). If a fetch
// during install returns something that doesn't match, install is aborted rather than
// silently caching — and later serving offline, indefinitely — a file that isn't what
// this version shipped. This defends against a *persistent* compromise discovered after
// this version was built (e.g. a compromised host quietly serving a modified crypto.js on
// some later request); it cannot detect a compromise that was already present when these
// hashes were generated — nothing self-referential can — so an honest build pipeline is
// still where real integrity starts.
// ====================================================================================

const CACHE_NAME = 'anigma-v39';

const INTEGRITY = {
  'js/crypto.js': '8b39895b6ed93548ca141a07339b62d184fea34c12c201fcff1354028b81936a',
  'js/container.js': '4f0be6e5a03de119b62073d9640f47f243abed9ac6ddee35dbfa13a8cb45e2c8',
  'js/worker.js': 'c04d916590a143aec83786d4a6ef89f904e519aab04d1ddee2422903cbe4d30f',
  'js/groups.js': '51f66061ae70d0a20542d98b14caf6a69e6ced19cab0f2c6e7014867ce2fec9c',
  'js/update.js': '6c6cf1f7f2b47db23c6735f0c623eab97cd983cdbd0583d37fbfd2599e1d6d04',
  'js/ui.js': 'c8087f81f4b62ecba0cee02be4e79bf27569fce998b2687af3d02430fcc22618',
  'js/groups-ui.js': '643cf9ead6b183d0f79812a8b62a07cb30077f5aca053c652b6e422763f65cd2',
  'js/i18n.js': '7224947740745a0fe3b2dc2ad084effd20ddcc083e8127dd70c49226e3532103',
  'css/app.css': '4756822e4703a6e830962a8619e4977866820c1bcb043f421d389eb3f3d057ad',
  'js/compat-check.js': '00c4ee345a37bdb614fc9567e36e809c05c3664b6bcbc7e552e2c21ef05fa2b4',
  'js/argon2-client.js': '63859ffefe06391682c132176e6191514586716214c5a0a513668833b566dfcb',
  'vendor/argon2id.js': 'bcb46968af88cd4af4e490e7daeabc9f84daf36eccbff1f98ea9041e21f9f073',
  'vendor/qrcode.min.js': '121fc385aab932ff749318b4dcec1482ec1ae2f357572981e2ed5da6431f2374',
  'index.html': '0d2f90cb456ba04593b0b4f0879421c62cbae84d9c904037d09096104b52d959'
};

// Everything else in the app shell (manifest, icons) is still cached for offline use, just
// not hash-pinned — none of it is executable script or defines/carries the CSP, so tamper
// risk there is materially lower and not worth the maintenance cost of pinning.
const APP_SHELL_REST = [
  'manifest.webmanifest',
  'icons/icon-192.png',
  'icons/icon-512.png',
  'icons/icon-192-maskable.png',
  'icons/icon-512-maskable.png',
  'icons/apple-touch-icon.png',
  'icons/favicon-32.png',
  'fonts/Vazirmatn-Variable.woff2'
];

async function sha256Hex(buf) {
  const digest = await crypto.subtle.digest('SHA-256', buf);
  return Array.from(new Uint8Array(digest)).map(function (b) { return b.toString(16).padStart(2, '0'); }).join('');
}

async function notifyClients(message) {
  const clients = await self.clients.matchAll({ includeUncontrolled: true });
  clients.forEach(function (c) { c.postMessage(message); });
}

self.addEventListener('install', function (event) {
  event.waitUntil(
    (async function () {
      const cache = await caches.open(CACHE_NAME);
      for (const path of Object.keys(INTEGRITY)) {
        const resp = await fetch(path, { cache: 'no-store' });
        if (!resp.ok) throw new Error('fetch failed for ' + path);
        const buf = await resp.clone().arrayBuffer();
        const hex = await sha256Hex(buf);
        if (hex !== INTEGRITY[path]) throw new Error('hash mismatch for ' + path);
        await cache.put(path, resp);
      }
      // './' is the SAME document as index.html (it defines the CSP and loads every script), and
      // a navigation to the site root is matched against THIS cache entry, not the 'index.html'
      // one. It used to be cached unverified, which bypassed the pin above. Require its bytes to
      // equal the pinned index.html, or abort the install like any other mismatch.
      const rootResp = await fetch('./', { cache: 'no-store' });
      if (!rootResp.ok) throw new Error('fetch failed for ./');
      const rootHex = await sha256Hex(await rootResp.clone().arrayBuffer());
      if (rootHex !== INTEGRITY['index.html']) throw new Error('hash mismatch for ./');
      await cache.put('./', rootResp);
      await cache.addAll(APP_SHELL_REST);
    })().catch(function (err) {
      // An aborted install means the browser keeps whatever service worker (and cache) it
      // already had, if any — this file's changes simply never take effect. Say so loudly
      // rather than fail silently offline; the page itself is still running fine from the
      // network regardless, since it isn't this same-origin fetch that loaded it.
      notifyClients({ type: 'INTEGRITY_FAILURE', detail: String((err && err.message) || err) });
      throw err;
    })
  );
});

self.addEventListener('activate', function (event) {
  event.waitUntil(
    caches.keys().then(function (names) {
      return Promise.all(names.filter(function (n) { return n !== CACHE_NAME; }).map(function (n) { return caches.delete(n); }));
    }).then(function () { return self.clients.claim(); })
  );
});

// Cache-first: once installed, nothing requires the network at all. A same-origin GET
// that isn't cached yet falls back to the network and is cached for next time (this only
// matters right after a deploy, before the new cache is fully warmed).
self.addEventListener('fetch', function (event) {
  if (event.request.method !== 'GET') return;
  const url = new URL(event.request.url);
  if (url.origin !== self.location.origin) return;

  event.respondWith(
    caches.match(event.request).then(function (cached) {
      if (cached) return cached;
      return fetch(event.request).then(function (response) {
        if (response && response.ok) {
          const copy = response.clone();
          caches.open(CACHE_NAME).then(function (cache) { cache.put(event.request, copy); });
        }
        return response;
      }).catch(function () { return cached; });
    })
  );
});

// Lets the page's "a new version is ready — reload" banner trigger the swap immediately
// instead of waiting for every tab to close.
self.addEventListener('message', function (event) {
  if (event.data && event.data.type === 'SKIP_WAITING') self.skipWaiting();
});
