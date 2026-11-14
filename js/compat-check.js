// ====================================================================================
// js/compat-check.js — loaded FIRST, written in plain ES5 on purpose so even a very old browser can run it.
// If the browser lacks what Anigma needs (the Web Crypto algorithms, local storage, ...), or if the app's own scripts
// fail to start (a syntax error in a browser that is too old), it shows a clear message instead of a half-working page.
// It never blocks a capable browser and sends nothing anywhere.
// ====================================================================================
(function () {
  'use strict';
  var shown = false;

  function lang() {
    try { var l = window.localStorage.getItem('anigma_lang'); if (l) return l === 'fa' ? 'fa' : 'en'; } catch (e) { /* ignore */ }
    var n = (navigator.language || navigator.userLanguage || '').toLowerCase();
    return n.indexOf('fa') === 0 ? 'fa' : 'en';
  }
  var TEXT = {
    fa: {
      title: 'این مرورگر برای اجرای آنیگما مناسب نیست',
      body: 'آنیگما برای رمزنگاری به قابلیت‌های امنیتی مرورگر نیاز دارد که در این مرورگر یا این نسخه از آن پیدا نشد. لطفاً با یکی از این مرورگرها (به‌روز) باز کنید: Chrome یا Edge نسخهٔ ۸۸ به بالا، Firefox نسخهٔ ۷۸ به بالا، Safari نسخهٔ ۱۴٫۱ به بالا (آیفون: iOS ۱۴٫۵ به بالا).',
      https: 'اگر این صفحه را با آدرس http (نه https) باز کرده‌اید، مرورگر قابلیت‌های رمزنگاری را غیرفعال می‌کند؛ آدرس باید با https شروع شود.',
      reason: 'جزئیات فنی: ',
      soft: 'مرورگر شما قدیمی است؛ آنیگما کار می‌کند ولی ممکن است ظاهرش کمی به‌هم بریزد. برای بهترین تجربه مرورگر را به‌روز کنید.',
      close: 'متوجه شدم',
      noscript: 'آنیگما برای کار کردن به جاوااسکریپت نیاز دارد. لطفاً آن را در مرورگر فعال کنید.'
    },
    en: {
      title: 'This browser can\u2019t run Anigma',
      body: 'Anigma needs security features of the browser (for encryption) that this browser or version does not have. Please open it in an up-to-date browser: Chrome or Edge 88+, Firefox 78+, or Safari 14.1+ (iPhone: iOS 14.5+).',
      https: 'If this page was opened with an http:// address (not https://), the browser turns the encryption features off; the address must start with https://.',
      reason: 'Technical detail: ',
      soft: 'Your browser is quite old. Anigma works, but some parts may look slightly off. Update your browser for the best experience.',
      close: 'Got it',
      noscript: 'Anigma needs JavaScript to work. Please enable it in your browser.'
    }
  };

  function el(tag, text, css) {
    var e = document.createElement(tag);
    if (text) e.textContent = text;
    if (css) for (var k in css) { if (Object.prototype.hasOwnProperty.call(css, k)) e.style[k] = css[k]; }
    return e;
  }

  function block(reason) {
    if (shown) return; shown = true;
    var L = lang(), T = TEXT[L];
    function paint() {
      var o = el('div', '', { position: 'fixed', top: '0', right: '0', bottom: '0', left: '0', zIndex: '2147483647', background: '#050b1a', color: '#e8f1ff',
        display: 'flex', alignItems: 'center', justifyContent: 'center', padding: '24px', fontFamily: 'system-ui, -apple-system, "Segoe UI", Tahoma, sans-serif' });
      o.setAttribute('dir', L === 'fa' ? 'rtl' : 'ltr');
      o.setAttribute('role', 'alertdialog');
      o.id = 'anigmaCompatOverlay';
      var box = el('div', '', { maxWidth: '520px', lineHeight: '1.9', textAlign: L === 'fa' ? 'right' : 'left' });
      box.appendChild(el('h1', T.title, { fontSize: '22px', margin: '0 0 12px', color: '#35b4ff' }));
      box.appendChild(el('p', T.body, { margin: '0 0 12px' }));
      box.appendChild(el('p', T.https, { margin: '0 0 12px', opacity: '.8', fontSize: '14px' }));
      if (reason) box.appendChild(el('p', T.reason + reason, { margin: '0', opacity: '.55', fontSize: '12px', direction: 'ltr', textAlign: 'left' }));
      o.appendChild(box);
      document.body.appendChild(o);
    }
    if (document.body) paint(); else document.addEventListener('DOMContentLoaded', paint);
  }

  function soft() {
    var L = lang(), T = TEXT[L];
    function paint() {
      var b = el('div', T.soft, { position: 'fixed', left: '0', right: '0', bottom: '0', zIndex: '2147483000', background: '#f2b84b', color: '#1a1200',
        padding: '10px 16px', fontSize: '14px', textAlign: 'center', fontFamily: 'system-ui, -apple-system, "Segoe UI", Tahoma, sans-serif' });
      b.setAttribute('dir', L === 'fa' ? 'rtl' : 'ltr');
      b.id = 'anigmaCompatSoft';
      var x = el('button', T.close, { marginInlineStart: '12px', marginLeft: '12px', border: '0', borderRadius: '6px', padding: '4px 10px', cursor: 'pointer' });
      x.onclick = function () { if (b.parentNode) b.parentNode.removeChild(b); };
      b.appendChild(x); document.body.appendChild(b);
    }
    if (document.body) paint(); else document.addEventListener('DOMContentLoaded', paint);
  }

  // ---- synchronous basics (anything missing here is fatal) ----
  var miss = [];
  if (typeof Promise === 'undefined') miss.push('Promise');
  if (typeof Uint8Array === 'undefined') miss.push('Uint8Array');
  if (typeof TextEncoder === 'undefined') miss.push('TextEncoder');
  if (typeof Blob === 'undefined' || !window.URL || typeof URL.createObjectURL !== 'function') miss.push('Blob/URL');
  try { window.localStorage.setItem('anigma_probe', '1'); window.localStorage.removeItem('anigma_probe'); } catch (e) { miss.push('localStorage'); }
  var subtle = window.crypto && (window.crypto.subtle || window.crypto.webkitSubtle);
  if (!window.crypto || typeof window.crypto.getRandomValues !== 'function') miss.push('getRandomValues');
  if (!subtle) miss.push(window.isSecureContext === false ? 'crypto.subtle (insecure context)' : 'crypto.subtle');
  if (miss.length) { block(miss.join(', ')); return; }

  // ---- the algorithms the app really uses (a quick probe, a few milliseconds) ----
  function probe(name, fn) { return fn().then(null, function (e) { throw new Error(name + (e && e.name ? ' (' + e.name + ')' : '')); }); }
  var p = probe('ECDH P-256', function () { return subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, false, ['deriveBits']); })
    .then(function () { return probe('AES-GCM', function () { return subtle.generateKey({ name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']); }); })
    .then(function () { return probe('HKDF', function () { return subtle.importKey('raw', new Uint8Array(32), 'HKDF', false, ['deriveBits']); }); })
    .then(function () { return probe('PBKDF2', function () { return subtle.importKey('raw', new Uint8Array(8), 'PBKDF2', false, ['deriveBits']); }); });
  p.then(null, function (e) { block(e && e.message ? e.message : 'webcrypto'); });

  // ---- soft check: a browser that predates modern CSS still works, but may look a little off ----
  try {
    if (window.CSS && typeof CSS.supports === 'function' && !CSS.supports('inset', '0')) { if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', soft); else soft(); }
  } catch (e2) { /* ignore */ }

  // ---- if the app's own scripts never finished starting (e.g. a syntax error in a too-old browser), say so ----
  window.setTimeout(function () { if (!window.__anigmaBooted) block('app scripts did not start'); }, 8000);
})();
