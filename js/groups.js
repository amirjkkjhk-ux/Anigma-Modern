// ====================================================================================
// ANIGMA — groups.js
// Group encryption with member revocation: a Broadcast-Encryption "Complete Subtree"
// (CS) scheme over a complete binary key tree. Implements sections 1-5 of
// docs/groups-spec-v1.md — key tree, signed group card, per-member invite package,
// covering-set algorithm, and group-message wrap/unwrap. No UI lives here.
//
// This file only COMPOSES existing primitives: every key agreement / message wrap goes
// through AnigmaCrypto (js/crypto.js, unchanged), and signatures use the browser's native
// Web Crypto (ECDSA P-256). Nothing cryptographic is implemented by hand. The bulk
// payload (message or file) is still encrypted by container.js/crypto.js under a random
// CEK exactly as before; this module only decides WHO can recover that CEK.
//
// Loading: like crypto.js/container.js this is a plain browser script (IIFE assigned to a
// top-level `const`), loaded before use by <script> or, in tests, by vm.runInThisContext
// (see tests/env-shim.js and tests/crypto.test.js). AnigmaCrypto must already be loaded.
// A CommonJS `module.exports` hook at the bottom additionally makes `require('./groups.js')`
// work in Node, provided AnigmaCrypto is on globalThis.
// ====================================================================================

const AnigmaGroups = (function () {
  'use strict';

  const CARD_FORMAT_VERSION = 1;   // `v` field of cards and invite packages
  const CEK_LEN = 32;              // bytes; matches the container's 256-bit content key
  const NODE_PUB_LEN = 65;         // raw uncompressed P-256 point (spec section 1)
  const MAX_CAPACITY = 1024;       // sanity cap only; the product uses 32 / 64 / 128 (spec 1)

  // Why ECDSA P-256 and not Ed25519 (which the spec's `managerSigPub` also allows):
  // Ed25519 in Web Crypto is still not uniformly supported across browsers (crypto.js
  // has to feature-detect X25519 for the same reason), while ECDSA P-256 is available
  // everywhere and shares the curve already used for every tree node. A signature that
  // some users' browsers cannot verify would silently lock them out of the group.
  const SIG_KEY_ALGO = { name: 'ECDSA', namedCurve: 'P-256' };
  const SIG_ALGO = { name: 'ECDSA', hash: 'SHA-256' };
  const NODE_KEY_ALGO = { name: 'ECDH', namedCurve: 'P-256' };

  // ------------------------------------------------------------------ small helpers
  // AnigmaCrypto is resolved lazily (at call time, not at load time) so the load order of
  // the two scripts never matters, and a missing dependency fails with a clear error.
  function C() {
    if (typeof AnigmaCrypto !== 'undefined') return AnigmaCrypto;
    if (typeof globalThis !== 'undefined' && globalThis.AnigmaCrypto) return globalThis.AnigmaCrypto;
    throw new Error('groups-crypto-missing');
  }

  // Accepts ArrayBuffer or any typed-array view and returns a Uint8Array over the same bytes.
  function toBytes(x) {
    if (x instanceof Uint8Array) return x;
    if (x instanceof ArrayBuffer) return new Uint8Array(x);
    if (ArrayBuffer.isView(x)) return new Uint8Array(x.buffer, x.byteOffset, x.byteLength);
    throw new Error('groups-bad-bytes');
  }

  // base64url (no padding): used only for groupId, which the spec asks for in that form.
  // Everything else is standard base64 via AnigmaCrypto.bufToB64, like the rest of the app.
  function bytesToB64Url(bytes) {
    return C().bufToB64(bytes).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  }

  function randomBytes(n) {
    return crypto.getRandomValues(new Uint8Array(n));
  }

  // ------------------------------------------------------------------ section 1: heap-indexed tree
  // Why heap indexing (1-based array): a node's parent is `i >> 1` and its children are
  // `2i` / `2i+1`, so the path from any leaf to the root is computable from the leaf
  // number alone — no pointers, no stored structure, and the card's `nodePub` array
  // doubles as the tree. Root = 1; with capacity N the leaves are [N, 2N-1].
  function isValidCapacity(n) {
    // A complete binary tree needs a power of two. The spec fixes 32/64/128 for the
    // product; the engine accepts any power of two >= 2 so tests can use tiny trees.
    return Number.isInteger(n) && n >= 2 && n <= MAX_CAPACITY && (n & (n - 1)) === 0;
  }

  function isLeafIndex(capacity, i) {
    return Number.isInteger(i) && i >= capacity && i <= 2 * capacity - 1;
  }

  // Node ids from the leaf up to the root, e.g. capacity 64, leaf 66 -> [66,33,16,8,4,2,1].
  function getPathNodeIds(capacity, leafIndex) {
    if (!isValidCapacity(capacity)) throw new Error('groups-bad-capacity');
    if (!isLeafIndex(capacity, leafIndex)) throw new Error('groups-bad-leaf');
    const ids = [];
    for (let i = leafIndex; i >= 1; i = i >> 1) ids.push(i);
    return ids;
  }

  // Validates and normalizes a revoked-leaf list: integers in the leaf range, de-duplicated,
  // sorted ascending (so the card — and therefore its signature — has one canonical form).
  function normalizeRevoked(capacity, revokedLeaves) {
    if (revokedLeaves === undefined || revokedLeaves === null) return [];
    if (!Array.isArray(revokedLeaves)) throw new Error('groups-bad-revoked-leaf');
    const set = new Set();
    for (const leaf of revokedLeaves) {
      if (!isLeafIndex(capacity, leaf)) throw new Error('groups-bad-revoked-leaf');
      set.add(leaf);
    }
    return Array.from(set).sort(function (a, b) { return a - b; });
  }

  // Every node (internal ones too) gets its own independent ECDH P-256 key pair, generated
  // through AnigmaCrypto so the raw 65-byte public format is exactly what the rest of the
  // code consumes. The returned tree holds ALL private keys: it is creator-device state
  // and must never be shared or exported whole (spec section 1). Only the public halves
  // leave the device, inside the signed card.
  async function createTree(capacity) {
    if (!isValidCapacity(capacity)) throw new Error('groups-bad-capacity');
    const nodes = new Array(2 * capacity); // index 0 unused: heap indexing is 1-based
    nodes[0] = null;
    await Promise.all(Array.from({ length: 2 * capacity - 1 }, async function (_, k) {
      const id = k + 1;
      const kp = await C().generateEphemeralKeyPair('P-256');
      const pubRaw = new Uint8Array(await crypto.subtle.exportKey('raw', kp.publicKey));
      nodes[id] = { priv: kp.privateKey, pubRaw: pubRaw };
    }));
    return {
      v: CARD_FORMAT_VERSION,
      // Stable for the life of the group: revocations change the card, never the tree.
      groupId: bytesToB64Url(randomBytes(16)),
      capacity: capacity,
      nodes: nodes
    };
  }

  function assertTree(tree) {
    if (!tree || typeof tree !== 'object' || typeof tree.groupId !== 'string' ||
        !isValidCapacity(tree.capacity) || !Array.isArray(tree.nodes) ||
        tree.nodes.length !== 2 * tree.capacity) {
      throw new Error('groups-bad-tree');
    }
  }

  // ------------------------------------------------------------------ section 4: covering set
  // Complete Subtree method. A revoked leaf must be excluded, but every other leaf must
  // stay covered by as few node keys as possible. Mark every node on a path from a revoked
  // leaf to the root (the "Steiner tree" of the revoked set); the cover is then every
  // UNMARKED child of a marked node. Those subtrees are disjoint, contain no revoked leaf,
  // and together contain every non-revoked leaf. Each member holds the keys of its own
  // leaf-to-root path, and exactly one of its path nodes lies in the cover — so it can
  // decrypt one wrap, while a revoked leaf (all of whose path nodes are marked) cannot.
  // Cover size is at most r * log2(N/r) for r revoked leaves.
  //   no revocations -> [1] (just the root); everything revoked -> [].
  function computeCoveringSet(capacity, revokedLeaves) {
    if (!isValidCapacity(capacity)) throw new Error('groups-bad-capacity');
    const revoked = normalizeRevoked(capacity, revokedLeaves);
    if (revoked.length === 0) return [1];

    const marked = new Set();
    for (const leaf of revoked) {
      for (let i = leaf; i >= 1; i = i >> 1) {
        if (marked.has(i)) break; // everything above is already marked
        marked.add(i);
      }
    }

    const cover = [];
    marked.forEach(function (i) {
      if (i >= capacity) return; // a revoked leaf has no children
      const left = 2 * i, right = 2 * i + 1;
      if (!marked.has(left)) cover.push(left);
      if (!marked.has(right)) cover.push(right);
    });
    cover.sort(function (a, b) { return a - b; }); // deterministic order
    return cover;
  }

  // ------------------------------------------------------------------ section 2: group card
  // Canonical JSON for signing. JSON.stringify keeps object keys in insertion order, so two
  // semantically identical cards built or parsed with different field order would sign to
  // different bytes and verification would fail. Sorting keys (recursively) before
  // stringifying gives every party the same byte string. Arrays keep their order — order
  // is meaningful in `nodePub`.
  function sortKeysDeep(v) {
    if (Array.isArray(v)) return v.map(sortKeysDeep);
    if (v && typeof v === 'object') {
      const out = {};
      Object.keys(v).sort().forEach(function (k) {
        if (v[k] !== undefined) out[k] = sortKeysDeep(v[k]);
      });
      return out;
    }
    return v;
  }
  function canonicalJson(value) {
    return JSON.stringify(sortKeysDeep(value));
  }

  // ECDSA P-256 / SHA-256 signing keys for the group manager. Kept separate from the
  // manager's ECDH identity key on purpose: one key, one purpose.
  function generateManagerSigningKeyPair() {
    return crypto.subtle.generateKey(SIG_KEY_ALGO, true, ['sign', 'verify']);
  }

  function withoutSig(card) {
    const body = {};
    Object.keys(card).forEach(function (k) { if (k !== 'sig') body[k] = card[k]; });
    return body;
  }

  async function signCardBody(body, managerSigKeyPair) {
    const bytes = new TextEncoder().encode(canonicalJson(body));
    const sig = await crypto.subtle.sign(SIG_ALGO, managerSigKeyPair.privateKey, bytes);
    return C().bufToB64(sig); // WebCrypto ECDSA output is raw r||s (64 bytes)
  }

  async function buildCardInternal(tree, name, revokedLeaves, managerSigKeyPair, cardVersion) {
    assertTree(tree);
    if (typeof name !== 'string') throw new Error('groups-bad-name');
    if (!managerSigKeyPair || !managerSigKeyPair.privateKey || !managerSigKeyPair.publicKey) {
      throw new Error('groups-bad-signing-key');
    }
    const body = {
      v: CARD_FORMAT_VERSION,
      groupId: tree.groupId,
      name: name,
      capacity: tree.capacity,
      // Array index i-1 holds the public key of node i (spec section 2).
      nodePub: tree.nodes.slice(1).map(function (n) { return C().bufToB64(n.pubRaw); }),
      revokedLeaves: normalizeRevoked(tree.capacity, revokedLeaves),
      cardVersion: cardVersion,
      managerSigPub: C().bufToB64(await crypto.subtle.exportKey('raw', managerSigKeyPair.publicKey))
    };
    body.sig = await signCardBody(body, managerSigKeyPair);
    return body;
  }

  // Builds the public, shareable, signed card. `opts.cardVersion` defaults to 1;
  // revokeMember() is what normally advances it.
  function buildGroupCard(tree, name, revokedLeaves, managerSigKeyPair, opts) {
    const version = (opts && opts.cardVersion !== undefined) ? opts.cardVersion : 1;
    if (!Number.isInteger(version) || version < 1) throw new Error('groups-bad-card-version');
    return buildCardInternal(tree, name, revokedLeaves, managerSigKeyPair, version);
  }

  // Structural check of a card (types, ranges, key lengths). Throws on the first problem;
  // callers that want a boolean go through verifyGroupCard(). Extra unknown fields are
  // tolerated (they are covered by the signature anyway) so newer cards still parse.
  function validateCardShape(card) {
    if (!card || typeof card !== 'object') throw new Error('groups-bad-card');
    if (card.v !== CARD_FORMAT_VERSION) throw new Error('groups-bad-card');
    if (typeof card.groupId !== 'string' || !card.groupId) throw new Error('groups-bad-card');
    if (typeof card.name !== 'string') throw new Error('groups-bad-card');
    if (!isValidCapacity(card.capacity)) throw new Error('groups-bad-card');
    if (!Number.isInteger(card.cardVersion) || card.cardVersion < 1) throw new Error('groups-bad-card');
    if (typeof card.managerSigPub !== 'string' || typeof card.sig !== 'string') throw new Error('groups-bad-card');
    if (!Array.isArray(card.nodePub) || card.nodePub.length !== 2 * card.capacity - 1) throw new Error('groups-bad-card');
    for (const p of card.nodePub) {
      if (typeof p !== 'string' || C().b64ToBuf(p).byteLength !== NODE_PUB_LEN) throw new Error('groups-bad-card');
    }
    normalizeRevoked(card.capacity, card.revokedLeaves); // throws on a bad leaf
    if (!Array.isArray(card.revokedLeaves)) throw new Error('groups-bad-card');
  }

  // Returns a Promise<boolean>. It NEVER throws for a bad card: malformed structure, a
  // wrong signature and a tampered field all return false, so a caller cannot forget a
  // try/catch and accidentally treat an exception path as success.
  //
  // IMPORTANT trust note: by default the card is checked against the `managerSigPub`
  // EMBEDDED in itself. That proves the card is internally consistent and untampered since
  // that key signed it, but anyone can forge a card with their own key. To actually
  // authenticate the manager, pass `expectedManagerSigPub` — the key you pinned out of
  // band (e.g. from the first card you accepted, or a scanned QR) as base64 or bytes.
  async function verifyGroupCard(card, expectedManagerSigPub) {
    try {
      validateCardShape(card);
      if (expectedManagerSigPub !== undefined && expectedManagerSigPub !== null) {
        const expected = typeof expectedManagerSigPub === 'string'
          ? expectedManagerSigPub : C().bufToB64(toBytes(expectedManagerSigPub));
        if (expected !== card.managerSigPub) return false;
      }
      const pub = await crypto.subtle.importKey('raw', C().b64ToBuf(card.managerSigPub), SIG_KEY_ALGO, false, ['verify']);
      const bytes = new TextEncoder().encode(canonicalJson(withoutSig(card)));
      return await crypto.subtle.verify(SIG_ALGO, pub, C().b64ToBuf(card.sig), bytes);
    } catch (e) {
      return false;
    }
  }

  // A card must describe exactly this tree before the manager signs invites or revocations
  // for it; otherwise a card/tree mix-up would hand out keys that open nothing.
  function assertCardMatchesTree(card, tree) {
    if (card.groupId !== tree.groupId || card.capacity !== tree.capacity) throw new Error('groups-card-mismatch');
    for (let id = 1; id < 2 * tree.capacity; id++) {
      if (card.nodePub[id - 1] !== C().bufToB64(tree.nodes[id].pubRaw)) throw new Error('groups-card-mismatch');
    }
  }

  // ------------------------------------------------------------------ section 3: invite package
  // Private to one invitee: the private keys of every node on their leaf-to-root path,
  // each wrapped separately with the existing AnigmaCrypto.encryptMessage. It is sent in
  // ANONYMOUS mode because the manager's identity key is not an input here and the
  // invitee can't tell "the manager" apart from a forger by a signature on this package
  // anyway; authenticity instead comes from checking the unwrapped keys against the signed
  // card (see openInvitePackage's `card` argument). Anonymous mode also has no curve
  // restriction, so an invitee with an X25519 identity works too.
  async function buildInvitePackage(tree, leafIndex, inviteePubRaw, card) {
    assertTree(tree);
    if (!card) throw new Error('groups-bad-card');
    validateCardShape(card);
    assertCardMatchesTree(card, tree);
    const pathNodeIds = getPathNodeIds(tree.capacity, leafIndex);
    if (card.revokedLeaves.indexOf(leafIndex) !== -1) throw new Error('groups-leaf-revoked');

    const wrappedPathKeys = [];
    for (const id of pathNodeIds) {
      const jwk = await crypto.subtle.exportKey('jwk', tree.nodes[id].priv);
      wrappedPathKeys.push(await C().encryptMessage(JSON.stringify(jwk), inviteePubRaw, { anonymous: true }));
    }
    return {
      v: CARD_FORMAT_VERSION,
      groupId: tree.groupId,
      leafIndex: leafIndex,
      pathNodeIds: pathNodeIds,
      wrappedPathKeys: wrappedPathKeys,
      cardVersion: card.cardVersion
    };
  }

  // Unwraps the path keys for the invitee. Returns plain, JSON-serializable data
  //   { v, groupId, leafIndex, cardVersion, keys: [{ nodeId, jwk }, ...] }
  // so the caller can persist it — but those are live private keys, so the caller must
  // encrypt it at rest under the identity passphrase like any other secret.
  //
  // If the (already verified) `card` is supplied, each unwrapped key's public half is
  // re-derived and compared with card.nodePub; a package carrying keys that don't match
  // the signed card is rejected. Without `card` that authenticity check is skipped.
  async function openInvitePackage(invitePackage, myPrivateKey, card) {
    const p = invitePackage;
    if (!p || p.v !== CARD_FORMAT_VERSION || typeof p.groupId !== 'string' ||
        !Array.isArray(p.pathNodeIds) || !Array.isArray(p.wrappedPathKeys) ||
        p.pathNodeIds.length !== p.wrappedPathKeys.length || p.pathNodeIds.length < 2) {
      throw new Error('groups-bad-invite');
    }
    // The tree depth is encoded in the path length, which pins down the capacity; the path
    // must then be exactly the leaf-to-root path of `leafIndex` — never trust listed ids.
    const capacity = Math.pow(2, p.pathNodeIds.length - 1);
    const expectedPath = getPathNodeIds(capacity, p.leafIndex);
    if (expectedPath.some(function (id, k) { return id !== p.pathNodeIds[k]; })) throw new Error('groups-bad-invite');
    if (card) {
      if (card.groupId !== p.groupId || card.capacity !== capacity) throw new Error('groups-card-mismatch');
    }

    const keys = [];
    for (let k = 0; k < expectedPath.length; k++) {
      const nodeId = expectedPath[k];
      const opened = await C().decryptMessage(p.wrappedPathKeys[k], { myPrivateKey: myPrivateKey });
      const jwk = JSON.parse(opened.text);
      if (!jwk || jwk.kty !== 'EC' || jwk.crv !== 'P-256' || typeof jwk.d !== 'string') throw new Error('groups-bad-invite');
      if (card) {
        const key = await crypto.subtle.importKey('jwk', jwk, NODE_KEY_ALGO, true, ['deriveBits']);
        const pubRaw = await C().derivePublicRawFromPrivateKey(key, 'P-256');
        if (C().bufToB64(pubRaw) !== card.nodePub[nodeId - 1]) throw new Error('groups-invite-key-mismatch');
      }
      keys.push({ nodeId: nodeId, jwk: jwk });
    }
    return { v: CARD_FORMAT_VERSION, groupId: p.groupId, leafIndex: p.leafIndex, cardVersion: p.cardVersion, keys: keys };
  }

  // Turns stored path keys into CryptoKeys. Accepts the object returned by
  // openInvitePackage, an array of {nodeId, jwk|key}, a Map, or a {nodeId: jwk|key} object.
  // Each value may be a JWK or an already-imported private CryptoKey.
  async function normalizePathKeys(input) {
    let entries = [];
    let groupId = null;
    if (input && Array.isArray(input.keys)) {
      entries = input.keys.map(function (e) { return [e.nodeId, e.jwk || e.key]; });
      groupId = typeof input.groupId === 'string' ? input.groupId : null;
    } else if (Array.isArray(input)) {
      entries = input.map(function (e) { return [e.nodeId, e.jwk || e.key]; });
    } else if (input instanceof Map) {
      entries = Array.from(input.entries());
    } else if (input && typeof input === 'object') {
      entries = Object.keys(input).map(function (k) { return [Number(k), input[k]]; });
    } else {
      throw new Error('groups-bad-path-keys');
    }
    const map = new Map();
    for (const pair of entries) {
      const nodeId = pair[0], v = pair[1];
      if (!Number.isInteger(nodeId) || nodeId < 1 || !v) throw new Error('groups-bad-path-keys');
      if (v.type === 'private' && v.algorithm) map.set(nodeId, v);
      else if (v.kty) map.set(nodeId, await crypto.subtle.importKey('jwk', v, NODE_KEY_ALGO, false, ['deriveBits']));
      else throw new Error('groups-bad-path-keys');
    }
    return { groupId: groupId, map: map };
  }

  // ------------------------------------------------------------------ section 5: group messages
  // Wraps a content-encryption key for everyone who is still in the group.
  //   plainBytesOrCEK: a 32-byte CEK (Uint8Array/ArrayBuffer), or null/undefined to have a
  //   fresh random one generated. The payload itself is encrypted separately by
  //   container.js/crypto.js under this CEK (unchanged); this function only wraps the CEK,
  //   so any other length is rejected rather than silently treated as data.
  // Returns { header, cek }: `header` = { groupId, cardVersion, wraps: [{nodeId, wrapped}] }
  // goes alongside the ciphertext, `cek` is what the caller encrypts the payload with.
  //
  // Wraps use anonymous mode (spec section 5): the sender need not be the manager. The
  // card is verified first by default, so a forged card can't make us encrypt to an
  // attacker's keys; pass opts.expectedManagerSigPub to pin the manager, or
  // opts.skipVerification if the caller has just verified this exact card itself.
  async function encryptForGroup(plainBytesOrCEK, card, opts) {
    opts = opts || {};
    if (opts.skipVerification) validateCardShape(card);
    else if (!(await verifyGroupCard(card, opts.expectedManagerSigPub))) throw new Error('groups-card-invalid');

    let cek;
    if (plainBytesOrCEK === undefined || plainBytesOrCEK === null) cek = randomBytes(CEK_LEN);
    else {
      cek = toBytes(plainBytesOrCEK);
      if (cek.length !== CEK_LEN) throw new Error('groups-bad-cek');
    }

    const cover = computeCoveringSet(card.capacity, card.revokedLeaves);
    if (cover.length === 0) throw new Error('groups-no-recipients'); // everyone revoked

    const cekB64 = C().bufToB64(cek);
    const wraps = [];
    for (const nodeId of cover) {
      const nodePubRaw = C().b64ToBuf(card.nodePub[nodeId - 1]);
      wraps.push({ nodeId: nodeId, wrapped: await C().encryptMessage(cekB64, nodePubRaw, { anonymous: true }) });
    }
    return { header: { groupId: card.groupId, cardVersion: card.cardVersion, wraps: wraps }, cek: cek };
  }

  // Recovers the CEK (Uint8Array, 32 bytes) using the member's own path keys. Only wraps
  // whose nodeId is one of the member's path nodes are attempted. Errors:
  //   groups-group-mismatch  keys belong to a different group than the header
  //   groups-not-in-cover    none of my path nodes is in the covering set (e.g. revoked)
  //   groups-decrypt-failed  a matching wrap existed but would not open (corrupt/forged)
  // Note: path keys never change when others are revoked (receivers are stateless), but
  // that also means a revoked member keeps being able to read messages that were
  // encrypted BEFORE their revocation; revocation only affects future cards.
  async function decryptForGroup(groupMessageHeader, myPathPrivateKeys) {
    const h = groupMessageHeader;
    if (!h || typeof h.groupId !== 'string' || !Array.isArray(h.wraps)) throw new Error('groups-bad-header');
    const keys = await normalizePathKeys(myPathPrivateKeys);
    if (keys.groupId !== null && keys.groupId !== h.groupId) throw new Error('groups-group-mismatch');

    let tried = false;
    for (const w of h.wraps) {
      const key = w && keys.map.get(w.nodeId);
      if (!key) continue;
      tried = true;
      try {
        const opened = await C().decryptMessage(w.wrapped, { myPrivateKey: key });
        const cek = new Uint8Array(C().b64ToBuf(opened.text));
        if (cek.length === CEK_LEN) return cek;
      } catch (e) { /* try the next matching wrap */ }
    }
    throw new Error(tried ? 'groups-decrypt-failed' : 'groups-not-in-cover');
  }

  // ------------------------------------------------------------------ revocation
  // Manager-side. Adds `leafIndex` to the revoked set and returns a NEW card: higher
  // cardVersion, updated revokedLeaves, signed again. The tree and every member's keys
  // stay as they are — the removal takes effect purely through the smaller covering set
  // that senders compute from the new card. The old card is verified against the
  // manager's own signing key first, so a tampered card can't be re-signed as legitimate.
  async function revokeMember(card, managerFullTree, leafIndex, managerSigKeyPair) {
    assertTree(managerFullTree);
    if (!managerSigKeyPair || !managerSigKeyPair.publicKey) throw new Error('groups-bad-signing-key');
    const pinned = C().bufToB64(await crypto.subtle.exportKey('raw', managerSigKeyPair.publicKey));
    if (!(await verifyGroupCard(card, pinned))) throw new Error('groups-card-invalid');
    assertCardMatchesTree(card, managerFullTree);
    if (!isLeafIndex(card.capacity, leafIndex)) throw new Error('groups-bad-leaf');
    if (card.revokedLeaves.indexOf(leafIndex) !== -1) throw new Error('groups-already-revoked');

    const revoked = card.revokedLeaves.concat([leafIndex]);
    return buildCardInternal(managerFullTree, card.name, revoked, managerSigKeyPair, card.cardVersion + 1);
  }

  return {
    createTree: createTree,
    buildGroupCard: buildGroupCard,
    verifyGroupCard: verifyGroupCard,
    buildInvitePackage: buildInvitePackage,
    openInvitePackage: openInvitePackage,
    computeCoveringSet: computeCoveringSet,
    encryptForGroup: encryptForGroup,
    decryptForGroup: decryptForGroup,
    revokeMember: revokeMember,
    // helpers
    generateManagerSigningKeyPair: generateManagerSigningKeyPair,
    getPathNodeIds: getPathNodeIds,
    canonicalJson: canonicalJson,
    isValidCapacity: isValidCapacity
  };
})();

// Node/CommonJS hook so `require('./groups.js')` works in tests. In the browser, and under
// vm.runInThisContext (how the existing tests load crypto.js/container.js), `module` does
// not exist and this is skipped.
if (typeof module !== 'undefined' && module.exports) {
  module.exports = AnigmaGroups;
}
