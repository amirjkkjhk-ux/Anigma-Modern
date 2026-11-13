// ====================================================================================
// ANIGMA — groups-ui.js
//
// UI for the group-encryption feature (see docs/groups-spec-v1.md and
// docs/groups-integration-notes.md). Deliberately its OWN tab, not a "recipient" picked
// from Secure message / Files — groups are managed and used entirely from here.
//
// js/groups.js (the audited engine — createTree, buildGroupCard, buildInvitePackage,
// encryptForGroup, decryptForGroup, revokeMember, ...) is NOT touched by this file and is
// called exactly as its own test suite exercises it. Nothing here re-implements any of
// its security-relevant logic (covering-set selection, signature verification, CEK
// wrapping) — this file only moves data in and out of it and renders the result.
//
// Covers both group MESSAGES and group FILES (see the "group files" section below). File
// encryption turned out to need no js/worker.js changes at all — the worker only ever sees
// raw cekBytes, never who they were wrapped for, so the exact same chunked pipeline Files
// already uses is reused here unchanged; only js/ui.js (header/CEK setup, factored into
// filesRunEncryptOperation/filesRunDecryptOperation so this file can share it) and this
// file changed. See docs/groups-integration-notes.md, "فاز ۳" for the full account.
//
// Storage: `anigma_groups_v1` in localStorage, AES-GCM under the SAME idMasterKey derived
// from the identity passphrase that already protects `anigma_contacts_v1` — loaded/saved
// with the identical pattern as idLoadContacts()/idSaveContacts() in ui.js. Not yet folded
// into the identity backup/export file (AnigmaCrypto.exportIdentityBackup) — a group only
// exists on the devices that created/joined it, not inside identity-backup.json. This is
// stated plainly in groups.intro / the list-empty state, not hidden.
// ====================================================================================

let idGroups = [];
let groupsLoadFailed = false;
let groupsCurrentId = null; // which group record .id is open in the detail view, or null

// ------------------------------------------------------------------ storage (mirrors idLoadContacts/idSaveContacts)
let groupsNeedRebind = false; // true after reading a blob written before slot-binding
async function groupsLoadAll() {
  const raw = localStorage.getItem('anigma_groups_v1');
  groupsLoadFailed = false;
  if (!raw || !idMasterKey) { idGroups = []; return; }
  try {
    const blob = JSON.parse(raw);
    const pt = await AnigmaCrypto.openStored(idMasterKey, 'groups', blob);
    idGroups = JSON.parse(new TextDecoder().decode(pt));
    groupsNeedRebind = blob.aad !== 1;
    if (await storageIsRolledBack('groups', blob)) showError('status.storage.rolledBack');
  } catch (e) {
    idGroups = [];
    groupsLoadFailed = true;
    showError('status.groups.loadFailed');
  }
}
async function groupsSaveAll() {
  if (!idMasterKey) return;
  if (groupsLoadFailed) {
    if (!confirm(t('confirm.groupsOverwrite'))) return;
    groupsLoadFailed = false;
  }
  const sealed = await AnigmaCrypto.sealStored(idMasterKey, 'groups', new TextEncoder().encode(JSON.stringify(idGroups)));
  localStorage.setItem('anigma_groups_v1', JSON.stringify({ v: 2, aad: 1, seq: await storageNextSeq('groups'), iv: AnigmaCrypto.bufToB64(sealed.iv), ct: AnigmaCrypto.bufToB64(sealed.ct) }));
}

// ------------------------------------------------------------------ tree <-> storable JSON
// AnigmaGroups.createTree() holds live, non-serializable CryptoKey objects (tree.nodes[i].priv).
// Only the manager's OWN device ever holds this — exported here purely as a storage format,
// never sent anywhere (buildInvitePackage/buildGroupCard only ever take the live tree object
// and only let its PUBLIC halves leave, via the signed card).
async function groupsExportTree(tree) {
  const nodes = [];
  for (let i = 1; i < 2 * tree.capacity; i++) {
    const jwk = await crypto.subtle.exportKey('jwk', tree.nodes[i].priv);
    nodes.push({ id: i, jwk: jwk });
  }
  return { v: 1, groupId: tree.groupId, capacity: tree.capacity, nodes: nodes };
}
async function groupsImportTree(obj) {
  const nodesArr = new Array(2 * obj.capacity);
  nodesArr[0] = null;
  for (const n of obj.nodes) {
    const priv = await crypto.subtle.importKey('jwk', n.jwk, { name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits']);
    const pubRaw = new Uint8Array(await AnigmaCrypto.derivePublicRawFromPrivateKey(priv, 'P-256'));
    nodesArr[n.id] = { priv: priv, pubRaw: pubRaw };
  }
  return { v: 1, groupId: obj.groupId, capacity: obj.capacity, nodes: nodesArr };
}

// ------------------------------------------------------------------ small local helpers
// The manager holds every node's private key, so — unlike a regular member, who only has
// the path keys for their own leaf — it can open ANY current wrap directly, by trying
// every node it has against the message/file header. (See docs/groups-integration-notes.md,
// "ممیزی امنیتی مستقل" section, for why decryptForGroup() accepting a bare Map here, with
// no groupId to cross-check, is safe: every call site below only ever builds this map for
// `rec`'s OWN tree and only ever uses it against a header already confirmed to belong to
// that same rec.groupId first.)
async function groupsAdminDecryptMap(rec) {
  const tree = await groupsImportTree(rec.treeStore);
  const map = new Map();
  for (let i = 1; i < 2 * tree.capacity; i++) if (tree.nodes[i]) map.set(i, tree.nodes[i].priv);
  return map;
}

function groupsFind(id) { return idGroups.find(function (g) { return g.id === id; }); }
function groupsNewId() { return crypto.randomUUID ? crypto.randomUUID() : ('g' + Date.now() + Math.random()); }
function downloadTextFile(filename, text) {
  const blob = new Blob([text], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url; a.download = filename;
  document.body.appendChild(a); a.click(); document.body.removeChild(a);
  setTimeout(function () { URL.revokeObjectURL(url); }, 4000);
}
// Invites, cards and group messages are pasted as text. They used to start with a fixed label
// ("ANIGMA-GROUP-INVITE:" ...) and a base64 of JSON, which any filter can match. Now: base64 of
//     salt (16 random bytes) | JSON XOR keystream(salt)
// where the JSON carries its own type tag (so an invite can't be opened as a card). As with file headers
// the keystream needs no secret — this removes the constant signature, it is not secrecy; the private
// parts of these blobs are encrypted separately (wrapped keys, AES-GCM message body). Blobs made with
// the old labels are still accepted.
const GROUP_BLOB_LEGACY_PREFIX = { invite: 'ANIGMA-GROUP-INVITE:', card: 'ANIGMA-GROUP-CARD:', msg: 'ANIGMA-GROUP-MSG:' };
async function packBlob(kind, obj) {
  const json = new TextEncoder().encode(JSON.stringify({ t: kind, d: obj }));
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const masked = await AnigmaContainer.maskBytes(salt, json);
  const out = new Uint8Array(16 + masked.length);
  out.set(salt, 0); out.set(masked, 16);
  return AnigmaCrypto.bufToB64(out);
}
async function unpackBlob(kind, text) {
  const s = (text || '').trim();
  const legacy = GROUP_BLOB_LEGACY_PREFIX[kind];
  if (s.indexOf(legacy) === 0) return JSON.parse(decodeURIComponent(escape(atob(s.slice(legacy.length)))));
  let bytes;
  try { bytes = new Uint8Array(AnigmaCrypto.b64ToBuf(s)); } catch (e) { throw new Error('groups-wrong-blob-type'); }
  if (bytes.length < 20) throw new Error('groups-wrong-blob-type');
  let obj;
  try { obj = JSON.parse(new TextDecoder().decode(await AnigmaContainer.maskBytes(bytes.slice(0, 16), bytes.slice(16)))); }
  catch (e) { throw new Error('groups-wrong-blob-type'); }
  if (!obj || obj.t !== kind) throw new Error('groups-wrong-blob-type');
  return obj.d;
}

// ------------------------------------------------------------------ create
async function groupsCreateSubmit() {
  playSound('click');
  const name = document.getElementById('groupsNewName').value.trim();
  const capacity = parseInt(document.getElementById('groupsNewCapacity').value, 10);
  if (!name) { updateStatus('status.groups.needName', null, true); return; }
  try {
    const tree = await AnigmaGroups.createTree(capacity);
    const signerKp = await AnigmaGroups.generateManagerSigningKeyPair();
    const card = await AnigmaGroups.buildGroupCard(tree, name, [], signerKp, { cardVersion: 1 });
    const signerJwk = await crypto.subtle.exportKey('jwk', signerKp.privateKey);
    const rec = {
      id: groupsNewId(), role: 'admin', groupId: tree.groupId, name: name, capacity: capacity,
      card: card, treeStore: await groupsExportTree(tree), signerJwk: signerJwk,
      members: [], nextLeaf: capacity, createdTs: Date.now()
    };
    idGroups.push(rec);
    await groupsSaveAll();
    document.getElementById('groupsNewName').value = '';
    document.getElementById('groupsCreateForm').style.display = 'none';
    groupsRenderList();
    groupsOpenDetail(rec.id);
    updateStatus('status.groups.created');
    addLog('log.msg.groupCreated');
  } catch (e) {
    showError('status.groups.err', { msg: (e && e.message) ? e.message : '' });
  }
}

// ------------------------------------------------------------------ join
async function groupsJoinSubmit() {
  playSound('click');
  try {
    const fileInput = document.getElementById('groupsJoinFile');
    let raw = document.getElementById('groupsJoinInput').value.trim();
    if (fileInput.files && fileInput.files[0]) raw = await fileInput.files[0].text();
    if (!raw) { updateStatus('status.groups.needInvite', null, true); return; }
    const blob = await unpackBlob('invite', raw);
    if (!blob || !blob.card || !blob.invite) throw new Error('groups-bad-invite-blob');

    // First time we see this group: trust-on-first-use pin of the manager's signing key,
    // exactly like a contact's fingerprint is trusted the first time it's added — see
    // groups.join.hint in the UI for the plain-language version of this.
    if (!(await AnigmaGroups.verifyGroupCard(blob.card))) throw new Error('groups-card-invalid');
    const handle = await AnigmaGroups.openInvitePackage(blob.invite, idPrivateKey, blob.card);

    // The card and the invite arrive in the same blob, so a valid signature alone only proves
    // the blob is self-consistent, not WHO signed it. The person must compare the creator's
    // key code through a separate channel before we pin that key.
    const mgrCode = await AnigmaCrypto.computeFingerprint(AnigmaCrypto.b64ToBuf(blob.card.managerSigPub));
    if (!confirm(t('groups.join.confirmManager', { code: mgrCode }))) return;

    if (idGroups.some(function (g) { return g.groupId === blob.card.groupId && g.role === 'member'; })) {
      updateStatus('status.groups.alreadyJoined', null, true);
      return;
    }
    const rec = {
      id: groupsNewId(), role: 'member', groupId: blob.card.groupId, name: blob.card.name, capacity: blob.card.capacity,
      card: blob.card, managerSigPub: blob.card.managerSigPub, handle: handle, joinedTs: Date.now()
    };
    idGroups.push(rec);
    await groupsSaveAll();
    document.getElementById('groupsJoinInput').value = '';
    fileInput.value = '';
    document.getElementById('groupsJoinForm').style.display = 'none';
    groupsRenderList();
    groupsOpenDetail(rec.id);
    updateStatus('status.groups.joined');
    addLog('log.msg.groupJoined');
  } catch (e) {
    showError('status.groups.err', { msg: (e && e.message) ? e.message : '' });
  }
}

// ------------------------------------------------------------------ invite (admin)
async function groupsInviteSubmit() {
  playSound('click');
  const rec = groupsFind(groupsCurrentId);
  if (!rec || rec.role !== 'admin') return;
  const alias = document.getElementById('groupsInviteAlias').value.trim();
  const pubText = document.getElementById('groupsInvitePubKey').value.trim();
  if (!alias || !pubText) { updateStatus('status.groups.invite.needFields', null, true); return; }
  try {
    const pubRaw = AnigmaCrypto.b64ToBuf(pubText);
    await AnigmaCrypto.importPublicKeyRaw(pubRaw); // validates, same as adding a contact

    if (rec.nextLeaf > 2 * rec.capacity - 1) { updateStatus('status.groups.invite.full', null, true); return; }
    const tree = await groupsImportTree(rec.treeStore);
    const leaf = rec.nextLeaf;
    const invite = await AnigmaGroups.buildInvitePackage(tree, leaf, pubRaw, rec.card);
    const blobText = await packBlob('invite', { card: rec.card, invite: invite });

    rec.members.push({ leaf: leaf, alias: alias, pub: AnigmaCrypto.bufToB64(pubRaw), addedTs: Date.now() });
    rec.nextLeaf = leaf + 1;
    await groupsSaveAll();

    document.getElementById('groupsInviteAlias').value = '';
    document.getElementById('groupsInvitePubKey').value = '';
    const out = document.getElementById('groupsInviteOutput');
    out.value = blobText;
    document.getElementById('groupsInviteOutputWrap').style.display = 'block';
    groupsRenderMembers(rec);
    updateStatus('status.groups.invite.created');
    addLog('log.msg.groupInvited');
  } catch (e) {
    showError('status.groups.err', { msg: (e && e.message) ? e.message : '' });
  }
}

// ------------------------------------------------------------------ remove member (admin)
async function groupsRemoveMember(leaf) {
  const rec = groupsFind(groupsCurrentId);
  if (!rec || rec.role !== 'admin') return;
  const m = rec.members.find(function (x) { return x.leaf === leaf; });
  if (!confirm(t('groups.members.removeConfirm', { name: m ? m.alias : leaf }))) return;
  playSound('click');
  try {
    const tree = await groupsImportTree(rec.treeStore);
    const signerPriv = await crypto.subtle.importKey('jwk', rec.signerJwk, { name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign']);
    const pubJwk = Object.assign({}, rec.signerJwk);
    delete pubJwk.d;      // an EC public-key JWK must not carry the private scalar
    pubJwk.key_ops = ['verify'];
    const signerPub = await crypto.subtle.importKey('jwk', pubJwk, { name: 'ECDSA', namedCurve: 'P-256' }, true, ['verify']);
    const newCard = await AnigmaGroups.revokeMember(rec.card, tree, leaf, { privateKey: signerPriv, publicKey: signerPub });
    rec.card = newCard;
    await groupsSaveAll();
    const out = document.getElementById('groupsNewCardOutput');
    out.value = await packBlob('card', newCard);
    document.getElementById('groupsNewCardOutputWrap').style.display = 'block';
    groupsRenderMembers(rec);
    groupsRenderDetailMeta(rec);
    updateStatus('status.groups.memberRemoved');
    addLog('log.msg.groupMemberRemoved');
  } catch (e) {
    showError('status.groups.err', { msg: (e && e.message) ? e.message : '' });
  }
}

// ------------------------------------------------------------------ apply an updated card (member)
async function groupsApplyCardSubmit() {
  playSound('click');
  const rec = groupsFind(groupsCurrentId);
  if (!rec || rec.role !== 'member') return;
  try {
    const raw = document.getElementById('groupsApplyCardInput').value.trim();
    if (!raw) return;
    const card = await unpackBlob('card', raw);
    // Pinned check: the new card must be signed by the SAME manager key this member first
    // trusted when joining — not just "a valid signature from someone". This is what stops
    // anyone other than the real manager from ever posting a card this member will accept.
    if (!(await AnigmaGroups.verifyGroupCard(card, rec.managerSigPub))) { updateStatus('status.groups.applyCard.badSig', null, true); return; }
    if (card.groupId !== rec.groupId) { updateStatus('status.groups.applyCard.wrongGroup', null, true); return; }
    if (card.cardVersion <= rec.card.cardVersion) { updateStatus('status.groups.applyCard.notNewer', null, true); return; }
    rec.card = card;
    await groupsSaveAll();
    document.getElementById('groupsApplyCardInput').value = '';
    groupsRenderDetailMeta(rec);
    updateStatus('status.groups.applyCard.done');
    addLog('log.msg.groupCardApplied');
  } catch (e) {
    showError('status.groups.err', { msg: (e && e.message) ? e.message : '' });
  }
}

// ------------------------------------------------------------------ encrypt / decrypt a message
async function groupsEncryptSubmit() {
  playSound('click');
  const rec = groupsFind(groupsCurrentId);
  if (!rec) return;
  const text = document.getElementById('groupsMsgInput').value;
  if (!text) { updateStatus('status.groups.msg.empty', null, true); return; }
  try {
    const { header, cek } = await AnigmaGroups.encryptForGroup(null, rec.card);
    const key = await crypto.subtle.importKey('raw', cek, 'AES-GCM', false, ['encrypt']);
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, new TextEncoder().encode(text)));
    const packed = await packBlob('msg', { header: header, iv: AnigmaCrypto.bufToB64(iv), ct: AnigmaCrypto.bufToB64(ct) });
    document.getElementById('groupsMsgInput').value = '';
    const out = document.getElementById('groupsEncOutput');
    out.value = packed;
    document.getElementById('groupsEncOutputWrap').style.display = 'block';
    updateStatus('status.groups.encrypted');
    addLog('log.msg.groupEncrypted');
  } catch (e) {
    showError('status.groups.err', { msg: (e && e.message) ? e.message : '' });
  }
}
async function groupsDecryptSubmit() {
  playSound('click');
  const rec = groupsFind(groupsCurrentId);
  if (!rec) return;
  try {
    const raw = document.getElementById('groupsDecInput').value.trim();
    if (!raw) return;
    const blob = await unpackBlob('msg', raw);
    if (!blob.header || blob.header.groupId !== rec.groupId) { updateStatus('status.groups.msg.wrongGroup', null, true); return; }

    const cek = rec.role === 'admin'
      ? await AnigmaGroups.decryptForGroup(blob.header, await groupsAdminDecryptMap(rec))
      : await AnigmaGroups.decryptForGroup(blob.header, rec.handle);
    const key = await crypto.subtle.importKey('raw', cek, 'AES-GCM', false, ['decrypt']);
    const iv = new Uint8Array(AnigmaCrypto.b64ToBuf(blob.iv));
    const ct = AnigmaCrypto.b64ToBuf(blob.ct);
    const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ct);
    document.getElementById('groupsDecInput').value = '';
    const out = document.getElementById('groupsDecOutput');
    out.value = new TextDecoder().decode(pt);
    document.getElementById('groupsDecOutputWrap').style.display = 'block';
    updateStatus('status.groups.decrypted');
    addLog('log.msg.groupDecrypted');
  } catch (e) {
    const key = (e && e.message === 'groups-not-in-cover') ? 'status.groups.msg.notInCover' : 'status.groups.err';
    showError(key, { msg: (e && e.message) ? e.message : '' });
  }
}

// ------------------------------------------------------------------ group files
// Same pattern as group messages (encryptForGroup/decryptForGroup produce/consume a CEK,
// nothing else), but the bulk payload goes through the EXACT SAME chunked worker pipeline
// Files already uses — js/worker.js never sees or cares who a CEK was wrapped for, it only
// ever gets raw cekBytes, so no worker.js change was needed for this at all. Only the
// progress UI is separate from the Files tab's (filesShowProgress/filesRenderProgress
// target DOM elements inside the Files panel, which the user isn't looking at while on the
// Groups tab) — filesRunEncryptOperation/filesRunDecryptOperation accept override hooks for
// exactly this reason.
let groupsFilesSelected = []; // [{file, relPath}] — same shape js/worker.js already expects
const GROUP_FILE_BLOB_CAP = 800 * 1024 * 1024; // same cap as the Files tab

function groupsFileShowProgress(show) {
  document.getElementById('groupsFileProgressWrap').style.display = show ? 'block' : 'none';
  document.getElementById('groupsFileEncryptBtn').disabled = show;
  document.getElementById('groupsFileDecInput').disabled = show;
}
let groupsFileProgressStartTime = 0;
function groupsFileRenderProgress(processed, total, fileName, fileIndex, fileCount, phase) {
  const pct = total > 0 ? Math.min(100, Math.round((processed / total) * 100)) : 0;
  document.getElementById('groupsFileProgressFill').style.width = pct + '%';
  const elapsedS = (Date.now() - groupsFileProgressStartTime) / 1000;
  const speed = elapsedS > 0 ? processed / elapsedS : 0;
  const remaining = total - processed;
  const etaS = speed > 0 ? remaining / speed : 0;
  const statsKey = phase === 'preparing' ? 'files.progress.preparingStats' : 'files.progress.stats';
  document.getElementById('groupsFileProgressMeta').textContent =
    t(statsKey, { percent: pct, done: humanSize(processed), total: humanSize(total), speed: humanSize(speed), eta: formatEta(etaS) }) +
    (fileName ? ' — ' + t('files.progress.processing', { name: fileName, index: fileIndex || 0, count: fileCount || groupsFilesSelected.length }) : '');
}

function groupsFileOnSelect(fileList) {
  groupsFilesSelected = Array.from(fileList).map(function (f) { return { file: f, relPath: f.webkitRelativePath || f.name }; });
  const box = document.getElementById('groupsFileEncSelected');
  box.textContent = groupsFilesSelected.length ? t('groups.file.enc.selected', { n: groupsFilesSelected.length }) : '';
}

async function groupsFileEncryptSubmit() {
  playSound('click');
  const rec = groupsFind(groupsCurrentId);
  if (!rec) return;
  if (!groupsFilesSelected.length) { updateStatus('status.groups.file.needFiles', null, true); return; }
  if (filesOperationActive) { updateStatus('files.busy', null, true); return; }

  const totalBytes = groupsFilesSelected.reduce(function (s, e) { return s + e.file.size; }, 0);
  let destination = null;
  const hasFsApi = 'showSaveFilePicker' in window;
  if (hasFsApi) {
    const pickerStartedAt = Date.now();
    try {
      const handle = await window.showSaveFilePicker({ suggestedName: 'group-package.anigma', types: [{ description: 'Anigma package', accept: { 'application/octet-stream': ['.anigma'] } }] });
      destination = { mode: 'fsapi', handle: handle };
    } catch (e) {
      // See filesStartEncrypt() in ui.js for why a fast AbortError means the picker never
      // actually opened (not a real user-cancel) and should fall back, not abort.
      const pickerFailedInstantly = (Date.now() - pickerStartedAt) < FILES_PICKER_CANCEL_MIN_MS;
      if (e && e.name === 'AbortError' && !pickerFailedInstantly) { updateStatus('files.saveCancelled'); return; }
      if (totalBytes > GROUP_FILE_BLOB_CAP) { updateStatus('files.err.tooLargeForBlob', { cap: humanSize(GROUP_FILE_BLOB_CAP) }, true); return; }
      destination = { mode: 'blob' };
    }
  } else {
    if (totalBytes > GROUP_FILE_BLOB_CAP) { updateStatus('files.err.tooLargeForBlob', { cap: humanSize(GROUP_FILE_BLOB_CAP) }, true); return; }
    destination = { mode: 'blob' };
  }

  try {
    const { header, cek } = await AnigmaGroups.encryptForGroup(null, rec.card);
    const chunkEl = document.getElementById('fileChunkSizeRange');
    const compressEl = document.getElementById('fileCompressionSelect');
    const roundEl = document.getElementById('fileRoundSizeToggle');
    const chunkSizeMB = chunkEl ? parseInt(chunkEl.value, 10) : 4;
    const compressMode = compressEl ? compressEl.value : 'auto';
    const roundSize = roundEl ? roundEl.classList.contains('on') : false;
    const baseNonce = crypto.getRandomValues(new Uint8Array(7));
    const headerBytes = await AnigmaContainer.buildMaskedHeader({ chunkSizeMB: chunkSizeMB, baseNonce: baseNonce, wraps: [], group: header });

    groupsFileProgressStartTime = Date.now();
    await filesRunEncryptOperation({
      files: groupsFilesSelected, chunkSizeMB: chunkSizeMB, cekBytes: cek, baseNonce: baseNonce,
      headerBytes: headerBytes, compressMode: compressMode, roundSize: roundSize, destination: destination,
      outputFilename: 'group-package.anigma', doneLogKey: 'log.msg.groupFileEncrypted', doneLogParams: { count: groupsFilesSelected.length },
      showProgress: groupsFileShowProgress, renderProgress: groupsFileRenderProgress,
      onDone: function () {
        groupsFilesSelected = [];
        document.getElementById('groupsFileEncInput').value = '';
        document.getElementById('groupsFileEncSelected').textContent = '';
      }
    });
  } catch (e) {
    showError('status.groups.err', { msg: (e && e.message) ? e.message : '' });
  }
}

async function groupsFileHandleDecrypt(file) {
  const rec = groupsFind(groupsCurrentId);
  if (!rec || !file) return;
  if (filesOperationActive) { updateStatus('files.busy', null, true); return; }
  try {
    // A group header can carry many more (small) wraps than a direct-recipient header — readHeader()
    // keeps reading until the whole thing parses (masked or legacy layout alike).
    let headerInfo;
    try {
      headerInfo = (await AnigmaContainer.readHeader(file)).info;
    } catch (e) {
      if (e.message === 'container-unknown-version') { updateStatus('files.err.badVersion', { v: e.foundVersion }, true); return; }
      updateStatus('files.err.badMagic', null, true); return;
    }
    if (!headerInfo.group) { updateStatus('status.groups.file.notAGroupFile', null, true); return; }
    if (headerInfo.group.groupId !== rec.groupId) { updateStatus('status.groups.msg.wrongGroup', null, true); return; }
    // Security review #3c (ui.js) applies identically here — see filesHandleDecryptFile().
    if (headerInfo.chunkSizeMB < AnigmaContainer.MIN_CHUNK_MB || headerInfo.chunkSizeMB > AnigmaContainer.MAX_CHUNK_MB) {
      updateStatus('files.err.badChunkSize', null, true); return;
    }

    const groupHeader = {
      groupId: headerInfo.group.groupId, cardVersion: headerInfo.group.cardVersion,
      wraps: headerInfo.group.wraps.map(function (w) { return { nodeId: w.nodeId, wrapped: AnigmaContainer.groupWrapToString(w) }; })
    };
    let cekBytes;
    try {
      cekBytes = rec.role === 'admin'
        ? await AnigmaGroups.decryptForGroup(groupHeader, await groupsAdminDecryptMap(rec))
        : await AnigmaGroups.decryptForGroup(groupHeader, rec.handle);
    } catch (e) {
      updateStatus('status.groups.msg.notInCover', null, true);
      return;
    }

    const hasDirApi = 'showDirectoryPicker' in window;
    let dirHandle = null;
    if (hasDirApi) {
      const pickerStartedAt = Date.now();
      try { dirHandle = await window.showDirectoryPicker(); }
      catch (e) {
        const pickerFailedInstantly = (Date.now() - pickerStartedAt) < FILES_PICKER_CANCEL_MIN_MS;
        if (e && e.name === 'AbortError' && !pickerFailedInstantly) { updateStatus('files.saveCancelled'); return; }
        dirHandle = null;
      }
    }
    const memoryFiles = dirHandle ? null : [];
    if (memoryFiles) {
      const approxPlainBytes = Math.max(0, file.size - headerInfo.headerLength);
      if (approxPlainBytes > MEMORY_DECRYPT_WARN_BYTES) {
        if (!confirm(t('files.warn.memoryDecrypt', { size: humanSize(approxPlainBytes) }))) return;
      }
    }

    groupsFileProgressStartTime = Date.now();
    await filesRunDecryptOperation({
      file: file, headerInfo: headerInfo, cekBytes: cekBytes, destDirHandle: dirHandle, memoryFiles: memoryFiles,
      doneLogKey: 'log.msg.groupFileDecrypted', showProgress: groupsFileShowProgress, renderProgress: groupsFileRenderProgress,
      onError: filesMapDecryptError
    });
  } catch (e) {
    showError('status.groups.err', { msg: (e && e.message) ? e.message : '' });
  }
}

// ------------------------------------------------------------------ leave / remove locally
function groupsLeaveCurrent() {
  const rec = groupsFind(groupsCurrentId);
  if (!rec) return;
  const confirmKey = rec.role === 'admin' ? 'groups.leave.confirmAdmin' : 'groups.leave.confirmMember';
  if (!confirm(t(confirmKey, { name: rec.name }))) return;
  playSound('click');
  idGroups = idGroups.filter(function (g) { return g.id !== rec.id; });
  groupsSaveAll();
  groupsShowList();
  groupsRenderList();
  updateStatus('status.groups.left');
  addLog('log.msg.groupLeft');
}

// ------------------------------------------------------------------ rendering
function groupsShowList() {
  groupsCurrentId = null;
  document.getElementById('groupsListView').style.display = 'block';
  document.getElementById('groupsDetailView').style.display = 'none';
}
function groupsOpenDetail(id) {
  groupsCurrentId = id;
  const rec = groupsFind(id);
  if (!rec) { groupsShowList(); return; }
  document.getElementById('groupsListView').style.display = 'none';
  document.getElementById('groupsDetailView').style.display = 'block';
  document.getElementById('groupsDetailName').textContent = rec.name;
  document.getElementById('groupsInviteCard').style.display = rec.role === 'admin' ? 'block' : 'none';
  document.getElementById('groupsMembersCard').style.display = rec.role === 'admin' ? 'block' : 'none';
  document.getElementById('groupsApplyCardCard').style.display = rec.role === 'member' ? 'block' : 'none';
  document.getElementById('groupsNewCardOutputWrap').style.display = 'none';
  document.getElementById('groupsInviteOutputWrap').style.display = 'none';
  document.getElementById('groupsEncOutputWrap').style.display = 'none';
  document.getElementById('groupsDecOutputWrap').style.display = 'none';
  document.getElementById('groupsFileProgressWrap').style.display = 'none';
  groupsFilesSelected = [];
  document.getElementById('groupsFileEncInput').value = '';
  document.getElementById('groupsFileEncSelected').textContent = '';
  document.getElementById('groupsLeaveTitle').textContent = t(rec.role === 'admin' ? 'groups.leave.titleAdmin' : 'groups.leave.titleMember');
  document.getElementById('groupsLeaveHint').textContent = t(rec.role === 'admin' ? 'groups.leave.hintAdmin' : 'groups.leave.hintMember');
  groupsRenderDetailMeta(rec);
  if (rec.role === 'admin') groupsRenderMembers(rec);
}
async function groupsRenderDetailMeta(rec) {
  const activeCount = rec.role === 'admin'
    ? rec.members.filter(function (m) { return rec.card.revokedLeaves.indexOf(m.leaf) === -1; }).length
    : null;
  const roleLabel = t(rec.role === 'admin' ? 'groups.role.admin' : 'groups.role.member');
  let text = roleLabel + ' · ' + t('groups.detail.capacity', { capacity: rec.capacity }) + ' · ' + t('groups.detail.cardVersion', { v: rec.card.cardVersion });
  if (activeCount !== null) text += ' · ' + t('groups.detail.activeMembers', { n: activeCount });
  try {
    const mgrCode = await AnigmaCrypto.computeFingerprint(AnigmaCrypto.b64ToBuf(rec.card.managerSigPub));
    text += ' · ' + t('groups.detail.managerCode', { code: mgrCode });
  } catch (e) { /* card shape was already validated; cosmetic only */ }
  document.getElementById('groupsDetailMeta').textContent = text;
}
function groupsRenderMembers(rec) {
  const box = document.getElementById('groupsMembersList');
  box.textContent = '';
  if (!rec.members.length) {
    const p = document.createElement('p');
    p.className = 'field-hint';
    p.textContent = t('groups.members.empty');
    box.appendChild(p);
    return;
  }
  rec.members.forEach(function (m) {
    const revoked = rec.card.revokedLeaves.indexOf(m.leaf) !== -1;
    const card = document.createElement('div');
    card.className = 'contact-card';
    const left = document.createElement('div');
    const name = document.createElement('div');
    name.className = 'cc-name';
    const dot = document.createElement('span');
    dot.className = 'cc-status-dot ' + (revoked ? 'unverified' : 'verified');
    name.appendChild(dot);
    name.appendChild(document.createTextNode(m.alias));
    left.appendChild(name);
    if (revoked) {
      const tag = document.createElement('div');
      tag.className = 'cc-fp';
      tag.textContent = t('groups.members.removedTag');
      left.appendChild(tag);
    }
    card.appendChild(left);
    if (!revoked) {
      const actions = document.createElement('div');
      const delBtn = document.createElement('button');
      delBtn.type = 'button'; delBtn.className = 'btn-sm';
      delBtn.innerHTML = iconSvg('trash', 'icon-anim') + '<span>' + escapeHtml(t('groups.members.remove')) + '</span>';
      delBtn.addEventListener('click', function () { groupsRemoveMember(m.leaf); });
      actions.appendChild(delBtn);
      card.appendChild(actions);
    }
    box.appendChild(card);
  });
}
function groupsRenderList() {
  const box = document.getElementById('groupsList');
  if (!box) return;
  box.textContent = '';
  if (!idGroups.length) {
    const p = document.createElement('p');
    p.className = 'field-hint';
    p.textContent = t('groups.list.empty');
    box.appendChild(p);
    return;
  }
  idGroups.forEach(function (g) {
    const card = document.createElement('div');
    card.className = 'contact-card';
    card.style.cursor = 'pointer';
    const left = document.createElement('div');
    const name = document.createElement('div');
    name.className = 'cc-name';
    name.appendChild(document.createTextNode(g.name));
    const meta = document.createElement('div');
    meta.className = 'cc-fp';
    const countText = g.role === 'admin' ? t('groups.card.members', { n: g.members.length }) : t('groups.role.member');
    meta.textContent = t(g.role === 'admin' ? 'groups.role.admin' : 'groups.role.member') + ' · ' + countText;
    left.appendChild(name); left.appendChild(meta);
    card.appendChild(left);
    card.addEventListener('click', function () { groupsOpenDetail(g.id); });
    box.appendChild(card);
  });
}

// ------------------------------------------------------------------ wiring
function groupsWireUI() {
  function on(id, fn) { const el = document.getElementById(id); if (el) el.addEventListener('click', fn); }
  on('tabGroupsBtn', function () { switchMainTab('groups'); });
  on('groupsCreateShowBtn', function () {
    document.getElementById('groupsJoinForm').style.display = 'none';
    const f = document.getElementById('groupsCreateForm');
    f.style.display = f.style.display === 'none' ? 'block' : 'none';
  });
  on('groupsJoinShowBtn', function () {
    document.getElementById('groupsCreateForm').style.display = 'none';
    const f = document.getElementById('groupsJoinForm');
    f.style.display = f.style.display === 'none' ? 'block' : 'none';
  });
  on('groupsCreateSubmitBtn', groupsCreateSubmit);
  on('groupsJoinSubmitBtn', groupsJoinSubmit);
  on('groupsBackBtn', function () { playSound('click'); groupsShowList(); });
  on('groupsInviteSubmitBtn', groupsInviteSubmit);
  on('groupsApplyCardSubmitBtn', groupsApplyCardSubmit);
  on('groupsEncryptBtn', groupsEncryptSubmit);
  on('groupsDecryptBtn', groupsDecryptSubmit);
  on('groupsLeaveBtn', groupsLeaveCurrent);

  on('groupsInviteCopyBtn', async function () {
    const ok = await copyToClipboard(document.getElementById('groupsInviteOutput').value);
    updateStatus(ok ? 'status.copy.done' : 'status.copy.failed', null, !ok);
  });
  on('groupsInviteDownloadBtn', function () { downloadTextFile('anigma-group-invite.txt', document.getElementById('groupsInviteOutput').value); });
  on('groupsNewCardCopyBtn', async function () {
    const ok = await copyToClipboard(document.getElementById('groupsNewCardOutput').value);
    updateStatus(ok ? 'status.copy.done' : 'status.copy.failed', null, !ok);
  });
  on('groupsNewCardDownloadBtn', function () { downloadTextFile('anigma-group-card.txt', document.getElementById('groupsNewCardOutput').value); });
  on('groupsEncCopyBtn', async function () {
    const ok = await copyToClipboard(document.getElementById('groupsEncOutput').value);
    updateStatus(ok ? 'status.copy.done' : 'status.copy.failed', null, !ok);
  });
  on('groupsEncQrBtn', function () { renderQR(document.getElementById('groupsEncOutput').value.trim(), 'qr.title.text', 'qr.desc.text', 'log.msg.qr'); });

  on('groupsFileEncryptBtn', groupsFileEncryptSubmit);
  on('groupsFileCancelBtn', function () { filesCancelOperation(); }); // shared with the Files tab — same global filesWorker/filesOperationActive
  const fileEncInput = document.getElementById('groupsFileEncInput');
  if (fileEncInput) fileEncInput.addEventListener('change', function () { groupsFileOnSelect(fileEncInput.files); });
  const fileDecInput = document.getElementById('groupsFileDecInput');
  if (fileDecInput) fileDecInput.addEventListener('change', function () {
    const f = fileDecInput.files && fileDecInput.files[0];
    fileDecInput.value = '';
    if (f) groupsFileHandleDecrypt(f);
  });
}

if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', groupsWireUI);
else groupsWireUI();
