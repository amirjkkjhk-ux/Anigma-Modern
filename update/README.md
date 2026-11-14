# update/ — files the installed apps download

Two files live here once a release is published, and ONLY these two are ever fetched by the app:

* `latest.json`      – the update manifest (version, notes, installer URL + SHA-256 + size per platform)
* `latest.json.sig`  – base64 ECDSA P-256 / SHA-256 signature over the exact bytes of `latest.json`

They are produced by `tools/sign-update.js` with the PRIVATE key (`update-signing-key.pem`, kept offline).
They are deliberately NOT in this repository snapshot: a signature cannot be made without that key, and an
unsigned or placeholder file would simply be rejected by every installed app.

Before committing them to `main`:

    node tools/verify-update.js --dir update --assets <folder with the real APK/EXE>

It must print "all checks passed" (signature valid for the key embedded in `js/update.js`, version newer than the
installed one, installer size + SHA-256 equal to what was signed).
