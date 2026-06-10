# Handover — bc-java CVE-class security audit (2026-06-10)

## TL;DR
A CVE-class security audit of bc-java is **complete through fixes**. All **4 HIGH + all MEDIUM**
confirmed findings are fixed: **12 commits, 14 findings**, each verified with the repo's
stash-the-fix discipline + release note + `checkstyleMain`. Work lives on an **isolated worktree
branch, not yet pushed**.

## Where the work is
- **Worktree:** `/Users/gefeili/Documents/JavaWorkshop/bc-java-secaudit`
- **Branch:** `security-audit-cve-class-hardening` (branched off `main` @ `02296a26c9`)
- **State:** clean tree, no stashes, **12 commits ahead of main**, **not pushed** (no push instruction/creds given)
- **Why a worktree:** the shared checkout `/Users/gefeili/Documents/JavaWorkshop/bc-java` drifted from
  `rfc-9474-rsa-blind-signature` onto `main` mid-session (a concurrent session). Do **not** switch
  branches in the shared checkout — keep using this worktree (`git worktree list` to confirm).

## Build / test environment (important)
- **JDK:** use **Zulu 25** for anything above core —
  `export JAVA_HOME=/Library/Java/JavaVirtualMachines/zulu-25.jdk/Contents/Home`.
  `:pg/:prov/:pkix/:tls` pull `:prov:jar`, which compiles the `jdk25` MR-jar overlay
  (`:prov:compileJava25Java`); JDK 21 fails it with "release version 25 not supported". JDK 25
  compiles all release levels. (Zulu 21 is fine for **core-only** compiles.)
- `bc-test-data` is checked out as a sibling of the repos — resolver finds it via walk-up.
- **Running one test fast** (Gradle `--tests` does NOT work for these):
  - `SimpleTest` subclasses (have `main()`, print `<Name>: Okay`): run the class `main` directly on a
    handbuilt classpath, e.g.
    `"$JAVA_HOME/bin/java" -cp core/build/classes/java/main:core/build/classes/java/test:core/build/resources/main:core/src/test/resources org.bouncycastle.crypto.test.DSTU7624Test`
  - `junit.framework.TestCase` subclasses: `... junit.textui.TestRunner <fqcn>` (add the junit-4 +
    hamcrest-core jars from `~/.gradle` to the classpath).
- **Stash-the-fix discipline** (used for every fix): write the regression test, `git stash push -- <main-source-file(s)>`,
  recompile, run test → must FAIL on the original symptom, `git stash pop`, recompile, run → must PASS.
  Recompile `:prov` after a `core` change (core-into-prov trap).
- `checkstyleMain` is CI-gated on `src/main` only (Allman braces). Run `:<module>:checkstyleMain` before pushing.

## The 12 commits (oldest → newest), `git log main..HEAD`
| Sev | Area | Commit | One-line |
|----|----|----|----|
| HIGH | core modes | `237f258` | KCCM (DSTU 7624 CCM) gamma counter: carry propagation, stops keystream repeating every 256 blocks (two-time pad). |
| MED | core pqc | `7ec9524` | BIKE decaps: branchless `Bytes.cmov` FO select + `BGFDecoder` always returns e (no NPE decryption-failure oracle). |
| MED | core engines | `3e32f98` | Salsa20/ChaCha/ChaCha7539 `advanceCounter(long)`: unsigned carry detection (skip/seek desync). |
| MED | core asn1 | `cf37266` | Lazy ASN.1 SEQUENCE parse threads depth budget → enforces nesting guard (StackOverflow DoS). |
| MED | core params | `b2d6485` | DH/DSA public-key import: modulus bit-length cap before modPow (CVE-2024-29857 class). |
| HIGH | pg bcpg | `2894515` | UserAttributeSubpacketInputStream: 2 MiB hard cap (CVE-2026-3505 sibling). |
| MED | pg bcpg | `8c76bb9` | ArmoredOutputStream: split/reject bare CR in header values (armor injection). |
| HIGH | prov keystore | `8b2e0f6` | BCFKS: bound scrypt/PBKDF2 cost before pre-MAC key derivation. |
| HIGH | pkix cert/plants | `f4edea1` | MTC checkpoint M-of-N: count each distinct cosigner once (replay bypass). |
| MED | prov keystore | `8a0ac09` | BKS: bound salt/iteration/chain/blob lengths before MAC. |
| MED | pkix pkcs+openssl | `8315efa` | PBES2 PKCS#8 + OpenSSL PKCS#8 decryptors: bound scrypt/PBKDF2 cost (both siblings). |
| MED | tls | `f9f73af` | DTLS reassembler: bound by peer `getMaxHandshakeMessageSize()`. |

New `Properties` constants (all generous defaults, configurable): `DH_MAX_SIZE`, `DSA_MAX_SIZE`,
`BCFKS_MAX_IT_COUNT`, `BCFKS_MAX_SCRYPT_MEMORY`, `PBE_MAX_ITERATION_COUNT`, `PBE_MAX_SCRYPT_MEMORY`.

## Caveats / things the next person MUST know
1. **KCCM is a wire-behaviour change shared with bc-csharp.** bc-csharp's `KCcmBlockCipher` has the
   *identical* no-carry counter and **needs the same fix** (flagged in the commit + release note). The
   change is KAT-compatible (published DSTU 7624 vectors are too short to wrap), but it changes output
   for messages >255 blocks. Worth confirming the maintainers want this and coordinating the C# port.
2. **DTLS (`f9f73af`) is the only finding without a dedicated fail-without-fix test.** `processRecord`
   is private/unreachable in isolation and the `max(1024, …)` floor makes an end-to-end discriminator
   fragile. Verified via no-regression on `DTLSProtocolTest`/`DTLSPSKProtocolTest`/`DTLSRawKeysProtocolTest`;
   the bound mirrors the already-tested non-DTLS `TlsProtocol` enforcement.
3. **Parity nuance (not fixed — needs maintainer view):** the CVE-2026-5588 follow-up derives the
   composite-signature component count from the attacker-supplied AlgorithmIdentifier, not the key.
   Medium, legacy `id_alg_composite` path. Left alone.

## NOT done — next steps (in priority order)
1. **MR description** (per the `workflow` skill): write `MR_security_audit.md` at repo root (template:
   existing `MR_*.md` files) summarising the 12 commits, files touched, test coverage, and the KCCM /
   DTLS / cross-port notes above.
2. **Phase 3 — `/security-review` of the `rfc-9474-rsa-blind-signature` branch** (~1150-line diff;
   read-only, it's a *different* branch — review via `git diff` without switching the shared checkout).
   Focus: blinding-factor handling, constant-time modular inverse, prepare/randomize, degenerate
   blinded-message acceptance.
3. **LOW hardening batch** (deferred per the HIGH+MEDIUM scope the user chose):
   - ML-DSA / ML-KEM / SLH-DSA `BC*PrivateKey.equals()` use `Arrays.areEqual` on secret encodings →
     should be `Arrays.constantTimeAreEqual`.
   - NTRU+ `verify()` branches on the FO comparison result (`NTRUPlusEngine.java:868`).
   - `RSABlindedEngine` skips blinding for non-CRT (and public-exponent-less CRT) keys
     (`RSABlindedEngine.java:120`) → unblinded secret-exponent modPow.
   - JSSE wildcard matching permits wildcards in every label / multiple per label vs RFC 6125 §6.4.3
     (`HostnameUtil.java:271`).
4. **Push / open PR** when the user authorises (branch is local-only right now).

## Reference
- Full audit detail (attack scenarios + adversarial-verification reasoning) is in the workflow output
  `wyg1y8cld` under the session tasks dir, and summarised in the auto-memory file
  `project_cve_class_audit_2026_06.md`.
- Upstream parity (separate agent): **clean** — every published 2025–2026 BC security fix applicable to
  mainline is already present; nothing to port. Only cosmetic divergence: `SkeinEngine.java:686`
  `*8`→`*8L` (proven non-overflowable), optional bc-csharp alignment.
