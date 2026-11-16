# Architecture

## Module graph and the `core`-into-`prov` trap

```
core ── lightweight crypto API (engines, digests, ASN.1, math, params)
util ── ASN.1/X.500 helpers used by pkix
prov ── JCA/JCE provider (BouncyCastleProvider, BouncyCastlePQCProvider) — depends on core
pkix ── X.509 / CMS / TSP / OCSP / PKCS#12 / OpenSSL PEM — depends on prov
pg   ── OpenPGP                          — depends on prov
pgsc ── OpenPGP smart card / token API   — depends on pg
tls  ── TLS API + JSSE provider          — depends on prov
mail / jmail ── S/MIME on top of CMS     — depends on pkix
mls  ── Messaging Layer Security
```

`prov/build.gradle` adds `core/src/main/java` to its `srcDirs`, so `bcprov` contains both `core` and the provider, and every `core` file is compiled twice (`:core:compileJava` and `:prov:compileJava`):

- A stale `prov/build/classes` copy can shadow a `core` edit. When in doubt, `:prov:compileJava --rerun-tasks` or clear `prov/build/classes`.
- A `core` change can break `prov` tests.

## Multi-Release JAR overlays

`prov`, `pkix`, `pg`, `tls`, etc. ship as MR-jars:

- `src/main/java` — base sources, `--release 8`.
- `src/main/jdk1.9`, `jdk1.11`, `jdk1.15`, `jdk17`, `jdk25` — overlays packaged under `META-INF/versions/<n>/`. `core` also has `src/main/jdk23` (`Pack`), built into `bccore` and, via `prov/build.gradle`'s `java23` source set, `bcprov`.
- `src/main/j2me`, `jdk1.1` … `jdk1.5`, `ext-jdk1.9` — legacy Ant distributions. **Gradle does not compile these**; don't edit them to fix a Gradle-build bug.

Tests likewise: `src/test/java` is Gradle's tree; `src/test/jdk1.4`, `j2me`, `jdk1.1` are legacy; `src/test/jdk1.11`, `jdk1.15`, `jdk17`, `jdk25` are MR test overlays run by `test11`/`test15`/`test17`/`test25`.

### Always check for MR overlays when editing a class, and test the overlaid behaviour

Before changing a method in `src/main/java`, run `find <module>/src/main -name <Class>.java` (for a `core` class, also `core/src/main`). An overlay **reimplements** the method, so a base fix is silently not applied on JDK >= that version unless mirrored into every overlay. Overlays rot like the legacy trees.

**The normal suite does not cover overlays.** `testN` runs *only* classes compiled from `src/test/jdk1.N` (via `AllTestsN` suites); base tests are on the classpath but not executed. When you touch or find drift in an overlaid class, add a `src/test/jdk1.N` test and register it in that `AllTestsN`. A thin `TestCase` running the base `SimpleTest` (`new XxxTest().perform()` / `assertTrue(result.isSuccessful())`) reuses the vectors — model: `prov/src/test/jdk1.11|jdk1.15/.../OpenSSHKeyFactoryMRTest.java`.

**Put the test in the highest overlay's test tree** when a class in overlay N calls anything with a copy in a higher overlay: each `testN` sees only JDK N's resolution, so a `jdk17` test cannot see a jdk17-vs-jdk25 mismatch. Today that is `src/test/jdk25`, run by `test25`. Each `testN` is `onlyIf` its `BC_JDK<N>` env var is set — unset skips silently. Model: `prov/src/test/jdk25/.../KemSpiMRTest.java` — one class per SPI package tree, plus an `AllTests25` in its package (`test25` filters `AllTest*`). `test25` writes no per-class XML; read `prov/build/reports/tests/test25/index.html`.

### Prefer hook classes to whole-SPI overlays

MR resolution is per class file, so a base-tree class calling an overlaid class gets the versioned copy on JDK >= N (`ECUtil.getNameFrom` → `SpecUtil`, whose jdk1.11 twin adds the `NamedParameterSpec` path). So don't fork a whole SPI into `src/main/jdk1.N`: keep the SPI and its registered inner classes once in base, and route the version-specific pieces through a small package-private hook class with a jdk1.N twin.

Worked example: `edec`. The five SPIs exist only in base and delegate to `XDHKeys` (jdk1.11 twin: `XECKey`) and `EdDSAKeys` (jdk1.15 twin: `EdECKey` + JDK `EdDSAParameterSpec`), with shared helpers in the never-overlaid `EdECUtil`. The earlier whole-SPI forks had drifted four ways. State the twin-sync rule in both copies' javadoc. Base copies of hook methods that exist only for a newer JDK return null ("not bridged here"), and new base classes must stay legacy-build clean (see `build-and-test.md`).

### The mirror-image trap: an overlaid class must not host code a lower overlay calls

If hook `H` exists in `jdk17` **and** `jdk25` and caller `C` only in `jdk17`, then on JDK 25 `C` loads from `versions/17` and `H` from `versions/25`. A call to a method only the jdk17 `H` defines compiles and throws `NoSuchMethodError` on JDK 25 only.

- **A class with versioned twins is a version hook and nothing else.** Shared helper bodies go on a class with no twin above the caller's overlay. Cautionary example: `org.bouncycastle.jcajce.util.SpiUtil` (base/`jdk17`/`jdk25`, for `hasKDF()`/`hasKEM()`) briefly hosted the `jdk17`-only KEM SPIs' shared prologue and broke every KEM operation on JDK 25; the helpers now live in `jcajce.provider.asymmetric.util.KemSpiUtil`, `jdk17`-only.
- Check: `find <module>/src/main -name <Callee>.java` — a directory with a version **higher** than the caller's makes the call unsafe. Confirm against the jar: `unzip -l <module>/build/libs/bcprov-jdk18on-*.jar | grep '<Callee>.class'` — callee at `versions/17` and `versions/25`, caller only at `versions/17`, is the broken shape.
- **The reverse direction too:** a root class compiled against a hook's base copy is paired on JDK 9+ with its `versions/9` copy, so the copies must agree on every member a root caller uses, name *and* descriptor (return type included). `tls`'s `SSLEngineUtil.create(ContextData)` returned `SSLEngine` in `jdk1.5` and `ProvSSLEngine` in `jdk1.9`, so `SSLContext.createSSLEngine()` threw `NoSuchMethodError` on JDK 9+ in 1.86 (github #2448), exposed once `-implicit:none` stopped `compileJava9Java` recompiling the base tree into `versions/9`.

**Both directions are machine-checked.** `gradle/multirelease.gradle` gives every distributed module a `multiReleaseCheck` task (on `check`, so `build` runs it): it reads the constant pool of every class in the built jar plus the sibling BC jars it depends on, as one class universe (`bccore` excluded — it ships inside `bcprov`), and fails when a member reference does not resolve against the copy a JDK would pair with the caller. A failure reads `<caller> (root) -> <owner>.<name><descriptor> is absent from the versions/N copy paired with it on JDK N`; fix by making the copies agree or moving the member to a class with no twin — never by widening the gate. For jars the build did not produce, the root project has `multiReleaseCheckJar`: `./gradlew multiReleaseCheckJar -PmrJar=<jar>[,<jar>]` checks each jar alone, `-PmrClasspath=<jar>,<jar>,...` loads them as one universe (first jar wins on a duplicate). Negative test after any change to the script: the published `bctls-jdk18on-1.86.jar` must report exactly the two `SSLEngineUtil.create` pairings. Pair the gate with a test in the highest overlay's test tree (`tls/src/test/jdk25/.../SSLEngineMRTest`): the gate proves the jar links, the test proves the path runs.

## Update `module-info.java` when you add or remove package

Each Gradle module has a JPMS descriptor at `<module>/src/main/jdk1.9/module-info.java`; it is what modular (JDK 9+ `--module-path`) consumers see. An unlisted package is invisible to them but fine on the class path, so the omission is easy to miss — only a modular consumer gets `module org.bouncycastle.provider does not export …`.

- **New class in an existing package** — no change; descriptors export packages.
- **New package** — add `exports org.bouncycastle.<pkg>;` to the module whose `src/main/java` holds it (`prov` covers `core`, which has no descriptor; others: `util`, `pkix`, `tls`, `mail`/`jmail`, `pg`, `pgsc`, `mls`).
- **Removed package** — remove its `exports`.
- **New module** — needs its own `src/main/jdk1.9/module-info.java` plus the `java9` source set and `META-INF/versions/9` jar wiring in `build.gradle` (copy `pg`'s), or it ships as a file-name-derived automatic module (`pgsc` nearly did in 1.87).
- **`prov` has a second descriptor**, `prov/src/main/ext-jdk1.9/module-info.java`, for the legacy Ant build. Keep it **identical** to the jdk1.9 one (`diff` prints nothing); nothing fails when it drifts.

## The OSGi `Export-Package` manifest is a *second*, silent place to wire a package

Each module's `build.gradle` applies `biz.aQute.bnd.builder` and sets `Export-Package` / `Import-Package` from a `packages` brace-list (e.g. `pkix`'s `org.bouncycastle.{cades|cert|cmc|cms|…|tsp}.*`, `util`'s `org.bouncycastle.asn1.{bsi|cmc|…|tsp}.*` plus `org.bouncycastle.oer.*`), independent of `module-info.java`:

- A new sub-package of a listed family is covered by the `.*` glob.
- A **new top-level family** must be added to the `packages` string, or it is silently missing from the bundle (`cades` in `pkix` and `asn1.mod` in `util` were). Only the built jar's `META-INF/MANIFEST.MF` shows it.
- **`prov` is the exception**: `!org.bouncycastle.internal.*,org.bouncycastle.*;version=…` exports everything but `internal.*`, so new prov/core packages need no `build.gradle` edit — but a package meant to be concealed must be added to the `!…` prefix (`org.bouncycastle.apache.bzip2` is OSGi-exported but JPMS-concealed).

So "add a package" is a three-file habit: `module-info.java` (both prov descriptors), `package-info.java`, and — for a new top-level family outside `prov` — the `build.gradle` `packages` list. Removing a family means all three.

## Every new package ships a `package-info.java`

Add it with the first class: a one-sentence Javadoc above `package …;` saying what the package is for, pointing at the RFC/spec/sibling package where useful. Mirror existing ones (`pkix/.../cms/package-info.java`, `core/.../asn1/package-info.java`). Without it the package is an unnamed bucket in the API docs.

## Examples live in `misc/`, not in the Gradle modules

- Example/demo code goes in `misc/src/main/java/org/bouncycastle/<area>/examples/`, never in a published module (it would ship in the `bc*` jars and become exported API). No published module has an `examples` package under `src/main/java` now, and no `module-info.java` exports one. When moving examples in, drop any `exports …examples;` from the source module's descriptors (both prov ones if from `prov`).
- Not counterexamples: `<module>/src/main/javadoc/.../examples` (javadoc only), `core/src/main/j2me/.../crypto/examples` and `pg/src/main/jdk1.1/.../openpgp/examples` (legacy overlays).
- `misc` is a Gradle module, deliberately **non-publishing**: `./gradlew :misc:build` compiles and smoke-tests examples, but it has no `publishing` block and is not in the root `distModules`. Keep it that way.
- Checkstyle exempts `org.bouncycastle..*.examples.*` from `DebugMethodChecker`, so examples carry **no** `-DM` squelch comments; Allman-brace checks still apply.
- `misc/build.gradle` declares its cross-module deps explicitly (`prov`, `util`, `pkix`, `pg`, `mail`, `javax.mail`) since `project(...)` deps are non-transitive; `misc/src/test` has its own `PrintTestResult` copy.
- Test harnesses needing third-party jars belong here too (e.g. `org.bouncycastle.mls.examples.client`, the MLS gRPC interop runner). Take such dependencies **by Maven coordinate**, never as jars under `test/libs` via `files()` — those are invisible to Dependabot and scanners (that gRPC/protobuf set drifted three CVEs behind).
- For a non-standard JCE alias BC deliberately doesn't register (e.g. `Cipher.ECIESwithSHA256andAES-ECB`, github #1095): don't register it; ship a `misc/` example building it via the lightweight API, whose class javadoc gives the reason (cite the standards) and points at the compliant variant. Model: `misc/.../crypto/examples/ECIESAESECBExample.java`.

## JCE provider registration

`BouncyCastleProvider` registers by name via `ConfigurableProvider.addAlgorithm("Cipher.SM2", "...GMCipherSpi$SM2")`. Per-family registration lives in `prov/src/main/java/org/bouncycastle/jcajce/provider/{asymmetric,symmetric,digest,keystore,...}/<Family>.java`, with the `*Spi` classes as siblings — that `Family.java` is the entry point for a JCE-visible change. The lightweight engine is usually in `core/.../crypto/engines/`.

## PQC algorithms: BCPQC ≠ BC

PQC algorithms live in the separate `BouncyCastlePQCProvider` (`BCPQC`), whose service table is independent of `BC`'s. `BouncyCastleProvider.loadPQCKeys()` is the bridge: it must `addKeyInfoConverter(oid, new <Alg>KeyFactorySpi())` for **every** PQC OID, or certificates and PKCS#8 keys using it decode through `BCPQC` but not through `BC` (the common path). Keep `<Alg>Engine` package-private and drive KATs through the public generator/signer with `FixedSecureRandom` / `NISTSecureRandom`. For any port — signature or KEM, which follows the same checklist shape — use the `bcpqc-add-algorithm` skill, which holds the full file checklist and the signature-encoding contract.

## Package layering: `.bc` (lightweight) vs `.jcajce` (JCA/JCE)

In `pkix`, `pg`, `mail`/`jmail`, `tls` and `mls`:

- **`.bc` subpackages** use `org.bouncycastle.crypto.*` directly (`cms.bc`, `openpgp.bc`, `operator.bc`).
- **`.jcajce` subpackages** use `java.security.*` / `javax.crypto.*`, usually through a `JcaJceHelper` (`cms.jcajce`, `openpgp.operator.jcajce`, `operator.jcajce`).
- **Top-level packages** (`cms`, `openpgp`, `cades`, `cert`, …) abstract over both. They may use `org.bouncycastle.operator` / `cert` / `asn1` types (`DigestCalculatorProvider`, `ContentSigner`, `ContentVerifier`, `X509CertificateHolder`) but must not import any `java.security.*` / `javax.crypto.*` class except `java.security.SecureRandom`, nor any `org.bouncycastle.crypto.*` class (no exception at all).

In practice: a top-level digest takes a `DigestCalculatorProvider`; a top-level signature check takes a `ContentVerifierProvider` / `SignerInfoVerifier` (define a new operator in `org.bouncycastle.operator`, or module-locally like `cert.plants.MTCCosignerVerifierProvider`, with `.bc`/`.jcajce` implementations if none fits); a `Signer` / `AsymmetricKeyParameter` parameter means the class belongs in `.bc`; to wrap a `Jca*` builder, wrap its JCA-free parent (`SignerInfoGeneratorBuilder`) or move to `.jcajce`; JCA- or lightweight-friendly factories go in the peer package. Decide the split up front for a new package.

**`pg` extra rule, machine-enforced:** `org.bouncycastle.openpgp.operator` (and subpackages) must not import `org.bouncycastle.openpgp.api.*`; a class needing both goes in `org.bouncycastle.openpgp.api.operator` (where `PGPContentSignerBuilderProviderFactory` is). `config/checkstyle/import-control-pg-operator.xml` enforces it, failing `:pg:checkstyleMain` with `Disallowed import - org.bouncycastle.openpgp.api.<X>. [ImportControl]`. Checkstyle sees only imports — watch for fully-qualified names in review.

## Shared prov/pkix cert-path logic goes in `asn1.x509` as a public pure-ASN.1 validator

prov's `jce/provider` validator, prov's legacy `org.bouncycastle.x509` API and pkix's `pkix/jcajce` revocation checker cannot share package-private code (prov cannot see pkix; `org.bouncycastle.internal.*` is JPMS-concealed and OSGi-excluded). When the same RFC 5280 logic is needed in more than one stack:

- Extract a **public, pure-ASN.1 engine class into core's `org.bouncycastle.asn1.x509`** with a **public checked exception** (no module-info/OSGi edits needed).
- Keep thin per-module wrappers that do the JCA extraction and rethrow as their local `AnnotatedException`, message text verbatim.
- Keep extraction *lazy* where the original was: expose `requiresX(...)` predicates rather than having a wrapper eagerly compute a value whose failure the original reached only conditionally.
- Worked examples: `PKIXNameConstraintValidator` / `NameConstraintValidatorException` (RFC 5280 sec. 6.1.4), `PKIXCRLValidator` / `CRLValidatorException` (sec. 6.3.3).
- JCA-bound duplication (CertPathBuilder plumbing, `Signature`/CRL verification, store selectors) does not fit; sharing it would mean new public JCA API in prov.

## `core` keeps the JDK security API out: SecureRandom + Destroyable only

`core/src/main/java` may use exactly:

- **`java.security`**: `SecureRandom` only.
- **`javax.security`**: `javax.security.auth.Destroyable` and `DestroyFailedException` only.
- **`javax.crypto`**: nothing.

No JCA operation or spec class (`MessageDigest`, `Signature`, `Cipher`, `KeyFactory`, `java.security.cert.*`, `java.security.spec.*`, …) — that is the `prov` `*Spi` layer's job. The vetted exceptions are five files of security-manager/configuration plumbing: `CryptoServicesPermission`, `CryptoServicesRegistrar`, `util/Properties`, `util/Strings`, `util/test/FixedSecureRandom`. Don't add to them without the maintainer signing off.

Machine-enforced: `config/checkstyle/import-control-core.xml`, applied path-scoped to `core/src/main/java` (also when the `prov` checkstyle task sees the core sources). A violation fails `:core:checkstyleMain` with `Disallowed import - <class>. [ImportControl]`; a newly vetted exception means editing that file's per-file `allow` list. Only imports are checked — watch for fully-qualified names in review. The jdk1.1/jdk1.2 overlays legitimately *contain* `java/security/...` backport sources; the legacy Ant builds don't run this check.
