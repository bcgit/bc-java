# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build & test

The build is Gradle multi-module. JDK 21+ is required to drive Gradle. Optional environment variables `BC_JDK8`, `BC_JDK11`, `BC_JDK17`, `BC_JDK21`, `BC_JDK25` opt in version-specific test tasks (compiled against MR-jar overlays). The default `:test` aggregates `:core:test :prov:test :prov:test11 :prov:test15 :prov:test17 :pkix:test :pg:test :tls:test :mls:test :mail:test :jmail:test`.

```
./gradlew clean build                                # full build + all tests
./gradlew :prov:compileJava :prov:compileTestJava    # quick compile-only check
./gradlew :prov:test --tests <fqcn>                  # one JUnit class
./gradlew -PexcludeTests=<glob> :prov:test           # exclude pattern
```

`bc-test-data` (separate repo `bcgit/bc-test-data`) must be checked out for the full suite to pass. `TestResourceFinder.findTestResource(homeDir, fileName)` (six per-module copies under `<module>/src/test/java/org/bouncycastle/test/`) resolves the bc-test-data root in this order:

1. The system property `bc.test.data.home`, if set.
2. The environment variable `BC_TEST_DATA_HOME`, if set.
3. Walk up from the working directory looking for a directory literally named `bc-test-data` — the default that makes `./gradlew :prov:test` work when bc-test-data is checked out as a sibling of `bc-java`.

When the property or environment variable is supplied, the named path is required to exist; a mistyped value fails fast with a `FileNotFoundException` naming both the source (`-Dbc.test.data.home` or `$BC_TEST_DATA_HOME`) and the bad path, rather than silently falling through. The Gradle build no longer sets the property itself; supply `-Dbc.test.data.home=/path/to/bc-test-data` (or export `BC_TEST_DATA_HOME` once in your shell) only when the sibling-checkout convention doesn't fit your layout. Direct `java -cp ... junit.textui.TestRunner ...` invocations follow the same rule.

### Running an individual test fast

Two conventions coexist:

- `org.bouncycastle.util.test.SimpleTest` subclasses (~half of the suite) override `performTest()` and call `fail(msg)` / `isTrue(msg, cond)` / `areEqual(a, b)`. They have a `main()` that registers `BouncyCastleProvider` and prints `<TestName>: Okay` on success or `<TestName>: <message>` on failure.
- `junit.framework.TestCase` subclasses (the other half, especially in `pkix/.../pkcs/test`, `pkix/.../cms/test`, etc.) use plain JUnit assertions and are aggregated by an `AllTests` suite class. Run one via `junit.textui.TestRunner`:
  ```
  java -cp ... junit.textui.TestRunner org.bouncycastle.pkcs.test.PKCS12UtilTest
  ```

To iterate quickly on either flavour, run directly without Gradle. The full classpath you need:

```
java -cp pkix/build/classes/java/main:pkix/build/classes/java/test:pkix/src/test/resources:\
        prov/build/classes/java/main:prov/build/classes/java/test:prov/build/resources/main:\
        prov/src/test/resources:\
        core/build/classes/java/main:core/build/classes/java/test:core/build/resources/main:\
        core/src/test/resources:\
        util/build/classes/java/main:\
        $(find ~/.gradle -name 'junit-*.jar' | head -1):\
        $(find ~/.gradle -name 'hamcrest-core-1*.jar' | head -1) \
     org.bouncycastle.openssl.test.ParserTest
```

If your bc-test-data checkout isn't a sibling of `bc-java`, add `-Dbc.test.data.home=/abs/path/to/bc-test-data` to the command. Otherwise the walk-up search picks it up automatically.

Common gotchas:
- `*/build/resources/main` directories are required — some tests pull resource files (e.g. `lowmcL1.bin.properties` for Picnic, GOST tables) that fail with cryptic `NullPointerException` if missing.
- `prov/src/test/resources` and `core/src/test/resources` carry test fixtures referenced by `TestResourceFinder` and direct classpath lookups.
- IDE-built classes under `out/production/...` (IntelliJ) are NOT on the Gradle classpath — don't reference them, and beware that they can drift from Gradle's outputs.
- After deleting or renaming a test method (e.g. when rolling back an edit), the stale `.class` file lingers under `<module>/build/classes/java/test/`. JUnit's `TestSuite.class` reflection-walk will still find and run the stale method, surfacing confusing `ClassNotFoundException` / `NoClassDefFoundError` for inner-class artifacts that were removed. Run `./gradlew :<module>:compileTestJava --rerun-tasks` (or `:<module>:clean`) after a rollback to flush.

### Verifying a fix actually catches the bug

The repo's working norm for any defect-fix patch is: write the test that reproduces the bug, then **stash the fix** (`git stash push <fix-files>`), recompile (`./gradlew :<module>:compileJava`), rerun the test to confirm it now fails on the original symptom, then `git stash pop` and rerun to confirm it now passes. This catches tests that pass for the wrong reason. Use it whenever you add a regression test alongside a fix.

When the fix is in `core/`, remember to recompile `prov` too (the `core`-into-`prov` trap below) so the test JVM picks up the updated bytecode rather than a stale `prov/build/classes` shadow.

## Architecture

### Module graph and the `core`-into-`prov` trap

```
core ── lightweight crypto API (engines, digests, ASN.1, math, params)
util ── ASN.1/X.500 helpers used by pkix
prov ── JCA/JCE provider (BouncyCastleProvider, BouncyCastlePQCProvider) — depends on core
pkix ── X.509 / CMS / TSP / OCSP / PKCS#12 / OpenSSL PEM — depends on prov
pg   ── OpenPGP                          — depends on prov
tls  ── TLS API + JSSE provider          — depends on prov
mail / jmail ── S/MIME on top of CMS     — depends on pkix
mls  ── Messaging Layer Security
```

**Important quirk**: `prov/build.gradle` adds `core/src/main/java` directly to its `srcDirs`. The published `bcprov-<vmrange>.jar` therefore contains both the `core` lightweight API **and** the `prov` JCE provider classes. Practical implications:

- Editing a file under `core/src/main/java/...` will be compiled twice — once by `:core:compileJava`, once by `:prov:compileJava`. If a stale `prov` class file persists after a `core` change, classes loaded from `prov/build/classes/...` may shadow your edit. When in doubt, run `:prov:compileJava --rerun-tasks` or clear `prov/build/classes`.
- A change in `core` can break `prov` tests that compile against both source trees.

### Multi-Release JAR overlays

`prov`, `pkix`, `pg`, `tls`, etc. ship as MR-jars. Inside each module:

- `src/main/java` — base sources, compiled with `--release 8`
- `src/main/jdk1.9`, `jdk1.11`, `jdk1.15`, `jdk17`, `jdk25` — version-specific overlays packaged under `META-INF/versions/<n>/`
- `src/main/j2me`, `src/main/jdk1.1` … `jdk1.5`, `src/main/ext-jdk1.9` — alternate distributions for the legacy Ant builds (J2ME, pre-1.6 JDKs). **Gradle does not compile these.** Don't edit them when fixing a Gradle-build bug; they're separate trees maintained for the J2ME/legacy distributions.

The same applies to tests: `src/test/java` is the Gradle-driven tree; `src/test/jdk1.4`, `src/test/j2me`, `src/test/jdk1.1` are alternate trees, while `src/test/jdk1.11`, `jdk1.15`, `jdk17`, `jdk25` are MR-jar test overlays driven by the `test11`/`test15`/`test17`/`test25` Gradle tasks.

### Update `module-info.java` when you add or remove package

Each Gradle-built module has a JPMS descriptor at `<module>/src/main/jdk1.9/module-info.java` (e.g. `prov/src/main/jdk1.9/module-info.java`, `pkix/src/main/jdk1.9/module-info.java`) listing every exported package. The Java 8 sources under `<module>/src/main/java` and the descriptor are bundled into the same multi-release jar; the descriptor is the source of truth for what's visible when downstream code runs on JDK 9+ with `--module-path`. A package that exists in the source tree but isn't listed in `module-info.java` is invisible to modular consumers — class-path consumers still see it, which is why the omission is easy to miss locally. Note: `core` itself has no module-info; its sources are bundled into the published `bcprov` jar via the core-into-prov srcDirs trick, so the `prov` module-info exports `core` packages.

`prov` additionally carries a parallel `prov/src/main/ext-jdk1.9/module-info.java` for the legacy Ant build that ships separately. Edits to the Gradle-driven `prov/src/main/jdk1.9/module-info.java` should be mirrored to the `ext-jdk1.9` variant for symmetry — it's not Gradle-built, but it's tracked and consumed by the legacy distribution.

When you add a class, ask which case applies:

- **Existing package** (e.g. dropping `ECBModeCipher` into `org.bouncycastle.crypto.modes`, already in `prov/.../module-info.java`) — no descriptor change needed. `module-info.java` exports packages, not classes.
- **New package** (a directory that doesn't yet exist under any `org.bouncycastle.*` tree) — add `exports org.bouncycastle.your.new.package;` to the corresponding module's `module-info.java`. The Gradle modules are `prov` (which also covers core), `util`, `pkix`, `tls`, `mail` / `jmail`, `pg`, `mls` — pick the one whose `src/main/java` your new package physically lives under.

Symmetrically, if you delete or merge away an entire package, remove its `exports` entry from both the `jdk1.9` and (where it exists) `ext-jdk1.9` descriptors. The compile-time signal that catches a missed entry — `module org.bouncycastle.provider does not export org.bouncycastle.crypto.foo` — only fires for modular downstream consumers, so a class-path-only test run won't surface it.

### Examples live in `misc/`, not in the Gradle modules

`misc/` is a non-Gradle source tree (not in `settings.gradle`, no `build.gradle`) used as the canonical home for example / demo code. Existing example packages: `misc/src/main/java/org/bouncycastle/{asn1,crypto,jcajce,openpgp,pqc/crypto}/examples/`. New example code should land here, not under `core/.../examples`, `prov/.../examples`, `pg/.../openpgp/examples`, etc. — putting it inside a Gradle module would force it into the published `bc*` jars and make it part of the JPMS-exported API surface. `pg/src/main/java/org/bouncycastle/openpgp/examples/` already exists as a legacy quirk and is published; the rule applies symmetrically — new OpenPGP example code goes under `misc/.../openpgp/examples/` instead (the package was added there for github #1414's `PublicKeyByteArrayHandler`, complementing the older PBE-only `ByteArrayHandler` in pg).

When moving existing example code into `misc/`, remember to drop any matching `exports …examples;` line from the source module's `module-info.java` files (both `jdk1.9` and `ext-jdk1.9` variants when the source was `prov`).

When the natural place for an example would be a generic JCE alias that BC deliberately doesn't ship (e.g. `Cipher.ECIESwithSHA256andAES-ECB` — non-standard for ECIES per IEEE 1363a / ISO 18033-2 / SECG SEC 1; see `misc/.../crypto/examples/ECIESAESECBExample.java` for the model, github #1095), the convention is: don't register the alias, ship a `misc/` example that builds the construction locally via the lightweight API, and open the class-level javadoc with the reason BC doesn't endorse the named form (cite the relevant standard sections) plus a pointer at the standards-compliant variant production callers should prefer. The example exists so the next person searching for the non-standard form has a concrete answer rather than nothing.

### JCE provider registration

`BouncyCastleProvider` (in `prov`) registers algorithms by string name through `ConfigurableProvider.addAlgorithm("Cipher.SM2", "...GMCipherSpi$SM2")` etc. Per-algorithm registration code lives in `prov/src/main/java/org/bouncycastle/jcajce/provider/{asymmetric,symmetric,digest,keystore,...}/<Family>.java`. The corresponding `*Spi` classes (CipherSpi, KeyFactorySpi, KeyPairGeneratorSpi, etc.) are siblings under the same package. When adding or fixing a JCE-visible behaviour, the registration `Family.java` is the entry point; the underlying lightweight engine usually lives in `core/src/main/java/org/bouncycastle/crypto/engines/`.

### Adding a PQC algorithm: BCPQC ≠ BC, but BC needs the OID table too

PQC algorithms live in a second provider, `BouncyCastlePQCProvider` (`BCPQC`), separate from `BouncyCastleProvider` (`BC`). The two providers have independent service tables. A new algorithm wired only into `BCPQC` will be reachable through `*.getInstance(name, "BCPQC")` calls and matching MR-jar / module-info exports, but it will NOT be recognised when a `X.509 CertificateFactory` / `KeyFactory` / etc. is obtained from the standard `BC` provider — which is the much more common path in caller code, because most BC-using applications add only `BouncyCastleProvider`.

The bridge is `BouncyCastleProvider.loadPQCKeys()` in `prov/src/main/java/org/bouncycastle/jce/provider/BouncyCastleProvider.java`. It is called from the `BouncyCastleProvider` constructor and registers an `AsymmetricKeyInfoConverter` (typically the BCPQC-side `KeyFactorySpi`) against every PQC OID via `addKeyInfoConverter(OID, new <Pqc>KeyFactorySpi())`. The `BC` provider's certificate / PKCS#8 / SubjectPublicKeyInfo parsing then routes unknown OIDs through this converter table — so a `CertificateFactory.getInstance("X.509", "BC")` can extract and decode a FAEST / Snova / Mayo / etc. public key even though the actual algorithm is implemented in BCPQC.

Practical checklist when porting a new PQC algorithm — easy to leave any of these out and end up with a half-wired addition:

- `core/src/main/java/org/bouncycastle/asn1/bc/BCObjectIdentifiers.java` (or `NISTObjectIdentifiers.java` for NIST-standardised schemes) — one OID per parameter set. **Grep the existing `bc_sig.branch(...)` / `bc_kem.branch(...)` arcs before picking a number.** A collision with another algorithm's parent arc is silent at compile time and only fires when `BouncyCastlePQCProvider.<init>` runs the second `Mappings.configure`, where it throws `IllegalStateException: duplicate provider key (Alg.Alias.KeyFactory.<oid>)` — diagnosable but not until provider load.
- `core/src/main/java/org/bouncycastle/pqc/crypto/<alg>/` — lightweight classes: `*Parameters`, `*PublicKeyParameters`, `*PrivateKeyParameters`, `*KeyGenerationParameters`, `*KeyPairGenerator`, `*Signer` (or KEM equivalents).
- `core/src/main/java/org/bouncycastle/pqc/crypto/util/Utils.java` — `<alg>Oids` / `<alg>Params` maps plus `<alg>OidLookup` / `<alg>ParamsLookup` helpers.
- `core/src/main/java/org/bouncycastle/pqc/crypto/util/PublicKeyFactory.java` — `<Alg>Converter` inner class + one `converters.put(oid, new <Alg>Converter())` per OID.
- `core/src/main/java/org/bouncycastle/pqc/crypto/util/PrivateKeyFactory.java` — `else if (algOID.on(BCObjectIdentifiers.<alg>))` branch.
- `core/src/main/java/org/bouncycastle/pqc/crypto/util/SubjectPublicKeyInfoFactory.java` and `PrivateKeyInfoFactory.java` — `instanceof <Alg>PublicKeyParameters` / `<Alg>PrivateKeyParameters` branches.
- `prov/src/main/java/org/bouncycastle/pqc/jcajce/spec/<Alg>ParameterSpec.java` — `AlgorithmParameterSpec` with one constant per parameter set + `fromName(String)` lookup.
- `prov/src/main/java/org/bouncycastle/pqc/jcajce/interfaces/<Alg>Key.java` — `extends Key` with `getParameterSpec()`.
- `prov/src/main/java/org/bouncycastle/pqc/jcajce/provider/<alg>/` — `BC<Alg>PublicKey` (use `Arrays.areEqual`) and `BC<Alg>PrivateKey` (use `Arrays.constantTimeAreEqual` in `equals()` for the secret-bearing path), `<Alg>KeyFactorySpi`, `<Alg>KeyPairGeneratorSpi`, `SignatureSpi` (or KEM equivalents) — each with one inner subclass per parameter set.
- `prov/src/main/java/org/bouncycastle/pqc/jcajce/provider/<Alg>.java` — `Mappings` extending `AsymmetricAlgorithmProvider`, calling `addKeyFactoryAlgorithm` / `addKeyPairGeneratorAlgorithm` / `addSignatureAlgorithm` for each parameter set.
- `prov/.../jcajce/provider/BouncyCastlePQCProvider.java` — add `"<Alg>"` to `ALGORITHMS`.
- `prov/.../jce/provider/BouncyCastleProvider.java` — in `loadPQCKeys()`, `addKeyInfoConverter(BCObjectIdentifiers.<alg>_<param>, new <Alg>KeyFactorySpi())` for every OID. **This is the BCPQC→BC bridge; skip it and certs / PKCS#8 work fine through BCPQC but break through BC.** Test it.
- `prov/src/main/jdk1.9/module-info.java` — `opens org.bouncycastle.pqc.jcajce.provider.<alg> to java.base;` plus `exports org.bouncycastle.pqc.crypto.<alg>;` plus `exports org.bouncycastle.pqc.jcajce.provider.<alg>;`. Mirror `pqc.crypto.<alg>` into `prov/src/main/ext-jdk1.9/module-info.java` (the legacy distribution does not export the JCE-side `provider.<alg>` packages).
- Tests in `prov/src/test/java/org/bouncycastle/pqc/jcajce/provider/test/<Alg>Test.java` plus an entry in `AllTests.java`. Include a `testBcProviderKeyInfoConverter`-style case that exercises `BouncyCastleProvider.getPublicKey(SubjectPublicKeyInfo)` and `getPrivateKey(PrivateKeyInfo)` against every parameter set, proving the `loadPQCKeys()` registration works.
- `docs/releasenotes.html` — one `<li>` under the current unreleased version's "Additional Features and Functionality" block.

### PQC engines should stay package-private — drive KATs through the public API

The lightweight `<Alg>Engine` produced when porting a reference C/Rust implementation tends to expose low-level entry points (`engine.keyGen(seedKey, sk, pk)`, `engine.sign(sk, msg, salt, mseed)`) that KAT vectors need but legitimate callers never touch. Resist the urge to make `<Alg>Engine` public just so `<Alg>KatTest` can poke at internals — that leaks the engine into the published `bcprov` API surface where it becomes load-bearing, and any future internal refactor has to preserve the engine signature too.

The standard pattern is to keep the engine package-private and drive `<Alg>KeyPairGenerator` / `<Alg>Signer` with a deterministic `SecureRandom` that emits exactly the bytes the KAT prescribes:

- `org.bouncycastle.util.test.FixedSecureRandom(bytes)` — emits a pre-baked byte sequence, single-shot (reconstruct it for each call site that needs the same seed). Use when the test wants a specific seed.
- `org.bouncycastle.pqc.crypto.test.NISTSecureRandom(seed, personalization)` — the NIST CTR-DRBG upstream KAT generators use to derive per-vector randomness from a 48-byte seed. The same DRBG instance can be reused across keygen + sign because the public-API call sites consume from it in the same order the reference C harness did.

Concrete: `MQOMKeyPairGenerator.generateKeyPair` reads `2 * seedSize` bytes via `random.nextBytes`; `MQOMSigner.generateSignature` then reads `mseed` (`seedSize`) followed by `salt` (`saltSize`). A single `NISTSecureRandom drbg = new NISTSecureRandom(seed, null)` shared between both calls reproduces the upstream KAT byte-for-byte without any engine reference. `UOVKeyPairGenerator` and `HawkKeyPairGenerator` follow the same shape (32-byte `SK_SEED_BYTES` for UOV, `SALT_BYTES` from `<Alg>Parameters` etc.). The rewritten `MQOMTest` / `MQOMKatTest` / `UOVTest` and the already-conforming `HawkTest` are the worked examples.

If you find yourself unable to demote `<Alg>Engine` to package-private without breaking tests, that is the symptom — rewrite the tests against the public `<Alg>KeyPairGenerator` / `<Alg>Signer` with `FixedSecureRandom` / `NISTSecureRandom` first, then demote.

### Package layering: `.bc` (lightweight) vs `.jcajce` (JCA/JCE)

The high-level modules (`pkix`, `pg`, `mail`/`jmail`, `tls`, `mls`) split their public surface by which low-level crypto stack a class touches:

- **`.bc` subpackages** — lightweight implementations using `org.bouncycastle.crypto.*` engines / signers / digests directly. Examples: `org.bouncycastle.cms.bc`, `org.bouncycastle.openpgp.bc`, `org.bouncycastle.operator.bc`.
- **`.jcajce` subpackages** — JCA/JCE implementations that call `java.security.*` / `javax.crypto.*` classes (typically through a `JcaJceHelper` so the provider is overridable). Examples: `org.bouncycastle.cms.jcajce`, `org.bouncycastle.openpgp.operator.jcajce`, `org.bouncycastle.operator.jcajce`.
- **Top-level packages** (e.g. `org.bouncycastle.cms`, `org.bouncycastle.openpgp`, `org.bouncycastle.cades`, `org.bouncycastle.cert`) — abstractions over BOTH stacks. They may take `DigestCalculatorProvider` / `ContentSigner` / `ContentVerifier` / `X509CertificateHolder` etc. from `org.bouncycastle.operator`, `org.bouncycastle.cert`, and `org.bouncycastle.asn1`, but must not import:
    - `java.security.MessageDigest`, `java.security.Signature`, `javax.crypto.Cipher`, `java.security.cert.X509Certificate` (or any other `java.security.*` / `javax.crypto.*` class) — those belong in `.jcajce`;
    - `org.bouncycastle.crypto.*` (engines, signers, digests, params, generators) — those belong in `.bc`.

The only `java.security` class allowed to be referenced from a non-`.jcajce` package is `java.security.SecureRandom`. There is **no** equivalent exception for `org.bouncycastle.crypto.*`: any direct lightweight import means the class belongs in a `.bc` subpackage, full stop.

Practical implications when adding code:

- Need an algorithm digest in a top-level utility? Take a `DigestCalculatorProvider` parameter and call `provider.get(algId).getOutputStream().write(...)` — never `MessageDigest.getInstance(...)` and never `new SHA256Digest()`.
- Need to verify a signature in a top-level utility? Take a `ContentVerifierProvider` / `SignerInfoVerifier` (or similar operator) — never `Signature.getInstance(...)` and never `new Ed25519Signer()`. If no existing operator fits, define one in `org.bouncycastle.operator` (or a module-local equivalent like `org.bouncycastle.cert.plants.MTCCosignerVerifierProvider`) and ship lightweight and JCA implementations as `.bc` / `.jcajce` peers.
- Need a `Signer` or `AsymmetricKeyParameter` parameter? That's a `.bc` signature — push the class into the `.bc` subpackage.
- Need to wrap an existing `Jca*` builder? Either (a) wrap the JCA-free parent (e.g. wrap `SignerInfoGeneratorBuilder` instead of `JcaSignerInfoGeneratorBuilder`) so the class can stay at the top, or (b) move the class into the `.jcajce` subpackage.
- A top-level class that does need to expose a JCA-friendly or lightweight-friendly factory method should ship the factory in its `.jcajce` or `.bc` peer instead of pulling JCA/lightweight imports into the top package.

The rule applies uniformly to `pkix` (`cms`, `cades`, `tsp`, `cert`, `operator`, ...), `pg`, `mail`/`jmail`, `tls`, and `mls`. When adding a new package under any of these modules, decide on the split up-front: if any class needs `java.security` / `javax.crypto` beyond `SecureRandom`, the package should be a `.jcajce` subpackage; if any class needs `org.bouncycastle.crypto.*`, the package should be a `.bc` subpackage. A JCA-free, lightweight-free top-level parent is usually still appropriate to host the operator interfaces both flavours adapt to.

### Test conventions

- Most tests extend `org.bouncycastle.util.test.SimpleTest` (not JUnit). They override `performTest()` and call `fail(msg)` / `isTrue(msg, cond)` / `areEqual(a, b)`. They are *not* discovered by Gradle directly — they're invoked from JUnit `AllTests` / `RegressionTest` wrappers.
- `RegressionTest.tests` arrays (one per package) list every `SimpleTest` to be run. When you add a new `SimpleTest`, also add a call from a parent test or from `RegressionTest`.
- Tests pass `-Dbc.test.data.home=<core/src/test/data>` for fixture lookups.
- The `:test` task runs each test class in its own JVM (`forkEvery = 1`).

### X.509 ASN.1 changes — check the RFC first

Anything under `core/src/main/java/org/bouncycastle/asn1/x509/` is a wire-format ASN.1 type from a specific PKI RFC. Before changing or extending one of these classes (parsing rules, structural constraints, defaults, error messages thrown for malformed input), verify the proposed behaviour against the authoritative RFC:

- Most extensions and the certificate / CRL container types: **RFC 5280** (extensions in §4.2.x, cert fields in §4.1.x, CRL fields in §5.1.x).
- Attribute certificates (`AttributeCertificateInfo`, `Holder`, `AttCertIssuer`, `V2Form`, `IssuerSerial`, etc.): **RFC 5755** (current; previously RFC 3281).
- OCSP types (`OCSPResponse`, `BasicOCSPResponse`, `ResponseData`, etc.): **RFC 6960**.
- Validation policy / qualified-cert types: RFC 3739 / RFC 3279 / X9.62 as appropriate.

When the RFC contains a "MUST" / "MUST NOT" that the existing code doesn't enforce, that's the actionable spec — cite the section in the commit message and (where helpful) in javadoc. When the RFC is silent, prefer staying compatible with what other major libraries (OpenSSL, Java's CertificateFactory, GnuTLS) accept rather than tightening unilaterally. Same convention applies to neighbouring ASN.1 PKI packages (`asn1/pkcs`, `asn1/cms`, `asn1/cmp`, `asn1/ocsp`) — cite RFC 7292 / 5652 / 4210 / 6960 etc.

For X.509 / WebPKI work specifically, the **CAB Forum** Baseline Requirements (<https://cabforum.org/>) layer additional constraints on top of RFC 5280 — key sizes, signature algorithm sets, extension presence/criticality, profile-specific name encodings, etc. Where a CAB Forum BR or guideline narrows what RFC 5280 allows and the change makes sense for general-purpose BC users (not just publicly-trusted CAs), follow the BR rather than the looser RFC. Cite the BR section alongside the RFC in the commit message / javadoc, and call out in the PR when a change is BR-driven so reviewers know it's deliberately stricter than the RFC.

### Exception messages are part of the test contract

Many tests assert on exact exception message text (e.g. `isTrue(e.getMessage().equals("..."))` or `getCause().getMessage()` checks). Changing the wording of a thrown exception — even something as small as adding a colon, rewording for clarity, or wrapping with `Exceptions.illegalArgumentException(...)` — will silently break tests in another module. Before modifying any exception message, grep the whole tree for the existing string and update every matching assertion in lockstep.

### System / security property constants

Any system or security property that controls BC behaviour belongs in `core/src/main/java/org/bouncycastle/util/Properties.java` as a `public static final String`, e.g. `Properties.PKCS12_MAX_IT_COUNT`, `Properties.PKCS12_IGNORE_USELESS_PASSWD`, `Properties.EMULATE_ORACLE`. Callers should reference the constant rather than inlining the literal `"org.bouncycastle.…"` name — both in production code and in tests that flip the property via `System.setProperty`. New properties should be added to `Properties` with the same naming pattern (`org.bouncycastle.<area>.<flag>`).

### Non-standard format interop

When supporting a non-standard wire encoding for interop with another implementation (e.g. SunJCE-shaped PKCS#12 secret keys per `Properties.PKCS12_ALLOW_SUN_SECRET_KEYS`, or vendor-specific TLS quirks), gate the new code path behind a `Properties.*` boolean and default it OFF. Keep the writer producing the standards-compliant form unconditionally — interop is a one-way concession on the read side, not a license to round-trip non-standard output. Cite the deviation in the property's javadoc (what's read, why it's gated, what BC writes instead) and reference the issue number in the release note so future maintainers can find the rationale.

### PKCS#12 SPI pair

The PKCS#12 keystore comes in two SPI flavours that share the bag-handling pipeline: `PKCS12KeyStoreSpi` (legacy MAC) and `PKCS12PBMAC1KeyStoreSpi` (RFC 9579 PBMAC1). When changing entry-type acceptance, bag dispatch in `engineLoad`, the cert/key write passes in `engineStore`, or the `getUsedCertificateSet` / `cryptData` helpers, the change usually needs mirroring in the other SPI. Shared static helpers — algorithm-OID lookup, key-size table, content/iteration-count helpers — live in the package-private `org.bouncycastle.jcajce.provider.keystore.pkcs12.PKCS12Util` so both SPIs can call them without one having to fully-qualify the other; new helpers should land there too rather than as static methods on either SPI.

### CMS streaming I/O: caller owns the outer stream

The streaming classes under `pkix/src/main/java/org/bouncycastle/cms/CMS*{Parser,StreamGenerator}.java` deliberately do **not** cascade close to caller-supplied streams, unlike `GZIPOutputStream` / `CipherOutputStream`. Stream generators finalize the CMS structure on `close()` of the returned `OutputStream` (writes signer infos, MAC, end-of-contents markers) but do not close the target `OutputStream` — if the target is a buffering encoder whose tail state only flushes on close (e.g. Apache Commons `Base64OutputStream`), the caller has to close it themselves. Parsers read only enough of the supplied `InputStream` to expose CMS metadata; encapsulated content drains lazily through `getContentStream()` / `getSignedContent()`, and the `InputStream` is closed only when the caller invokes `parser.close()` (inherited from `CMSContentInfoParser`). This convention is long-standing — changing it has been explicitly rejected (github #1572).

When updating CMS class-level javadoc, verify by tracing rather than paraphrasing aspirational behaviour: between Aug–Dec 2025 the `CMSAuthEnvelopedDataParser` doc claimed the constructor "fully drains and closes" the InputStream and that "plaintext content is buffered in memory" — both were wrong (the constructor reads ~84% of the input, no buffering happens), and the doc was corrected as part of github #2133. The model `<b>Stream handling note:</b>` blocks added across the package under that issue are the template to follow.

### Two locations for the same OID-table class

A handful of less-common arc OID classes are duplicated in the tree:

- `core/src/main/java/org/bouncycastle/internal/asn1/<arc>/<X>ObjectIdentifiers.java` — the **`internal.asn1`** copy, bundled into `core` (and so into `prov` via the core-into-prov srcDirs trick).
- `util/src/main/java/org/bouncycastle/asn1/<arc>/<X>ObjectIdentifiers.java` — the **public** copy, the API surface for downstream consumers.

Affected arcs include `kisa` (SEED), `nsri` (ARIA), `ntt` (Camellia), `oiw`, `gnu`, `iana`, `eac`, `cms`, `bsi`, `cryptlib`, `edec`, `iso`, `isara`, `isismtt`, `microsoft`, `misc`, `rosstandart`, etc. When importing from inside `core` or `prov` use the `internal.asn1.<arc>.<X>ObjectIdentifiers` form — `util` isn't on those modules' compile classpath, and the obvious `org.bouncycastle.asn1.<arc>` import will fail with a misleading "package does not exist". From `pkix` upward (or any module that already depends on `util`), the public form is fine.

### Release notes

Defects fixed and additional features go into `docs/releasenotes.html` under the **current** unreleased version block (e.g. section 2.1 with header "Release: 1.85"). Each entry is a single `<li>...</li>` referencing the GitHub issue number where applicable. The file is hand-edited HTML; preserve the existing prose style and `<ul>` structure.

### Commit messages

Existing convention: a short imperative sentence ending with `relates to github #NNNN.` for issue-driven work (e.g. `Corrected casing of Falcon naming when used with NamedParameterSpec, relates to github #2194`). Multi-line bodies are unusual — keep the headline self-contained.

### Code style

Match the surrounding file: Allman braces (open brace on its own line for class / method / control structures), 4-space indentation, no tabs. Don't reformat untouched code while editing — diffs that include unrelated whitespace changes are noisy and slow review.
