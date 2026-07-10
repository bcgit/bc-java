# Architecture

## Module graph and the `core`-into-`prov` trap

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

## Multi-Release JAR overlays

`prov`, `pkix`, `pg`, `tls`, etc. ship as MR-jars. Inside each module:

- `src/main/java` — base sources, compiled with `--release 8`
- `src/main/jdk1.9`, `jdk1.11`, `jdk1.15`, `jdk17`, `jdk25` — version-specific overlays packaged under `META-INF/versions/<n>/`
- `src/main/j2me`, `src/main/jdk1.1` … `jdk1.5`, `src/main/ext-jdk1.9` — alternate distributions for the legacy Ant builds (J2ME, pre-1.6 JDKs). **Gradle does not compile these.** Don't edit them when fixing a Gradle-build bug; they're separate trees maintained for the J2ME/legacy distributions.

The same applies to tests: `src/test/java` is the Gradle-driven tree; `src/test/jdk1.4`, `src/test/j2me`, `src/test/jdk1.1` are alternate trees, while `src/test/jdk1.11`, `jdk1.15`, `jdk17`, `jdk25` are MR-jar test overlays driven by the `test11`/`test15`/`test17`/`test25` Gradle tasks.

## Update `module-info.java` when you add or remove package

Each Gradle-built module has a JPMS descriptor at `<module>/src/main/jdk1.9/module-info.java` (e.g. `prov/src/main/jdk1.9/module-info.java`, `pkix/src/main/jdk1.9/module-info.java`) listing every exported package. The Java 8 sources under `<module>/src/main/java` and the descriptor are bundled into the same multi-release jar; the descriptor is the source of truth for what's visible when downstream code runs on JDK 9+ with `--module-path`. A package that exists in the source tree but isn't listed in `module-info.java` is invisible to modular consumers — class-path consumers still see it, which is why the omission is easy to miss locally. Note: `core` itself has no module-info; its sources are bundled into the published `bcprov` jar via the core-into-prov srcDirs trick, so the `prov` module-info exports `core` packages.

`prov` additionally carries a parallel `prov/src/main/ext-jdk1.9/module-info.java` for the legacy Ant build that ships separately. Edits to the Gradle-driven `prov/src/main/jdk1.9/module-info.java` should be mirrored to the `ext-jdk1.9` variant for symmetry — it's not Gradle-built, but it's tracked and consumed by the legacy distribution.

When you add a class, ask which case applies:

- **Existing package** (e.g. dropping `ECBModeCipher` into `org.bouncycastle.crypto.modes`, already in `prov/.../module-info.java`) — no descriptor change needed. `module-info.java` exports packages, not classes.
- **New package** (a directory that doesn't yet exist under any `org.bouncycastle.*` tree) — add `exports org.bouncycastle.your.new.package;` to the corresponding module's `module-info.java`. The Gradle modules are `prov` (which also covers core), `util`, `pkix`, `tls`, `mail` / `jmail`, `pg`, `mls` — pick the one whose `src/main/java` your new package physically lives under.

Symmetrically, if you delete or merge away an entire package, remove its `exports` entry from both the `jdk1.9` and (where it exists) `ext-jdk1.9` descriptors. The compile-time signal that catches a missed entry — `module org.bouncycastle.provider does not export org.bouncycastle.crypto.foo` — only fires for modular downstream consumers, so a class-path-only test run won't surface it.

## The OSGi `Export-Package` manifest is a *second*, silent place to wire a package

Each Gradle module also ships as an OSGi bundle: `<module>/build.gradle` applies the `biz.aQute.bnd.builder` plugin and sets `Export-Package` / `Import-Package` manifest attributes from a `packages` brace-list string (e.g. `pkix/build.gradle`'s `org.bouncycastle.{cades|cert|cmc|cms|…|tsp}.*`, `util/build.gradle`'s `org.bouncycastle.asn1.{bsi|cmc|…|tsp}.*` plus a separate `org.bouncycastle.oer.*`). This is **independent of `module-info.java`** and easy to leave out of step:

- **A new sub-package of an already-listed family** (e.g. `org.bouncycastle.cms.foo` under `…{…|cms|…}.*`) needs no change — the `.*` glob covers it.
- **A new top-level family** (a brace-list token that isn't there yet) must be **added to the `packages` string** in that module's `build.gradle`, or it is silently absent from the OSGi bundle even though `module-info.java` exports it. This drift is invisible to a normal build — the only signal is inspecting the built jar's `META-INF/MANIFEST.MF` (or `jar --describe-module` vs the manifest). Real cases found this way: `cades` missing from `pkix`, `asn1.mod` from `util`.
- **`prov` is the exception**: its list is the negative form `!org.bouncycastle.internal.*,org.bouncycastle.*;version=…`, i.e. export everything except `internal.*`, so a new `prov`/`core` package is auto-exported and needs no `build.gradle` edit (only a `module-info.java` one). The trade-off is that `prov` can *over*-export a package you meant to conceal unless you add it to the `!…` prefix (this is why `org.bouncycastle.apache.bzip2` is OSGi-exported but JPMS-concealed).

So "add a package" is a three-file habit: `module-info.java` (both `jdk1.9` and `ext-jdk1.9` for prov), the module's `package-info.java`, and — for a new top-level family in a module other than `prov` — the `packages` brace-list in `build.gradle`. Removing a family means removing it from all three.

## Every new package ships a `package-info.java`

When you introduce a new package, drop a `package-info.java` alongside the first class. A one-sentence Javadoc above the `package …;` declaration is enough — name what the package is for, point at the relevant RFC / spec / sibling package when it helps a reader orient. Mirror the style of the existing files (e.g. `pkix/.../cms/package-info.java`, `core/.../asn1/package-info.java`): brief, factual, no boilerplate. The package-info is what shows up in the generated Javadoc package list, so a missing one shows up as an unnamed bucket in the consumer-facing API docs.

This is symmetric with the `module-info.java` rule above: a new package that's exported but undocumented is half-wired the same way one that's documented but unexported is half-wired. Add both files in the same change.

## Examples live in `misc/`, not in the Gradle modules

`misc/` is a non-Gradle source tree (not in `settings.gradle`, no `build.gradle`) used as the canonical home for example / demo code. Existing example packages: `misc/src/main/java/org/bouncycastle/{asn1,crypto,jcajce,openpgp,pqc/crypto}/examples/`. New example code should land here, not under `core/.../examples`, `prov/.../examples`, `pg/.../openpgp/examples`, etc. — putting it inside a Gradle module would force it into the published `bc*` jars and make it part of the JPMS-exported API surface. `pg/src/main/java/org/bouncycastle/openpgp/examples/` already exists as a legacy quirk and is published; the rule applies symmetrically — new OpenPGP example code goes under `misc/.../openpgp/examples/` instead (the package was added there for github #1414's `PublicKeyByteArrayHandler`, complementing the older PBE-only `ByteArrayHandler` in pg).

When moving existing example code into `misc/`, remember to drop any matching `exports …examples;` line from the source module's `module-info.java` files (both `jdk1.9` and `ext-jdk1.9` variants when the source was `prov`).

When the natural place for an example would be a generic JCE alias that BC deliberately doesn't ship (e.g. `Cipher.ECIESwithSHA256andAES-ECB` — non-standard for ECIES per IEEE 1363a / ISO 18033-2 / SECG SEC 1; see `misc/.../crypto/examples/ECIESAESECBExample.java` for the model, github #1095), the convention is: don't register the alias, ship a `misc/` example that builds the construction locally via the lightweight API, and open the class-level javadoc with the reason BC doesn't endorse the named form (cite the relevant standard sections) plus a pointer at the standards-compliant variant production callers should prefer. The example exists so the next person searching for the non-standard form has a concrete answer rather than nothing.

## JCE provider registration

`BouncyCastleProvider` (in `prov`) registers algorithms by string name through `ConfigurableProvider.addAlgorithm("Cipher.SM2", "...GMCipherSpi$SM2")` etc. Per-algorithm registration code lives in `prov/src/main/java/org/bouncycastle/jcajce/provider/{asymmetric,symmetric,digest,keystore,...}/<Family>.java`. The corresponding `*Spi` classes (CipherSpi, KeyFactorySpi, KeyPairGeneratorSpi, etc.) are siblings under the same package. When adding or fixing a JCE-visible behaviour, the registration `Family.java` is the entry point; the underlying lightweight engine usually lives in `core/src/main/java/org/bouncycastle/crypto/engines/`.

## Adding a PQC algorithm: BCPQC ≠ BC, but BC needs the OID table too

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

## PQC engines should stay package-private — drive KATs through the public API

The lightweight `<Alg>Engine` produced when porting a reference C/Rust implementation tends to expose low-level entry points (`engine.keyGen(seedKey, sk, pk)`, `engine.sign(sk, msg, salt, mseed)`) that KAT vectors need but legitimate callers never touch. Resist the urge to make `<Alg>Engine` public just so `<Alg>KatTest` can poke at internals — that leaks the engine into the published `bcprov` API surface where it becomes load-bearing, and any future internal refactor has to preserve the engine signature too.

The standard pattern is to keep the engine package-private and drive `<Alg>KeyPairGenerator` / `<Alg>Signer` with a deterministic `SecureRandom` that emits exactly the bytes the KAT prescribes:

- `org.bouncycastle.util.test.FixedSecureRandom(bytes)` — emits a pre-baked byte sequence, single-shot (reconstruct it for each call site that needs the same seed). Use when the test wants a specific seed.
- `org.bouncycastle.pqc.crypto.test.NISTSecureRandom(seed, personalization)` — the NIST CTR-DRBG upstream KAT generators use to derive per-vector randomness from a 48-byte seed. The same DRBG instance can be reused across keygen + sign because the public-API call sites consume from it in the same order the reference C harness did.

Concrete: `MQOMKeyPairGenerator.generateKeyPair` reads `2 * seedSize` bytes via `random.nextBytes`; `MQOMSigner.generateSignature` then reads `mseed` (`seedSize`) followed by `salt` (`saltSize`). A single `NISTSecureRandom drbg = new NISTSecureRandom(seed, null)` shared between both calls reproduces the upstream KAT byte-for-byte without any engine reference. `UOVKeyPairGenerator` and `HawkKeyPairGenerator` follow the same shape (32-byte `SK_SEED_BYTES` for UOV, `SALT_BYTES` from `<Alg>Parameters` etc.). The rewritten `MQOMTest` / `MQOMKatTest` / `UOVTest` and the already-conforming `HawkTest` are the worked examples.

If you find yourself unable to demote `<Alg>Engine` to package-private without breaking tests, that is the symptom — rewrite the tests against the public `<Alg>KeyPairGenerator` / `<Alg>Signer` with `FixedSecureRandom` / `NISTSecureRandom` first, then demote.

## Package layering: `.bc` (lightweight) vs `.jcajce` (JCA/JCE)

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
