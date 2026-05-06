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

`bc-test-data` (separate repo `bcgit/bc-test-data`) must be checked out as a sibling of `bc-java` for the full suite to pass; the Gradle property `bcTestDataHome` defaults to `core/src/test/data`.

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
     -Dbc.test.data.home=core/src/test/data \
     org.bouncycastle.openssl.test.ParserTest
```

Common gotchas:
- `*/build/resources/main` directories are required — some tests pull resource files (e.g. `lowmcL1.bin.properties` for Picnic, GOST tables) that fail with cryptic `NullPointerException` if missing.
- `prov/src/test/resources` and `core/src/test/resources` carry test fixtures referenced by `TestResourceFinder` and direct classpath lookups.
- IDE-built classes under `out/production/...` (IntelliJ) are NOT on the Gradle classpath — don't reference them, and beware that they can drift from Gradle's outputs.

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

### JCE provider registration

`BouncyCastleProvider` (in `prov`) registers algorithms by string name through `ConfigurableProvider.addAlgorithm("Cipher.SM2", "...GMCipherSpi$SM2")` etc. Per-algorithm registration code lives in `prov/src/main/java/org/bouncycastle/jcajce/provider/{asymmetric,symmetric,digest,keystore,...}/<Family>.java`. The corresponding `*Spi` classes (CipherSpi, KeyFactorySpi, KeyPairGeneratorSpi, etc.) are siblings under the same package. When adding or fixing a JCE-visible behaviour, the registration `Family.java` is the entry point; the underlying lightweight engine usually lives in `core/src/main/java/org/bouncycastle/crypto/engines/`.

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

### Exception messages are part of the test contract

Many tests assert on exact exception message text (e.g. `isTrue(e.getMessage().equals("..."))` or `getCause().getMessage()` checks). Changing the wording of a thrown exception — even something as small as adding a colon, rewording for clarity, or wrapping with `Exceptions.illegalArgumentException(...)` — will silently break tests in another module. Before modifying any exception message, grep the whole tree for the existing string and update every matching assertion in lockstep.

### System / security property constants

Any system or security property that controls BC behaviour belongs in `core/src/main/java/org/bouncycastle/util/Properties.java` as a `public static final String`, e.g. `Properties.PKCS12_MAX_IT_COUNT`, `Properties.PKCS12_IGNORE_USELESS_PASSWD`, `Properties.EMULATE_ORACLE`. Callers should reference the constant rather than inlining the literal `"org.bouncycastle.…"` name — both in production code and in tests that flip the property via `System.setProperty`. New properties should be added to `Properties` with the same naming pattern (`org.bouncycastle.<area>.<flag>`).

### Release notes

Defects fixed and additional features go into `docs/releasenotes.html` under the **current** unreleased version block (e.g. section 2.1 with header "Release: 1.85"). Each entry is a single `<li>...</li>` referencing the GitHub issue number where applicable. The file is hand-edited HTML; preserve the existing prose style and `<ul>` structure.

### Commit messages

Existing convention: a short imperative sentence ending with `relates to github #NNNN.` for issue-driven work (e.g. `Corrected casing of Falcon naming when used with NamedParameterSpec, relates to github #2194`). Multi-line bodies are unusual — keep the headline self-contained.

### Code style

Match the surrounding file: Allman braces (open brace on its own line for class / method / control structures), 4-space indentation, no tabs. Don't reformat untouched code while editing — diffs that include unrelated whitespace changes are noisy and slow review.
