# The legacy Ant builds, and the jdk1.4 (build1-4) build in detail

## All three Ant builds (build1-4, build1-5to1-8, build1-8+)

- **A clean checkout cannot build.** `ant/jdk15+.xml:38` and `ant/jdk18+.xml` reference `core/src/main/resources`, which holds no tracked files, so it is absent in a fresh clone/worktree and Ant dies with `core/src/main/resources not found`. Step one in a new tree: `mkdir -p core/src/main/resources`. (`jdk14.xml`, `jdk13.xml`, `bc+-build.xml` don't reference it.)
- **The scripts don't propagate an Ant failure.** Each runs `if ant build-provider; then ant build; ant zip-src; fi`: a failed `build-provider` still exits 0, a failed `build` is masked by `zip-src`. Grep the log for `BUILD FAILED` and check the jars appeared under `build/artifacts/<jdkdir>/jars/`.
- **They share `build/`** — run them sequentially, never in parallel.
- Build-only timings (warm, fresh worktree): `build1-8+` 50s / 9 jars, `build1-5to1-8` 1m21s / 9 jars, `build1-4` 56s / 8 jars (no `bcjmail`), ~1.6G total. The "~25 minutes" quoted below is build + sign + full test.
- Each artifact tree holds `jars/`, a `<module>-<vmrange>-<ver>/` per module (`src.zip`, `javadoc/`) and `lcrypto-<vmrange>-<ver>/` as a **directory**. Nothing in the tree makes the `lcrypto-*.tar.gz`/`.zip` archives — they come from a manual release step.
- The wrappers add `META-INF/services/java.security.Provider` to the provider jars after Ant, differently: `build1-5to1-8` loops `jar uf` over `bcprov*jdk15to18*.jar` (catching `bcprov-ext` and debug builds); `build1-8+` uses a `tar` pipe naming two jars. Look there when a provider jar loads from Gradle but not from Ant.

### The Ant `jdk18+` build is not the published `jdk18on` artifact

`build1-8+` makes a `bcprov-jdk18on-<ver>.jar` with **no** `META-INF/versions/` entries and an `Ant-Version: Apache Ant 1.6.5` manifest; the published multi-release jar comes from Gradle. Use the Ant output only for what Gradle doesn't build: `bcprov-ext-jdk18on` and `bctest-jdk18on`.

### The jdk15to18 (Java 5) build has a *runtime* floor

`build1-5to1-8` (→ `ant/jdk15+.xml`) compiles 1.5 bytecode on JDK 8 with no `bootclasspath`, then runs on a **genuine JRE 5**, so Java 6/7/8 APIs compile and then throw `NoSuchMethodError`/`NoClassDefFoundError` at runtime. Route through the BC wrappers with `jdk1.5` overlays (`Longs`/`Integers`/`BigIntegers`), `Exceptions.ioException`, `Strings.toByteArray`, `instanceof Destroyable`, `System.arraycopy`. The build → `bcsign` (release machine only) → test workflow, the full API→fix table, test-exclusion overlays and the `-Xint` diagnostic for JRE-5 JIT defects are in the `build-jdk15to18` skill.

## jdk1.4: what it needs

`sh build1-4` drives `ant/jdk14.xml` (delegating to `ant/bc+-build.xml`), compiling with the **real JDK 1.4 javac** and testing on the same JRE, so post-1.4 API use fails at **compile time** — the strictest check for reachable `src/main/java`. Needs `/opt/jdk1.4.2`, `/opt/apache-ant-1.6.5`, `/opt/javamail-1.3.1/mail.jar`, `/opt/jaf-1.0.2/activation.jar` (the script sets ANT_HOME/JAVA_HOME/CLASSPATH and PATH). Ant runs on the 1.4 JVM, so a modern Ant can't drive it (Ant 1.10's `-Djava.security.manager=allow` dies with `UnsupportedClassVersionError: allow`); hand-run `ant -f ant/jdk14.xml …` with the 1.6.5 environment shown below.

## Source assembly and the preprocessor

`init` copies base `*/src/main/java` + `*/src/test/java` into `build/jdk1.4` (with per-fileset excludes), overwrites with `<module>/src/main/jdk1.4` / `src/test/jdk1.4` overlays, then runs the `replaceregexp` passes in `ant/build.regexp`: strips generics, `@Override`/`@Deprecated`/`@SuppressWarnings`, `StringBuilder`→`StringBuffer`, varargs declarations → arrays.

FINE in 1.4-reachable code: generics (but see the erased-override trap), `StringBuilder`, varargs declarations.

NOT fixable by the regexes: enhanced-for, autoboxing, enums, covariant return overrides, varargs *call sites*, and post-1.4 APIs:
- `String.contains`/`isEmpty`; `System.clearProperty` (→ `System.getProperties().remove`).
- `java.nio.charset.StandardCharsets` (→ `Strings.toUTF8ByteArray`/`toByteArray`) — the most common way a new *test* breaks this build.
- `java.util.Arrays.copyOf(Range)` (→ BC `Arrays`); `Integer.numberOfLeadingZeros`/`compare` (→ BC `Integers` or open-code); `Math.scalb`/`getExponent` (see `Dpe`'s private helpers).
- `java.util.concurrent` (→ synchronized collections, `Thread` + `join`), `ArrayDeque`, `ResourceBundle.Control`.
- `ECGenParameterSpec`/`OAEPParameterSpec`/EC `java.security.spec` types (→ `org.bouncycastle.jce.spec`); `NameClassPair.getNameInNamespace`; `KeyStore.SecretKeyEntry`; `Cipher.updateAAD`; `GCMParameterSpec` (→ BC `AEADParameterSpec`, which the jdk1.4 `BaseBlockCipher` understands).
- `(String,Throwable)` exception constructors (→ `Exceptions`/`SecurityExceptions` factories, or `super(msg)` + `initCause`); `ThreadLocal.remove()` (→ `set(null)`).

1.4-only traps:

- **`System.getenv` throws `java.lang.Error`** ("getenv no longer supported") — guard env-var reads in test-reachable code with `catch (Error)`, as the `TestResourceFinder` copies do.
- **Erased generic-interface overrides.** Stripping type arguments but not parameter types turns `new Comparator<IndexedHash>() { public int compare(IndexedHash l, IndexedHash r) }` into a raw `Comparator` that javac rejects ("is not abstract and does not override abstract method `compare(java.lang.Object,java.lang.Object)`"). Implement with the erased signature and cast inside (`tsp/ers/ByteArrayComparator`, `SortedIndexedHashList.DigestComparator`). Quick check: run the `ant/build.regexp` patterns over the file and package and compile with `/opt/jdk1.4.2/bin/javac`.
- **Static method hiding needs identical return types (JLS2).** The `util/src/main/jdk1.4` cmp overlays (`CertAnnContent`, `OOBCert`, `NestedMessageContent`) keep widened `CMPCertificate`/`PKIMessages` return types on `getInstance(Object)` — don't "fix" them.
- **`StringBuilder`+`StringBuffer` overload pairs collapse** into duplicates after preprocessing (e.g. `IETFUtils.appendRDN`); such files need an overlay of base minus the `StringBuffer` overloads.

## Overlay discipline: delete when you can, sync when you must

The jdk1.4 overlays are hand-maintained forks that rot (the 2026 sweep found missed security fixes, a registration naming a class gone since 2020, stale test assertions).

- **Prefer deleting an overlay** when base is 1.4-clean after preprocessing (as done for `PKIXNameConstraintValidator`). Verify with the real build, not by eye.
- When an overlay must exist, open it with a NOTE comment saying why (see the jdk1.4 `IETFUtils`) and keep everything else in step with base.
- `core/src/main/jdk1.4/.../util/Properties.java` must mirror every base constant 1.4-compiled code references — the most common way main breaks this build.
- Registrations are part of the sync: a base `Family.java` registering an SPI inner class missing from the overlay (`ec/SignatureSpi` deterministic-DSA/SHAKE variants) fails only at `getInstance`. Conversely, JRE 1.4's `sun.security.x509.AlgorithmId` consults provider `AlgorithmParameters` during cert parsing, so registering an SPI that can't parse the parameters breaks Sun-side parsing — the jdk1.4 `ECGOST` deliberately registers none.

## Build → sign → test

```
sh build1-4                                   # build-provider, build, zip-src
ANT_HOME=/opt/apache-ant-1.6.5 JAVA_HOME=/opt/jdk1.4.2 /opt/apache-ant-1.6.5/bin/ant -f ant/jdk14.xml build-test
bcsign4 build/artifacts/jdk1.4/jars/*.jar     # release machine only
ANT_HOME=/opt/apache-ant-1.6.5 JAVA_HOME=/opt/jdk1.4.2 /opt/apache-ant-1.6.5/bin/ant -f ant/jdk14.xml test-signed   # NOT "test"
```

- JRE 1.4's JCE authenticates providers: unsigned bcprov fails with "provider BC may not be signed by a trusted party". `bcsign4` signs with `bc1024key` via the 1.4 jarsigner, silently (empty log = success).
- **Sign every jar, then run `test-signed`, never `test`.** JRE 1.4 requires one signer per package, and `bctest` shares packages with the provider (`org.bouncycastle.pqc.crypto.hqc` for `GFTest`, `org.bouncycastle.pqc.crypto.ntruprime` for `UtilsTest`), so an unsigned `bctest` fails with `SecurityException: class "…hqc.GF"'s signer information does not match signer information of other classes in the same package`. `test` depends on `build-test`, which re-jars `bctest` every time and strips the signature. Don't drive `ant -f ant/bc+-build.xml test` directly either — it lacks `jdk14.xml`'s properties ("`${junit.printsummary}` is not a legal value for this attribute").
- Package-private provider tests (`prov/src/test/java/org/bouncycastle/jce/provider/*.java`, `CrlCacheTest` etc.) are excluded in `ant/jdk14.xml` for the same signed-package reason.
- `build/jdk1.4` and the artifact trees are **never cleaned**; `<copy>` keeps files a new exclude should drop. After changing excludes, deleting overlays or renaming files, `rm -rf build`.
- Failed suites: read the per-suite XML under `build/artifacts/jdk1.4/reports/xml/`; the console hides the exception.
- Fast loop (~2 min vs ~25 for the full pipeline): `ant -f ant/jdk14.xml build-provider`, re-sign `bcprov-ext`, run the class with `/opt/jdk1.4.2/bin/java -Xmx1536m -cp <jars> <test class>`.

## The debug variant (`<module>-debug-jdk14`)

Set `release.debug: true` in a git-ignored `bc-build.user.properties` at the tree root (read before `bc-build.properties`) and run the same build → `build-test` → `bcsign4` → `test-signed`. `target.prefix` becomes `debug-jdk14`, naming the jars, per-module dirs and `lcrypto-debug-jdk14-<ver>`. `ant/jdk15+.xml` has the same switch (`debug-jdk15to18`); `ant/jdk18+.xml` does not.

- **Build it fresh in its own worktree** (~750M, a minute): a staging tree that already ran tests absorbs test resources — in 1.86 `bcprov-debug-jdk14` shipped six `org/bouncycastle/i18n/test/*.properties`.
- **Compare each debug jar with its plain twin**: `diff <(unzip -Z1 debug.jar | sort) <(unzip -Z1 plain.jar | sort)` must be empty (both signed or both unsigned), `unzip -Z1 bcprov-debug-jdk14-*.jar | grep -c i18n/test` must be 0, and `javap -v -cp <jar> org.bouncycastle.crypto.engines.AESEngine | grep -c LocalVariableTable` is non-zero only for the debug jar.
- Test totals should match the plain run (1.87: 39 suites, 1251 tests, ~21 minutes).
- Don't write `-sources`/`-javadoc` jars (`legacy-source-javadoc-jars` skill) into `build/artifacts/jdk1.4/jars` while `test-signed` runs — the test classpath takes every jar there.

## Excluded areas and test excludes

- **LMS/HSS and XMSS/XMSS^MT are excluded** from jdk1.4 and jdk1.3 (`**/lms/**`, `**/xmss/**`, plus `crypto/params/LMS*`, `crypto/signers/LMS*` in `ant/jdk14.xml`), so changes confined to them can't break these builds. The jdk1.1/jdk1.4 `PrivateKeyFactory`/`PrivateKeyInfoFactory` overlays don't reference XMSS or BDS state.
- Tests that can't run on 1.4 get an `ant/jdk14.xml` exclude — but a `TestCase` referenced from a compiled `AllTests` also needs a jdk1.4 `AllTests` overlay without it, or a jdk1.4 stub overlay of the test (see `PKCS12PfxPduSecretKeyTest`'s overlay).

## jdk1.3 layers the jdk1.4 overlays — don't base a jdk1.3 overlay on `src/main/java`

`ant/jdk13.xml` stages base → `src/main/jdk1.4` overlays → `src/main/jdk1.3` overlays → preprocess. So:

- A class may compile for jdk1.3 with no jdk1.3 overlay because its jdk1.4 overlay already removed the post-1.3 APIs (`jce/provider/BouncyCastleProvider`: base uses `ConcurrentHashMap` and `java.util.logging`, the jdk1.4 overlay doesn't).
- **Base a new jdk1.3 overlay on the jdk1.4 overlay if one exists** (`find <module>/src/main/jdk1.4 -name <Class>.java`); copying base reintroduces the Java-5/1.4 APIs and, being copied last, wins.

## Legacy Ant provider jars sweep in main-namespace tests (OSGi junit contamination)

`ant/bc+-build.xml` builds `bcprov` by copying sources with `*Test.java` **excludes** (~line 364) and `bctest` with `*Test.java` **includes** (~line 975). Shallow globs (`org/bouncycastle/crypto/*/*Test.java`) miss tests placed directly in a main-namespace package to reach package-private code (`org.bouncycastle.asn1.ASN1TimeFormatTest`, `org.bouncycastle.crypto.agreement.owl.OwlUtilTest`), sweeping them into `bcprov`; bnd then emits `Import-Package: …junit.framework;resolution:=optional` and `uses:="junit.framework,…"`. (Gradle jars are unaffected.) Check with `unzip -p <jar> META-INF/MANIFEST.MF | grep junit` and `unzip -l <jar> | grep -E 'Test\.class$'`.

Fix (in `bc+-build.xml`, covering jdk15to18/jdk1.4/jdk1.3): exclude `org/bouncycastle/{crypto,asn1}/**/*Test.java` from the provider copy, and add a targeted bctest include (e.g. `**/crypto/agreement/owl/*Test.java`) so the test lands in `bctest`. `org.bouncycastle.util.test.{SimpleTest,Test}` legitimately ship in `bcprov`; only `*Test extends junit.framework.TestCase` is the problem.

### `org.bouncycastle.tls`-package tests: a targeted include gets them compiled, not run

- Tests in `org.bouncycastle.tls` itself (not `.tls.test`) match no bctest include (`**/test/*.java`, `**/test/*/*.java`), so they are never compiled by 1.4 javac nor run: `Add13CertificateStatusTest`, `AbstractTlsServerResetTest`, `CheckTlsFeaturesExtensionTest`, `DTLSReassemblerTest`. `SpreadCertificateStatusTest` has a targeted include (next to the `owl` one). They don't leak into `bctls`: `build-tls` excludes `**/*Test.java` (`unzip -l bctls-jdk14-*.jar | grep -cE 'Test\.class'` should be 0).
- **Test helpers there must be named `*TestSupport`**: `build-tls` also excludes `**/*TestSupport.java`, added after `DTLS13HandshakeTestSupport`, `DTLSRecordLayer13TestSupport` and `DTLS13KeyUpdateTestSupport` were swept into `bctls` and broke the provider compile. `DTLS13KeyUpdateTestSupport` (needed by `DTLS13ProtocolTest`) has a targeted `build-test` include, and `ant/jdk15+.xml` (which excludes `**/tls/*.java`) stages it with its own fileset. Such a helper must compile against `bctls` alone.
- A targeted include is a **compile-floor check only**: `ant/jdk14.xml` (~line 283) excludes `**/tls/AllTests.java`, the only suite referencing these classes. Running them means staging that `AllTests` and everything it references — not a one-liner. `org/bouncycastle/tls/test/AllTests.java` is not excluded, so `.tls.test` classes (e.g. `Tls13CertificateStatusTest`) do run.
