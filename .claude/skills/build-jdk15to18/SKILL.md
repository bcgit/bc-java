---
name: build-jdk15to18
description: Build, sign, and test the legacy jdk15to18 (Java 5) distribution via the build1-5to1-8 script and ant/jdk15+.xml. Use this whenever the user wants to build/sign/run the "build1-5to1-8" version, get "sh build1-5to1-8 test" to pass, reproduce a genuine-Java-5 compile or test failure, or chase a "JCE cannot authenticate the provider BC" / NoSuchMethodError / NoClassDefFoundError that only shows up on a real JRE 5. Captures the build→sign→test ordering, the two different JDKs involved, the machine-only signing step, and the compile-time vs runtime Java-version traps that the modern Gradle build cannot surface.
---

# Building, signing and testing the jdk15to18 (Java 5) distribution

The legacy `jdk15to18` artifact is a **1.5-bytecode** jar built on **JDK 8** and run on a **genuine JRE 5**. That split is the source of every non-obvious problem here: code that compiles fine (JDK 8 resolves all APIs) can still fail at runtime on JRE 5 because the API didn't exist in 1.5. The Gradle build (`--release 8`) cannot catch any of this; only this pipeline can.

This skill is for driving `sh build1-5to1-8` and getting `sh build1-5to1-8 test` green.

## The three steps — order matters

```
sh build1-5to1-8                                   # 1. BUILD on JDK 8  -> unsigned jars
/home/dgh/bin/bcsign build/artifacts/jdk1.5/jars/*.jar   # 2. SIGN (this machine only)
sh build1-5to1-8 test                              # 3. TEST on genuine JRE 5
```

**The build clobbers signatures.** `sh build1-5to1-8` (no arg) rewrites every jar in `build/artifacts/jdk1.5/jars/` unsigned. So you must always **build → sign → test**, in that order. Never run the no-arg build again after signing without re-signing.

**`test` does not rebuild the provider.** The `test` target only compiles the *test* tree and runs JUnit against the already-built (and signed) jars. So you can re-run `sh build1-5to1-8 test` as many times as you like without re-signing — only a no-arg rebuild forces a re-sign.

### Step 1 — build (JDK 8)

`sh build1-5to1-8` sets `JAVA_HOME=$JDKPATH` (default `/usr/lib/jvm/java-8-openjdk-amd64`) and runs `ant -f ant/jdk15+.xml build-provider build`, producing in `build/artifacts/jdk1.5/jars/`:
`bcprov`, `bcprov-ext`, `bcutil`, `bcpkix`, `bcpg`, `bcmail`, `bcjmail`, `bctls`, `bctest` (`-jdk15to18-<ver>.jar`).
The `<javac>` is `source/target=1.5`, `fork="true"`, **no `bootclasspath`** — so it compiles against JDK 8's libraries. That is why API-availability problems are invisible at this stage.

If you only need to iterate on the test compile, `build-provider` alone is *not* enough — `asn1.cmc`/`asn1.cmp`/etc. tests need `bcutil`/`bcpkix`, so run the full no-arg build at least once.

### Step 2 — sign (only works on this machine)

`/home/dgh/bin/bcsign <jars...>` signs in place with BC's release keys:
- It hardcodes `JAVA_HOME=java-7` (needs `pack200`, removed in JDK 14+).
- For names matching `jdk15|jdk16|fips` it `pack200 --repack`s then double-signs (RSA-2048 `bcrsa2048key` + 1024 `bc1024key`) against keystores under `/home/dgh/bc/` with a timestamp authority, then verifies.
- The keystores, passwords and certs live only on this machine, so **signing cannot be reproduced elsewhere** — on any other host the crypto tests cannot pass under a genuine JRE 5.

Sign the whole jar dir: `/home/dgh/bin/bcsign build/artifacts/jdk1.5/jars/*.jar`.

**Why signing is mandatory:** on JDK 5 the JCE requires providers performing `Cipher`/`Mac`/`KeyGenerator` work to be jars signed with a trusted JCE code-signing cert. An unsigned dev jar makes essentially every crypto test fail with `java.lang.SecurityException: JCE cannot authenticate the provider BC` (pure-ASN.1 suites still pass, which is the tell).

### Step 3 — test (genuine JRE 5)

The `test` branch of `build1-5to1-8` switches `JAVA_HOME=$JDK5PATH` (`/usr/lib/jvm/java-1.5.0-oracle-i586`) and runs `ant -f ant/jdk15+.xml test`: it copies+overlays sources, compiles the test tree with **genuine javac 1.5**, then runs the `**/AllTests.java` suites under **JRE 5**. Reports land in `build/artifacts/jdk1.5/reports/xml/TEST-*.xml` (parse these for failures — the console only prints `Test <suite> FAILED`).

## Two distinct classes of failure

### (a) Compile-time — genuine javac 1.5 rejects the test source

Test files using post-1.5 APIs must be excluded from the genuine-Java-5 compile in `ant/jdk15+.xml` (add an `<exclude>` to the `prov/src/test/java` fileset) **and** dropped from the genuine-Java-5 suite overlays under `prov/src/test/jdk1.5/` (the build copies the main tree then overlays `jdk1.5` with `overwrite="true"`, so the overlay `RegressionTest`/`AllTests` are what actually compile). Known excludes already in place:
- `jce/provider/test/AEADTest.java`, `jcajce/provider/test/LEATest.java` — `javax.crypto.spec.GCMParameterSpec` (Java 7).
- `jce/provider/test/X509LDAPCertStoreTest.java` — pulls `com.unboundid.ldap...` from `unboundid-ldapsdk-6.0.8.jar`, which is **Java 7 bytecode** (`class file has wrong version 51.0, should be 49.0`).

Main-source genuine-Java-5 overlays live under `<module>/src/main/jdk1.5/` (e.g. `core/src/main/jdk1.5/.../i18n/LocalizedMessage.java` avoids Java 6 `ResourceBundle.Control`). The no-arg build masks the need for these (JDK 8 has the API); only a genuine-javac-1.5 compile reveals them.

To check a single file fast without the whole pipeline, compile against the real Java 5 bootclasspath:
```
J5=/usr/lib/jvm/java-1.5.0-oracle-i586
"$J5/bin/javac" -source 1.5 -target 1.5 \
  -bootclasspath "$J5/jre/lib/rt.jar:$J5/jre/lib/jce.jar:$J5/jre/lib/jsse.jar" \
  -sourcepath <tree> -d /tmp/out <File>.java
```
(Include `jce.jar`/`jsse.jar` — `javax.crypto.*` / `javax.net.ssl.*` are not in `rt.jar` on JDK 5.)

**Excluding a test from the JRE-5 run.** The build copies the main test tree then overlays `<module>/src/test/jdk1.5/` with `overwrite="true"`. Two cases:
- A `*AllTests`/`*Test` discovered by the batchtest, or one constructed in an `AllTests` method: the offending class can fail to even *load* on JRE 5 (the bytecode verifier resolves a JDK-7/8 type referenced in a method body at class-load time, so a guard *inside* the method never runs). So you must drop it from the **suite**, via a `jdk1.5` overlay of the enclosing `AllTests`/`RegressionTest` (e.g. `prov/src/test/jdk1.5/.../RegressionTest.java`, `pkix/src/test/jdk1.5/.../cert/ocsp/test/AllTests.java`). The overlay must list every test *except* the excluded one (it replaces, not merges). Add the module's `src/test/jdk1.5` to the `overwrite` copy block in `ant/jdk15+.xml` if it isn't already (prov/tls/pg were wired; core/pkix were added during the 1.85 pass).
- A `SimpleTest` run only via `RegressionTest.tests` (e.g. `crypto.test.RSATest`): a `RegressionTest` overlay would duplicate ~200 entries, so a **runtime guard inside the test** keyed on `System.getProperty("java.version").startsWith("1.5")` is cleaner (it still runs on JDK 8/21). Used for the `RSATest` JIT case below.

### (b) Runtime — target-1.5 bytecode calls an API absent on JRE 5

These compile cleanly (JDK 8 has the API) and only surface as JUnit `NoSuchMethodError`/`NoClassDefFoundError` on JRE 5. **The BC util wrappers `Longs`/`Integers`/`BigIntegers` exist precisely for this** — they have `jdk1.5` overlays that reimplement the Java-7/8 method in a 1.5-safe way, so the fix is usually "route the static call through the wrapper" (and, if the wrapper lacks the method, add it to both the main class and its `jdk1.5` overlay). Confirmed fixes from the 1.85 pass:

| Java-7/8 API (symptom) | Java-5-safe fix |
|---|---|
| `new IOException(String,Throwable)` / `IOException(Throwable)` (Java 6) | `Exceptions.ioException(msg,cause)`; for an `IOException` subclass ctor `super(msg); initCause(cause);` |
| `BigInteger.longValueExact()` (Java 8) | `BigIntegers.longValueExact(x)` |
| `Long.parseUnsignedLong/compareUnsigned/divideUnsigned`, `Integer.compare` (Java 7/8) | `Longs.*` / `Integers.*` (add to main **and** `jdk1.5` overlay if missing) |
| `Math.getExponent`/`Math.scalb` (Java 6) | full `jdk1.5` overlay of the class (e.g. `Dpe`) with exact ports; keep main on `Math.*` |
| `SecretKey.destroy()` (Java 8 — `SecretKey extends Destroyable` only since 8) | `if (key instanceof Destroyable) ((Destroyable)key).destroy();` (the interface is Java 1.4) |
| `StandardCharsets` / `String.getBytes(Charset)` / `new String(byte[],Charset)` (Java 6/7) | `Strings.toByteArray` / charset-*name* (`String`) overloads |
| `java.util.Arrays.copyOf` / `copyOfRange` (Java 6) | `System.arraycopy` (BC `org.bouncycastle.util.Arrays.copyOf` has only primitive/`BigInteger` overloads) |
| `ResourceBundle.Control` (Java 6) | `jdk1.5` overlay; emulate no-fallback by pinning `Locale.setDefault(loc)` across `getBundle` |
| `PKIXRevocationChecker`/`java.security.cert.Extension` (Java 8) | not portable — version-gate the provider registration / exclude the test |

Audit grep before shipping a change: `longValueExact()`, `new IOException(` with a 2nd arg (and `extends IOException` ctors), `StandardCharsets`, `getBytes(java.nio.charset`, `\bLong\.(parseUnsigned|compareUnsigned|divideUnsigned)`, `Integer.compare`, `Math.(getExponent|scalb)`, `java.util.Arrays.copyOf`, `\.destroy\(\)` on `SecretKey`, `ResourceBundle.Control`, `java.security.cert.PKIXRevocationChecker`. **mls is not in this build** — ignore its hits.

Note: `@Override` on an *interface*-method implementation is a genuine-javac-1.5 error, but the real build compiles under JDK 8 (`-source 1.5`, lenient), so it is **not** a blocker — don't churn those.

### (c) JVM defect — JRE 5's JIT miscompiles correct code

Not every JRE-5-only failure is a Java-version-API problem. The Oracle 1.5.0_22 i586 HotSpot **JIT miscompiles `org.bouncycastle.math.raw.Mod.modOddIsCoprimeVar`** (the safegcd routine behind `BigIntegers.hasAnySmallFactors`) once that path warms up — so `RSATest`'s small-factor modulus rejection silently doesn't fire. The bytecode is correct (passes on JDK 21 and under the 1.5 **interpreter**). Diagnostic recipe to classify any suspicious JRE-5 failure:

```
J5=/usr/lib/jvm/java-1.5.0-oracle-i586
CP=build/artifacts/jdk1.5/jars/bcprov-jdk15to18-*.jar:build/artifacts/jdk1.5/jars/bctest-jdk15to18-*.jar
"$J5/bin/java"          -cp "$CP" <SimpleTest fqcn>   # genuine JIT  -> reproduces
"$J5/bin/java" -Xint    -cp "$CP" <SimpleTest fqcn>   # interpreter  -> if it PASSES, it's a JIT bug, not a BC bug
$JAVA_HOME/bin/java     -cp "$CP" <SimpleTest fqcn>   # JDK 21       -> if it PASSES, not a logic bug
```

If `-Xint` passes but JIT fails, it's a JVM defect — don't "fix" the BC code; guard the affected assertion on `java.version` 1.5 (see exclusion note above) and document it.

## Quick reference

| Need | Command |
|---|---|
| Full build (JDK 8) | `sh build1-5to1-8` |
| Sign (this machine) | `/home/dgh/bin/bcsign build/artifacts/jdk1.5/jars/*.jar` |
| Test (JRE 5) | `sh build1-5to1-8 test` |
| Clean | `sh build1-5to1-8 clean` |
| Failure detail | `build/artifacts/jdk1.5/reports/xml/TEST-*.xml` |

Overriding JDKs: `JDKPATH` (build JDK, default 8) and `JDK5PATH` (test JRE, default the oracle i586 5) are read from the environment by `build1-5to1-8`.
