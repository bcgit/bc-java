# The jdk1.4 (build1-4) legacy build

Besides Gradle and the jdk15to18 Ant build there is a Java 1.4 distribution: `sh build1-4`
drives `ant/jdk14.xml` (which delegates to `ant/bc+-build.xml`). It compiles with the **real
JDK 1.4 javac** at `/opt/jdk1.4.2` and runs tests on the same JRE — so unlike jdk15to18
(compiled on JDK 8, where API breaks only surface at runtime), post-1.4 API usage fails the
jdk1.4 build at **compile time**. A change that is Gradle-clean and jdk15to18-clean can still
break here; when touching reachable `src/main/java`, this build is the strictest check.
`build1-4` needs `/opt/jdk1.4.2`, `/opt/javamail-1.3.1/mail.jar` and `/opt/jaf-1.0.2/activation.jar`
(the script sets its own JAVA_HOME/CLASSPATH).

## Source assembly and the preprocessor

`ant/jdk14.xml`'s `init` copies base `*/src/main/java` + `*/src/test/java` into the staging
tree `build/jdk1.4` (with per-fileset excludes), then overwrites with the
`<module>/src/main/jdk1.4` / `src/test/jdk1.4` overlay trees, then runs `replaceregexp`
passes (patterns in `ant/build.regexp`) over the result. The preprocessor strips generics,
`@Override`/`@Deprecated`/`@SuppressWarnings`, rewrites `StringBuilder`→`StringBuffer`, and
turns varargs *declarations* (`...`) into arrays.

What is therefore FINE in 1.4-reachable code: generics, `StringBuilder`, varargs
declarations. What is NOT (the regexes can't fix syntax or APIs): enhanced-for loops,
autoboxing, enums, covariant return overrides, varargs *call sites*, and any post-1.4 API —
`String.contains`/`isEmpty`, `System.clearProperty` (use `System.getProperties().remove`),
`java.util.Arrays.copyOf(Range)` (use BC `Arrays`), `Integer.numberOfLeadingZeros`/`compare`
(use BC `Integers` or open-code), `Math.scalb`/`getExponent` (Java 6 — see `Dpe`'s private
bit-twiddling helpers for the pattern), `java.util.concurrent` (use synchronized collections
or plain `Thread` + `join`), `ArrayDeque`, `ResourceBundle.Control`,
`ECGenParameterSpec`/`OAEPParameterSpec`/EC `java.security.spec` types (Java 5 — use the BC
`org.bouncycastle.jce.spec` equivalents), `NameClassPair.getNameInNamespace`,
`KeyStore.SecretKeyEntry`, `Cipher.updateAAD`, `javax.crypto.spec.GCMParameterSpec` (use BC
`AEADParameterSpec` — the jdk1.4 `BaseBlockCipher` understands it), `(String,Throwable)`
exception constructors (use `Exceptions` / `SecurityExceptions` factories, or
`super(msg)` + `initCause` in subclasses), and `ThreadLocal.remove()` (use `set(null)`).

Two 1.4-only compiler/runtime traps with no modern analogue:

- **`System.getenv` throws `java.lang.Error` on JRE 1.4** ("getenv no longer supported").
  The six `TestResourceFinder` copies guard their `BC_TEST_DATA_HOME` lookup with
  `catch (Error)` for this reason — any new env-var read in test-reachable code needs the
  same guard.
- **JLS2 static method hiding requires identical return types.** A subclass static
  `getInstance(Object)` cannot narrow the parent's return type on 1.4 javac — that is why
  the `util/src/main/jdk1.4` cmp overlays (`CertAnnContent`, `OOBCert`,
  `NestedMessageContent`) keep the widened `CMPCertificate`/`PKIMessages` return types.
  Do not "fix" them to match base.
- **`StringBuilder`+`StringBuffer` overload pairs collapse.** Because of the
  `StringBuilder`→`StringBuffer` rewrite, a base class carrying both overload families
  (e.g. `IETFUtils.appendRDN`) becomes duplicate methods after preprocessing. Such files
  need a jdk1.4 overlay that is base minus the legacy `StringBuffer` overloads.

## Overlay discipline: delete when you can, sync when you must

The jdk1.4 overlay trees are hand-maintained forks and they rot: the 2026 overlay-sync sweep
found missed security fixes (name-constraint bypasses, RSA/ElGamal decrypt hardening,
policy-tree DoS guard, armor-header CRLF checks), broken registrations (an
`AlgorithmParametersSpi` class name that hadn't existed since 2020), and stale test
assertions. Rules of thumb:

- **Prefer deleting an overlay** when the base file is 1.4-clean after preprocessing
  (`PKIXNameConstraintValidator`'s overlay was deleted this way) — the build then always
  uses base and cannot drift. Verify with the real build, not by eyeball: the preprocessor
  plus 1.4 javac is the only authority.
- When an overlay must exist, open it with a NOTE comment saying exactly why (see the
  jdk1.4 `IETFUtils`), and keep everything else in step with base.
- `core/src/main/jdk1.4/.../util/Properties.java` must mirror every base constant that
  1.4-compiled code references — a new `Properties.X` used from a base-compiled class is
  the most common way main breaks this build (it happened twice in one week).
- Provider registrations are part of the sync: a service registered by a shared base
  `Family.java` whose SPI inner class is missing from the overlay (`ec/SignatureSpi`
  deterministic-DSA/SHAKE variants) fails only at `getInstance` time. Conversely, on JRE
  1.4 `sun.security.x509.AlgorithmId` consults provider `AlgorithmParameters`
  registrations during certificate parsing — registering an SPI that can't parse the
  algorithm's parameters (EC SPI for GOST) breaks Sun-side cert parsing; the jdk1.4
  `ECGOST` deliberately registers none.

## Build → sign → test

```
sh build1-4                                   # build-provider, build, zip-src
JAVA_HOME=/opt/jdk1.4.2 ant -f ant/jdk14.xml build-test
/home/dgh/bin/bcsign4 build/artifacts/jdk1.4/jars/*.jar    # this machine only
JAVA_HOME=/opt/jdk1.4.2 ant -f ant/jdk14.xml test
```

- JRE 1.4's JCE authenticates providers: unsigned bcprov jars fail with
  "provider BC may not be signed by a trusted party". `bcsign4` signs jdk14 jars with
  `bc1024key` via the 1.4 jarsigner (silently — an empty log is success).
- **Sign every jar, and sign after `build-test`**: the junit classpath takes the provider
  from `bcprov-ext-jdk14` plus all other jars in `artifacts/jars`, JRE 1.4 requires all
  classes in one package to share signer info, and the `test` target's `build-test`
  dependency re-jars `bctest` (wiping its signature) if anything recompiled.
- Package-private provider tests (`prov/src/test/java/org/bouncycastle/jce/provider/*.java`
  — `CrlCacheTest` etc.) are excluded in `ant/jdk14.xml` for the same reason `jdk15+.xml`
  excludes them: the test jar cannot share `org.bouncycastle.jce.provider` with the signed
  provider jar.
- The staging tree `build/jdk1.4` and artifact trees are **never cleaned** by the build:
  ant `<copy>` doesn't remove files that a new exclude should drop, and stale sources keep
  compiling. After changing excludes, deleting overlays, or renaming files, `rm -rf build`
  before rebuilding.
- Failed suites write per-suite XML under `build/artifacts/jdk1.4/reports/xml/` — the
  junit console output hides the actual exception; read the XML.
- Fast iteration on a single failure: `ant -f ant/jdk14.xml build-provider`, re-sign
  `bcprov-ext`, then run the test class directly with
  `/opt/jdk1.4.2/bin/java -Xmx1536m -cp <jars> <test class>` (SimpleTests print
  `<Name>: Okay`); the full pipeline is ~25 minutes, this loop is ~2.

Tests that genuinely cannot run on 1.4 (post-1.4 JCA APIs, algorithms excluded from the
distribution) get an `ant/jdk14.xml` exclude — but check the suite wiring first: a
`TestCase` referenced from a compiled `AllTests` needs either a jdk1.4 `AllTests` overlay
without the reference or a jdk1.4 stub overlay of the test itself (see the
`PKCS12PfxPduSecretKeyTest` overlay, which keeps the high-level-builder half and drops the
JCE-keystore half).
