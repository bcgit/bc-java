# Build & test

The build is Gradle multi-module. **JDK 25+ is required to drive Gradle**: the `compileJava25Java` task (e.g. `prov/build.gradle`, `tls/build.gradle`) is unconditional and sets `options.release = 25`, so a Gradle daemon launched under JDK 21/17/etc. fails `:prov:compileJava25Java` with `error: release version 25 not supported`, and that failed compile can leave `core/build/classes/java/main` empty (cascading into confusing "package does not exist" errors on the next step). (Separately, JDK 21+ is the floor for the Error Prone compiler plugin, which is compiled for Java 21 / class file 65 — an older daemon fails `:core:compileJava` with `UnsupportedClassVersionError: …ErrorProneJavacPlugin … class file version 65.0 … up to <NN>.0`.) On this machine a JDK 25 lives at `/opt/jdk-25`; drive Gradle with `JAVA_HOME=/opt/jdk-25 BC_JDK25=/opt/jdk-25 ./gradlew …`. Optional environment variables `BC_JDK8`, `BC_JDK11`, `BC_JDK17`, `BC_JDK21`, `BC_JDK25` opt in version-specific test tasks (compiled against MR-jar overlays). The default `:test` aggregates `:core:test :prov:test :prov:test11 :prov:test15 :prov:test17 :pkix:test :pg:test :tls:test :mls:test :mail:test :jmail:test`.

Per-module test tasks (`:util:test`, `:pkix:test`, …) restrict to `AllTest*` classes, so `--tests org.foo.SomeTest` for a non-`AllTests` class reports "No tests found"; run the aggregating suite instead, by **exact** class name (a glob like `*cms.test.AllTests` fails to match under the `AllTest*` include — `--tests org.bouncycastle.cms.test.AllTests` works).

```
./gradlew clean build                                # full build + all tests
./gradlew :prov:compileJava :prov:compileTestJava    # quick compile-only check
./gradlew :prov:test --tests <fqcn>                  # one JUnit class
./gradlew -PexcludeTests=<glob> :prov:test           # exclude pattern
./gradlew :prov:checkstyleMain                       # brace/style check (see conventions.md)
```

Style (Allman braces etc.) is machine-enforced on `src/main` by checkstyle and fails CI — run `checkstyleMain` before pushing. See the Code style section in `conventions.md` for what the config enforces.

`bc-test-data` (separate repo `bcgit/bc-test-data`) must be checked out for the full suite to pass. `TestResourceFinder.findTestResource(homeDir, fileName)` (six per-module copies under `<module>/src/test/java/org/bouncycastle/test/`) resolves the bc-test-data root in this order:

1. The system property `bc.test.data.home`, if set.
2. The environment variable `BC_TEST_DATA_HOME`, if set.
3. Walk up from the working directory looking for a directory literally named `bc-test-data` — the default that makes `./gradlew :prov:test` work when bc-test-data is checked out as a sibling of `bc-java`.

When the property or environment variable is supplied, the named path is required to exist; a mistyped value fails fast with a `FileNotFoundException` naming both the source (`-Dbc.test.data.home` or `$BC_TEST_DATA_HOME`) and the bad path, rather than silently falling through. The Gradle build no longer sets the property itself; supply `-Dbc.test.data.home=/path/to/bc-test-data` (or export `BC_TEST_DATA_HOME` once in your shell) only when the sibling-checkout convention doesn't fit your layout. Direct `java -cp ... junit.textui.TestRunner ...` invocations follow the same rule.

## Running an individual test fast

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

## Verifying a fix actually catches the bug

The repo's working norm for any defect-fix patch is: write the test that reproduces the bug, then **stash the fix** (`git stash push <fix-files>`), recompile (`./gradlew :<module>:compileJava`), rerun the test to confirm it now fails on the original symptom, then `git stash pop` and rerun to confirm it now passes. This catches tests that pass for the wrong reason. Use it whenever you add a regression test alongside a fix.

When the fix is in `core/`, remember to recompile `prov` too (the `core`-into-`prov` trap below) so the test JVM picks up the updated bytecode rather than a stale `prov/build/classes` shadow.

## The legacy jdk15to18 (Java 5) build has a *runtime* floor Gradle can't see

Besides the Gradle build there is a legacy Ant distribution, `jdk15to18`, driven by `sh build1-5to1-8` (→ `ant/jdk15+.xml`). It is **1.5-bytecode compiled on JDK 8 and run on a genuine JRE 5**. Because the compile uses JDK 8's libraries (no `bootclasspath`), Gradle (`--release 8`) and the Ant build both happily accept Java 6/7/8 APIs — but those then throw `NoSuchMethodError`/`NoClassDefFoundError` at **runtime on JRE 5**. So a change that is perfectly Gradle-clean can still break the legacy jar.

Practical rule when touching reachable `src/main/java`: don't introduce Java 6/7/8 APIs. Route through the BC util wrappers that carry `jdk1.5` overlays (`Longs`/`Integers`/`BigIntegers`), use `Exceptions.ioException` not `new IOException(msg,cause)`, `Strings.toByteArray` not `getBytes(StandardCharsets…)`, `instanceof Destroyable` not `SecretKey.destroy()`, `System.arraycopy` not `java.util.Arrays.copyOf`, etc. This is the *runtime* sibling of the Java-4 *source* floor.

Full workflow (build → **sign with `/home/dgh/bin/bcsign`, this machine only** → test), the complete API→fix table, the test-exclusion overlay mechanism, and the diagnostic for telling a real bug from a JRE-5 JIT defect (`-Xint`) are in the `build-jdk15to18` skill.

There is an even stricter Java 1.4 distribution (`sh build1-4`) that compiles with a genuine 1.4 javac — post-1.4 APIs fail it at *compile* time, and it has its own overlay trees, source preprocessor, and signing flow: see `build-jdk14.md`.
