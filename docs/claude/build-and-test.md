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
- `prov/src/test/resources` and `core/src/test/resources` carry test fixtures referenced by `TestResourceFinder` and direct classpath lookups. Other modules have their own too — e.g. `pg/src/test/resources` holds the OpenPGP/keybox fixtures (`pgpdata/*.kbx` for `KeyBoxTest`), loaded via `getResourceAsStream`. Put `<module>/src/test/resources` on the classpath (not just `<module>/build/resources/test`, which is empty until `processTestResources` runs), or a test fails with a misleading NPE / "Cannot take get instance of null" from a null resource stream in a *different* sub-test than the one you changed.
- IDE-built classes under `out/production/...` (IntelliJ) are NOT on the Gradle classpath — don't reference them, and beware that they can drift from Gradle's outputs.
- After deleting or renaming a test method (e.g. when rolling back an edit), the stale `.class` file lingers under `<module>/build/classes/java/test/`. JUnit's `TestSuite.class` reflection-walk will still find and run the stale method, surfacing confusing `ClassNotFoundException` / `NoClassDefFoundError` for inner-class artifacts that were removed. Run `./gradlew :<module>:compileTestJava --rerun-tasks` (or `:<module>:clean`) after a rollback to flush.

## A green Gradle run can mean the tests never ran — and the tree can move under you

Two ways a "BUILD SUCCESSFUL" has lied in practice. Both are cheap to check and expensive to miss.

**`UP-TO-DATE` test tasks.** Gradle will skip a test task it believes is current and still print
`BUILD SUCCESSFUL`. The tell is the wall time: `:pkix:test` in seconds when it normally takes
minutes. Confirm with `--console=plain` and look for `> Task :pkix:test UP-TO-DATE` (a real run
prints the task line with no suffix), or check the result XML is actually fresh:

```
find <module>/build -name "*.xml" -path "*test-result*" -printf "%TH:%TM %p\n" | sort | tail
```

`ls`-ing the results directory is not enough — the directory mtime updates even when nothing is
rewritten, and `find -newermt "-30 minutes"` is *not* valid relative syntax (it silently matches
nothing; use `-newermt "30 minutes ago"`). When in doubt force it: `:<module>:cleanTest :<module>:test`.

**HEAD moves while a suite runs.** dgh pulls into this clone during a session, so a long
`:core:test` / `:prov:test` can straddle a merge and describe a tree that no longer exists. This
has already produced a confident-but-wrong "my change broke three unrelated tests" (the failures
belonged to the pre-pull tree). So:

- Print `git log --oneline -1` immediately before launching a long run and again when it finishes;
  only trust the result if they match.
- A before/after comparison (stash the fix, re-run) is only valid if **both** runs are at the same
  HEAD. Re-run the baseline if a pull landed between them.
- `git stash push <paths>` names the commit it stashed against ("WIP on main: <hash> <subject>") —
  a free HEAD check, worth reading rather than skipping.
- `git log --oneline <old-head>..HEAD -- <paths you changed>` says whether the incoming work
  touched what you are touching; uncommitted edits usually survive a pull untouched, but verify
  rather than assume.

**`BC_JDK8` is exported in dgh's shell**, so `:prov:test` pulls in `test8`, which runs the suite
against the *built jar* on a real JDK 8 with `maxParallelForks = 8`. That is a different execution
path from running a test class directly against `build/classes`, and the only place some failures
appear. A `:prov:test` that suddenly takes much longer, or fails in tests you did not touch, is
usually `test8`.

## Verifying a fix actually catches the bug

The repo's working norm for any defect-fix patch is: write the test that reproduces the bug, then **stash the fix** (`git stash push <fix-files>`), recompile (`./gradlew :<module>:compileJava`), rerun the test to confirm it now fails on the original symptom, then `git stash pop` and rerun to confirm it now passes. This catches tests that pass for the wrong reason. Use it whenever you add a regression test alongside a fix.

When the fix is in `core/`, remember to recompile `prov` too (the `core`-into-`prov` trap below) so the test JVM picks up the updated bytecode rather than a stale `prov/build/classes` shadow.

When the fix *introduces the API the test compiles against* (new public setters, a new class), stashing the whole patch just breaks the test compile — it proves the API is new, not that the test catches the bug. Stash or temporarily remove only the enforcement (the check lines inside the method), recompile the main tree, and confirm the negative cases fail on the original symptom before restoring. The `JceKTSKeyTransRecipient` constraint port (`915e7f3ffb`) is the worked example.

### A green run after breaking the code means the test never reached it — verify the break landed

The same stash/mutate technique also answers "is this call site actually on my new code path?": put a `throw` at the top of the new method and confirm each test that should exercise it now fails. But a **false green** — the test passing when the code is deliberately broken — has two boring causes far more often than it has an interesting one, and both point you at innocent code:

- **The edit didn't apply.** A scripted `sed`/`replace` whose anchor doesn't match is a silent no-op. Assert it: `grep -c` the marker in the source *and* `javap -p -c <class> | grep -c` it in the compiled class before believing any test result.
- **A stale `prov` copy shadowed it.** Per the `core`-into-`prov` trap, `prov/build/classes/java/main` contains its own build of every `core` class. If it precedes `core/build/classes/java/main` on a hand-built classpath, or if only `:core:compileJava` was re-run, the JVM loads the old bytecode. Compile both (`:core:compileJava :prov:compileJava`) and put `core` first — and confirm the marker is present in *both* class trees.

This bit the EC constant-time multiplier work (`965f42dae9`), where both causes fired in turn and produced a confident but wrong "none of these paths are wired" conclusion. It invalidates ordinary test *results* the same way it invalidates a probe, so when a `core` change is exercised through `prov` tests, compile both and order the classpath core-first as routine.

## Parsing base64 out of Java source: `+` is the concatenation operator

A recurring shape in this tree is a PEM or key blob spread over many `"...\n" +` string literals.
Stripping "non-base64" characters with something like `re.sub(r'[^A-Za-z0-9+/=]', '', text)` keeps
the `+` that joins the literals, silently corrupting the decode — the result still base64-decodes,
just into garbage, so the failure is a wrong *answer* rather than an error. This produced a
confident undercount of the OpenSSH test keys (8 of 15) that survived two rounds of "checking".
Extract the contents of each `"..."` literal instead, then join. Where a tool can confirm the
result — `ssh-keygen -l -f`, `openssl asn1parse` — use it as the authority rather than the parse.

## The legacy jdk15to18 (Java 5) build has a *runtime* floor Gradle can't see

Besides the Gradle build there is a legacy Ant distribution, `jdk15to18`, driven by `sh build1-5to1-8` (→ `ant/jdk15+.xml`). It is **1.5-bytecode compiled on JDK 8 and run on a genuine JRE 5**. Because the compile uses JDK 8's libraries (no `bootclasspath`), Gradle (`--release 8`) and the Ant build both happily accept Java 6/7/8 APIs — but those then throw `NoSuchMethodError`/`NoClassDefFoundError` at **runtime on JRE 5**. So a change that is perfectly Gradle-clean can still break the legacy jar.

Practical rule when touching reachable `src/main/java`: don't introduce Java 6/7/8 APIs. Route through the BC util wrappers that carry `jdk1.5` overlays (`Longs`/`Integers`/`BigIntegers`), use `Exceptions.ioException` not `new IOException(msg,cause)`, `Strings.toByteArray` not `getBytes(StandardCharsets…)`, `instanceof Destroyable` not `SecretKey.destroy()`, `System.arraycopy` not `java.util.Arrays.copyOf`, etc. This is the *runtime* sibling of the Java-4 *source* floor.

Full workflow (build → **sign with `/home/dgh/bin/bcsign`, this machine only** → test), the complete API→fix table, the test-exclusion overlay mechanism, and the diagnostic for telling a real bug from a JRE-5 JIT defect (`-Xint`) are in the `build-jdk15to18` skill.

There is an even stricter Java 1.4 distribution (`sh build1-4`) that compiles with a genuine 1.4 javac — post-1.4 APIs fail it at *compile* time, and it has its own overlay trees, source preprocessor, and signing flow: see `build-jdk14.md`.
