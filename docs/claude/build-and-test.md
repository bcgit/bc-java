# Build & test

Gradle multi-module. **Drive Gradle with JDK 25+**: `JAVA_HOME=/opt/jdk-25 BC_JDK25=/opt/jdk-25 ./gradlew …`. The unconditional `compileJava25Java` (`options.release = 25`) fails on an older daemon with `error: release version 25 not supported` and can leave `core/build/classes/java/main` empty (cascading "package does not exist"); Error Prone needs JDK 21+ (`UnsupportedClassVersionError: …ErrorProneJavacPlugin … class file version 65.0`). Optional `BC_JDK8`/`BC_JDK11`/`BC_JDK17`/`BC_JDK21`/`BC_JDK25` enable the version-specific test tasks (each `onlyIf` its variable; unset skips silently). Default `:test` aggregates `:core:test :prov:test :prov:test11 :prov:test15 :prov:test17 :pkix:test :pg:test :pgsc:test :tls:test :tls-klog:test :mls:test :mail:test :jmail:test`.

```
./gradlew clean build                                # full build + all tests
./gradlew :prov:compileJava :prov:compileTestJava    # quick compile-only check
./gradlew :prov:test --tests <AllTests fqcn>          # one suite (exact AllTests name, see below)
./gradlew -PexcludeTests=<glob> :prov:test           # exclude pattern
./gradlew :prov:checkstyleMain                       # brace/style check — CI fails on it (see conventions.md)
```

- Per-module test tasks only include `AllTest*` classes: `--tests` on any other class reports "No tests found", and a glob like `*cms.test.AllTests` fails too — give the suite's **exact** FQCN (`--tests org.bouncycastle.cms.test.AllTests`).
- `bc-test-data` (`bcgit/bc-test-data`) is needed for the full suite. `TestResourceFinder.findTestResource(homeDir, fileName)` (per-module copies under `<module>/src/test/java/org/bouncycastle/test/`) resolves it from `-Dbc.test.data.home`, then `$BC_TEST_DATA_HOME`, then by walking up from the working directory to a directory named `bc-test-data` (a sibling checkout just works). A set-but-wrong property/variable fails fast with `FileNotFoundException`; Gradle does not set it.

## Running an individual test fast

- `SimpleTest` subclasses have a `main()` printing `<TestName>: Okay` or the failure message.
- JUnit `TestCase` classes: `java -cp ... junit.textui.TestRunner org.bouncycastle.pkcs.test.PKCS12UtilTest`.

Classpath for running directly (add `-Dbc.test.data.home=…` if bc-test-data isn't a sibling):

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

- `*/build/resources/main` are required (resource files such as the GOST tables) — missing ones give cryptic NPEs.
- Put `<module>/src/test/resources` on the path (e.g. `pg/src/test/resources` for `pgpdata/*.kbx`), not `build/resources/test` (empty until `processTestResources`) — otherwise a null resource stream fails a *different* sub-test with an NPE / "Cannot take get instance of null".
- IntelliJ's `out/production/...` is not Gradle's output; don't use it.
- After deleting/renaming a test method or inner class, stale `.class` files under `build/classes/java/test/` still run and throw `ClassNotFoundException`/`NoClassDefFoundError`; flush with `:<module>:compileTestJava --rerun-tasks` or `:<module>:clean`.
- For `core` changes exercised through `prov`, mind the core-into-prov trap (`architecture.md`): compile both, `core` first on the classpath.

## A green Gradle run can mean the tests never ran — and the tree can move under you

**`UP-TO-DATE` test tasks** still print `BUILD SUCCESSFUL`. Tell: wall time in seconds. Confirm with `--console=plain` (`> Task :pkix:test UP-TO-DATE`) or check result-file timestamps. When in doubt: `:<module>:cleanTest :<module>:test`. `find` here is `bfs`: `-newermt` wants an ISO-8601 stamp, not `"30 minutes ago"`.

**Where results land:**
- Most modules: `<module>/build/test-results/test/*.xml`.
- `:core:test` and `:prov:test` write `TEST-<fqcn>.xml` directly in `<module>/build/test-results/` (no `test/` subdir), one per **leaf** `TestCase`, not per suite. The `prov` per-task subdirs (`test8/`, `test11/`, …) hold only `binary/`; totals are in `<module>/build/reports/tests/<task>/index.html`. So globbing `test-results/test/*.xml` there finds nothing even after a real run.
- The `AllTest*` filter applies to core too: a `TestCase` no `AllTests` references never runs (`Blake2bpDigestTest`/`Blake2spDigestTest` until github #2488). A leaf's missing XML is how a missing registration shows.
- Clean full `:core:test` here: ~8 minutes, 787 tests.

**HEAD moves while a suite runs** — the maintainer pulls into this clone mid-session (this once produced a wrong "my change broke three unrelated tests"):
- Print `git log --oneline -1` before and after any long run; trust the result only if they match.
- Before/after comparisons (stash the fix, re-run) must both be at the same HEAD. `git stash push` names the commit it stashed against — read it.
- `git log --oneline <old-head>..HEAD -- <paths>` shows whether incoming work touched your files.
- **Never `git checkout` a tag or branch in this clone to build it.** Use `git worktree add ../bc-java-<tag> <tag>` (beside `bc-java`, so the bc-test-data walk-up still works); `git worktree remove` when done.

**`BC_JDK8` is exported in the maintainer's shell**, so `:prov:test` also runs `test8`: the suite against the *built jar* on a real JDK 8, `maxParallelForks = 8`. A `:prov:test` that is suddenly slow or fails in untouched tests is usually `test8`.

## Verifying a fix actually catches the bug (stash-the-fix)

For any defect fix: write the reproducing test, `git stash push <fix-files>`, recompile (`./gradlew :<module>:compileJava`; for `core` fixes also `:prov:compileJava`), confirm the test fails on the original symptom, `git stash pop`, confirm it passes.

When the fix *introduces the API the test compiles against*, stash only the enforcement lines inside the method instead — stashing the whole patch just proves the API is new (worked example: `JceKTSKeyTransRecipient`, `915e7f3ffb`).

### A green run after breaking the code means the test never reached it — verify the break landed

Same technique answers "is this call site on my new path?" (put a `throw` at the top of the new method). A false green usually means:
- **The edit didn't apply** — a `sed` whose anchor missed is a silent no-op. `grep -c` the marker in the source *and* `javap -p -c <class> | grep -c` it in the compiled class.
- **A stale `prov` copy shadowed it** (core-into-prov trap) — compile `:core:compileJava :prov:compileJava`, put `core` first, and check the marker in both class trees.

Both fired in turn on the EC constant-time multiplier work (`965f42dae9`).

## Parsing base64 out of Java source: `+` is the concatenation operator

For PEM/key blobs spread over `"...\n" +` literals, extract each `"..."` literal's contents and join — don't strip non-base64 characters with a regex, which keeps the `+` and silently decodes garbage. Use `ssh-keygen -l -f` / `openssl asn1parse` as the authority where possible.

## Java source floor (legacy Ant builds)

`src/main/java` (and test code the legacy builds stage) is also built by the Ant distributions: `build1-4` compiles it with the **real JDK 1.4 javac** after a regex preprocessor that strips generics, annotations, varargs *declarations* and rewrites `StringBuilder`→`StringBuffer`; `build1-5to1-8` compiles on JDK 8 but runs on a **genuine JRE 5**, so Java 6+ APIs fail only at runtime. Gradle accepts all of this, so it can't catch it. Therefore:

- No enhanced-for, autoboxing, enums, covariant return overrides, varargs *call sites*, or post-1.4 APIs.
- `StandardCharsets` / `getBytes(charset)` → `Strings.toByteArray` / `Strings.toUTF8ByteArray`.
- `java.util.Arrays.copyOf(Range)` → BC `Arrays` or `System.arraycopy`.
- `new IOException(msg, cause)` → `Exceptions.ioException`; `new X(msg, cause)` for any `java.security`/`javax.crypto` exception → the `SecurityExceptions` factory (see conventions.md); own subclasses use `super(msg)` + `initCause`.
- `String.contains`/`isEmpty`, `Integer.numberOfLeadingZeros`/`compare` (→ BC `Integers`/`Longs`), `java.util.concurrent`, `ArrayDeque`, `ThreadLocal.remove()` (→ `set(null)`), `SecretKey.destroy()` (→ `instanceof Destroyable`).
- Implementing a generic interface (`Comparator<Foo>`) must use the erased `Object` signature and cast inside — the preprocessor strips the type argument but not the parameter types.
- A new `Properties.X` constant must also be added to `core/src/main/jdk1.4/org/bouncycastle/util/Properties.java`.
- `System.getenv` throws `java.lang.Error` on JRE 1.4 — guard with `catch (Error)`.

Full API list, overlay rules, the Ant build/sign/test flow and its traps: `docs/claude/build-jdk14.md` and the `build-jdk15to18` skill.

## OSS-Fuzz builds `main` with its own script — keep two things compatible with it

`google/oss-fuzz` `projects/bc-java` (`build.sh`, `Dockerfile`, the `*Fuzzer.java` harnesses) clones `main` daily, so a change here can break fuzzing with nothing failing locally:

- **It builds on JDK 17** (`gradle jar`, Error Prone off, `-x compileJava23Java -x java23Classes -x compileJava25Java -x java25Classes`). A new `src/main/jdkNN` source set above 17 breaks it with `release version NN not supported` until their `build.sh` gains a matching `-x` pair (the jdk23 `Pack` overlay did this in 2026-10).
- **Test helpers it compiles must not need JUnit** — a harness puts `pkix/src/test/java` on its classpath without JUnit. `CMSTestUtil` throws `AssertionError`, not `junit.framework.Assert`; keep it so.
- **Malformed-input fixes** must throw `IllegalArgumentException`/`IllegalStateException` (incl. `ASN1ParsingException`) or the checked exception the API declares. Any other unchecked exception from parsing (NPE, `ClassCastException`, index/arithmetic) is filed as a crash.

Status: the `bc-java` entry in `https://oss-fuzz-build-logs.storage.googleapis.com/status.json` (build id → `log-<build id>.txt` in the same bucket); check it after build changes. Local repro: in a `google/oss-fuzz` checkout, `python3 infra/helper.py build_image bc-java`, then `build_fuzzers` with a local source path (a real git clone) and `-e GIT_CONFIG_COUNT=1 -e GIT_CONFIG_KEY_0=safe.directory -e GIT_CONFIG_VALUE_0='*'` (`core/build.gradle` runs `git`), then `check_build`, `run_fuzzer`.
