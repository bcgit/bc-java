# Release checks

Assumes `build-jdk14.md`, the `build-jdk15to18` skill and `architecture.md`'s multi-release section are read as needed.

Run these on every release candidate, before anything is published. A green `./gradlew build`
caught neither 1.86 patch-release defect: 1.86.1 (github #2448, `SSLContext.createSSLEngine()`
threw `NoSuchMethodError` on JDK 9+) and 1.86.2 (github #2493, 1.86.1 bctls bundles would not
resolve in OSGi).

- Run every check against the **signed jars as they will ship** (`<module>/build/libs/*-<ver>.jar`),
  not `build/classes`.
- Keep the published previous release as a negative control. A check that does not fail on the
  known-bad jar has proved nothing.
- Print `git log --oneline -1` first and confirm the jars' timestamps postdate that commit.

## 1. Legacy Ant builds: build, sign and test all three

`build1-4`, `build1-5to1-8` and `build1-8+` each need a full build, signing, then the signed test
target. Run each in its own `git worktree` beside `bc-java`, never in this clone and never two in
one `build/`. `mkdir -p core/src/main/resources` in a fresh tree.

- **jdk15to18 OSGi manifests come from `bnd.sh`, before signing.** Nothing in `build1-5to1-8` or
  the Ant files writes a bundle manifest; run by hand over all nine jars, from the tree root, with
  `BND_HOME` naming the directory holding `biz.aQute.bnd-2.2.0.jar`:
  `sh ./bnd.sh build/artifacts/jdk1.5/jars/*.jar`. It rewrites the manifest, so the order is build,
  `build-test`, `bnd.sh`, `bcsign`, `test-signed` - wrapping invalidates a signature, and a jar
  signed without it has no `Bundle-SymbolicName`. Skipping it fails nothing (jars load, tests pass);
  only check 3 notices. `bnd.sh` prints nothing on success. jdk1.4 jars are **not** wrapped (no OSGi
  manifests), so `build1-4` stays build, sign, test.
- **The debug variants are part of the release.** jdk1.4 and jdk15to18 each ship
  `<module>-debug-<vmrange>-<ver>` jars, built with `release.debug: true` (`build-jdk14.md`, "The
  debug variant"). Build each in its own fresh worktree, sign, run `test-signed`, and check every
  debug jar has exactly the entry names of its plain twin.
- **Don't trust the exit status** - the wrapper scripts exit 0 after a failed `build`. Grep each log
  for `BUILD FAILED` and count the jars: 8 for jdk1.4 (no bcjmail), 9 each for jdk15to18 and
  jdk18on. (1.87: a failed jdk1.4 `build-lw` silently dropped bcpkix/bcpg/bcmail.)
- **Force a full genuine javac 1.5 test compile.** `build-test` is incremental: delete `build/jdk1.5`
  and `build/bctest-jdk15to18-*` first, then check the log shows `Compiling <all> source files`
  (1.87: 35 errors hidden by an incremental compile).
- **Read the reports, not the console.** Sum `tests` / `errors` / `failures` across
  `build/artifacts/<jdkdir>/reports/xml/TEST-*.xml`, check every file is from this run, and check
  the suite count matches the previous run.
- New tests are the usual breakage: one using a post-1.4/1.5 API, or driving an engine the legacy
  build excludes, needs an exclude in `ant/jdk14.xml` / `ant/jdk15+.xml`.
- **Audit overlays for drift.** List each `src/main/jdk1.4` / `jdk1.5` overlay whose base file has
  commits since the last release tag that the overlay lacks (`git log <last-tag>..HEAD -- <base>`
  vs `-- <overlay>`), and read what each missed (1.87: jdk1.4 `SubjectPublicKeyInfoFactory` could
  not encode X-Wing keys). Prefer deleting the overlay when the base passes the real 1.4 build.

## 2. Multi-release linkage (the #2448 class)

```
./gradlew multiReleaseCheckJar -PmrClasspath=<bcprov>,<bcutil>,<bcpkix>,<bcpg>,<bcpgsc>,<bctls>,<bcmail>,<bcjmail>,<bcmls>
./gradlew multiReleaseCheckJar -PmrClasspath=<bcprov>,<bcutil>,<bcpkix>,<bctls-klog>
```

Both must print `OK`. Negative control: the same task against published `bctls-jdk18on-1.86.jar`
with 1.86 bcprov/bcutil from Maven Central (check the `.sha1`) must report the
`SSLEngineUtil.create` pairings, or the gate has regressed.

Runtime probe on every JDK the build knows (8, 11, 17, 21, 25), once with bctls and once with
bctls-klog:

- `SSLContext.getInstance("TLS", "BCJSSE")`, `init(null, null, null)`, then `createSSLEngine()`,
  `createSSLEngine(host, port)` and `beginHandshake()`. JDK 8 must load `ProvSSLEngine_8`, 9+
  `ProvSSLEngine_9`.
- On 21 and 25, an ML-KEM round trip through `javax.crypto.KEM` with provider `BC` (covers the
  jdk17/jdk25 `SpiUtil` mirror-image trap).

Control: published 1.86 bctls on JDK 17 must throw the original `NoSuchMethodError`.

## 3. OSGi resolution (the #2493 class)

**Manifests.** Every bundle has `Bundle-Version: <ver>`, exports at `<ver>`, and every
`org.bouncycastle` import ranged `[<major.minor>,<next>)`. The floor must never be a patch version
sibling bundles are not published at. No `junit` anywhere in a manifest. Resolve every import
statically against the set's own exports; nothing may be unresolved.

**A real container** - Apache Karaf 4.3.x in a throwaway copy:
- Empty `data/` and `deploy/`, move the SSH/RMI ports, enable the stock `karaf` user in
  `etc/users.properties`.
- Drive with `bin/client -a <port> -u karaf -p karaf -b < commands` (batch mode required without a
  terminal).
- `bundle:install` and `bundle:start` the whole set, then bctls-klog. All must be `Active`.
- Also install the previous release's bcprov/bcutil; `bundle:requirements <id>` must show every
  `org.bouncycastle` import still wired to the **new** bundles.
- Controls: published bctls 1.86.1 with bcprov/bcutil 1.86 must stay `Installed` with
  `missing requirement … (version>=1.86.1)`; published 1.86.2 must go `Active`.

**The jdk15to18 bundles.** Repeat both halves over the wrapped, signed jars from check 1 (their
manifests come from `bnd.sh`, so the Gradle result says nothing about them). Each jar must carry
`Bundle-SymbolicName`, `Bundle-Version: <ver>`, `Bundle-RequiredExecutionEnvironment: J2SE-1.5`,
exports at `<ver>` and `org.bouncycastle` imports ranged `[<ver>,<next>)`, nothing unresolved. In
Karaf, bcprov, bcutil, bcpkix, bcpg, bctls, bcmail, bcjmail and bcprov-ext must all go `Active` and
wire to each other. Expected differences, not findings:
- `bcprov` exports `org.bouncycastle.internal.*` (the `bnd.sh` export is `org.bouncycastle.*`).
- `bctest` is wrapped but unusable - it imports `junit` and exports main-namespace packages holding
  its package-private tests (`org.bouncycastle.est`, `org.bouncycastle.tls`, ...), so it stays
  `Installed` with a uses constraint violation against bcpkix.

## 4. Module descriptors (JPMS)

A missing `exports` only hurts modular consumers, so no build or class-path test notices it.

- **Every distributed module has a descriptor.** Read `META-INF/versions/9/module-info.class` from
  each jar with `javap` (`jar --describe-module` won't take `--release` with `--file`). 1.87's new
  pgsc had none and would have shipped as automatic module `bcpgsc.jdk18on`.
- **Exports match the jar.** Compare `exports` with the packages holding classes, counting root and
  `META-INF/versions/*` entries. Nothing exported may be absent; nothing present may be unexported
  without a reason recorded in the descriptor or `architecture.md` - today only bcprov's
  `org.bouncycastle.internal.*`, concealed by design. (1.87 found `org.bouncycastle.mls.TreeKEM`
  unexported since 2024.)
- **The graph resolves.** `java -p <all jars + javax.mail/activation> --add-modules
  ALL-MODULE-PATH --validate-modules`, and `--list-modules` on JDK 11 and 25: every BC module by its
  `org.bouncycastle.*` name, none `automatic`. `jdeps --multi-release 25 --module-path <jars>
  --check <module>` must report no missing dependencies other than documented optional ones
  (pgsc's YubiKit).
- **The two prov descriptors agree.** `diff prov/src/main/jdk1.9/module-info.java
  prov/src/main/ext-jdk1.9/module-info.java` prints nothing.
- **pgsc's YubiKey backend works modularly.** From the module path, with YubiKit (Gradle's
  `:pgsc:testRuntimeClasspath`, transitive jars included) on the class path,
  `YubikeyOpenPGPSmartCardBackend.createInstance()` must fail with `IllegalAccessError` without
  `--add-reads org.bouncycastle.pgsc=ALL-UNNAMED` and succeed with it.

## 5. Duplicate classes across the binary jars

List the classes in every binary jar of each set - Gradle `*/build/libs/*.jar` (not `-sources` /
`-javadoc`) and each Ant `build/artifacts/<jdkdir>/jars/*.jar`. No jar may hold an entry twice and
no class may appear in two jars meant for one class path; a `META-INF/versions/N` copy counts as
the same class as its root copy. Expected overlaps, the whole of what should be reported:

- `bccore` is contained in `bcprov`, and nothing in `bccore` is missing from `bcprov`.
- `bctls` and `bctls-klog` are alternative builds; klog adds only the key-log classes.
- Ant `bcprov` and `bcprov-ext` have the same class list.
- Ant `bctest` repeats the `org.bouncycastle.util.test` support classes `bcprov` ships
  (`SimpleTest`, `FixedSecureRandom`, ...); the copies must be byte-identical.
- `bcmail` / `bcjmail` share class names by construction (javax and jakarta builds). Check: no
  `bcmail` class references `jakarta/mail`, no `bcjmail` class `javax/mail`, classes differing in
  bytes are those touching the mail API, and neither shares a class with any other jar.

Anything else is a finding; `bcutil`, `bcpkix`, `bcpg`, `bcpgsc` and `bcmls` share nothing. Also
compare Ant and Gradle builds of each module: Ant excludes mail's `handlers` directory while Gradle
overlays it, so a class added to `mail/.../smime/handlers` with no jmail counterpart reaches only
the Gradle `bcjmail` (1.87: an unreferenced `HandlerUtil`). `jdeps -verbose:class` over the Ant jar,
dependencies on the class path, says whether it needs what it lacks.

## 6. Signatures

`jarsigner -verify` every jar, legacy and Gradle. Verify jdk1.4 jars with
`/opt/jdk1.4.2/bin/jarsigner -verify` (prints `jar verified.`): they use the 1024-bit key a 1.4 JRE
needs, which a current JDK reports as "treated as unsigned … weak algorithm" even when correct.

## 7. Tagging

Once checks pass and the release notes carry the date, tag both repositories with the same
lightweight tag `r1rv<NN>` (`r1rv87`; patch releases `r1rv86v1`, `r1rv86v2`):

- `bc-java`: the commit the release was built from, including any last documentation commit.
- `bc-test-data`: the commit the release tests ran against. `git fetch` first and check
  `git status -sb` - the local checkout is often a commit behind `origin/main`, possibly missing
  vectors this release reads.

Tags are created locally and pushed by the maintainer. `git diff --stat <build-commit> <tag> -- .
':!docs' ':!CONTRIBUTORS.md'` should show nothing that reaches a jar.
