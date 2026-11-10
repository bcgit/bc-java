# Release checks

Run these on every release candidate, before anything is published. Both 1.86 patch releases
shipped defects that only these checks see: 1.86.1 (github #2448, `SSLContext.createSSLEngine()`
threw `NoSuchMethodError` on JDK 9+) and 1.86.2 (github #2493, the 1.86.1 bctls bundles would not
resolve in OSGi). A green `./gradlew build` caught neither. Run every check against the **signed
jars as they will ship** (`<module>/build/libs/*-<ver>.jar`), not against `build/classes`, and keep
the published previous release as a negative control. A check that does not fail on the known-bad
jar has proved nothing.

Print `git log --oneline -1` first and confirm the jars' timestamps postdate that commit, so you
know which tree they came from.

## 1. Legacy Ant builds: build, sign and test all three

`build1-4`, `build1-5to1-8` and `build1-8+` each need a full build, then signing, then the signed
test target (see `build-jdk14.md` and the `build-jdk15to18` skill). Run each in its own
`git worktree` beside `bc-java`, never in this clone and never two in one `build/`. Remember
`mkdir -p core/src/main/resources` in a fresh tree.

- **jdk15to18 gets its OSGi manifests from `bnd.sh`, before signing.** Nothing in `build1-5to1-8`
  or the Ant files writes a bundle manifest for this line: the root `bnd.sh` wraps each jar with
  `biz.aQute.bnd` and has to be run by hand, over all nine jars
  (`sh ./bnd.sh build/artifacts/jdk1.5/jars/*.jar`, from the tree root, with `BND_HOME` naming the
  directory that holds `biz.aQute.bnd-2.2.0.jar`). It rewrites the manifest, so the order is build,
  `build-test`, `bnd.sh`, `bcsign`, `test-signed` - wrapping a signed jar invalidates its signature,
  and a jar signed without it ships with no `Bundle-SymbolicName` at all. The first 1.87 pass
  skipped the step and nothing failed, because the jar still loads and every test still passes;
  check 3 below is what notices. `bnd.sh` prints nothing on success. The jdk1.4 jars are **not**
  wrapped: that line ships without OSGi manifests, so `build1-4` stays build, sign, test.

- **Don't trust the exit status.** The wrapper scripts exit 0 after a failed `build` (see
  `build-and-test.md`). Grep each log for `BUILD FAILED` and count the jars: 8 for jdk1.4 (it has
  no bcjmail), 9 each for jdk15to18 and jdk18on. In the 1.87 cycle a failed jdk1.4 `build-lw`
  silently dropped bcpkix/bcpg/bcmail, and every suite then reported `ClassNotFoundException`.
- **Force a full genuine javac 1.5 test compile.** `build-test` is incremental, so delete
  `build/jdk1.5` and `build/bctest-jdk15to18-*` first, then check the log shows
  `Compiling <all> source files`. The 1.87 pass found 35 errors that an incremental compile hid.
- **Read the reports, not the console.** Sum `tests` / `errors` / `failures` across
  `build/artifacts/<jdkdir>/reports/xml/TEST-*.xml`, check every file is from this run, and check
  the suite count matches the previous run.
- New tests are the usual breakage: a test added this cycle that uses a post-1.4/1.5 API, or that
  drives an engine the legacy build excludes, needs an exclude in `ant/jdk14.xml` /
  `ant/jdk15+.xml`.
- **Audit overlays for drift.** List each `src/main/jdk1.4` / `jdk1.5` overlay whose base file has
  commits since the last release tag that the overlay doesn't
  (`git log <last-tag>..HEAD -- <base>` against `-- <overlay>`), and read what each missed. The 1.87
  pass found the jdk1.4 `SubjectPublicKeyInfoFactory` overlay could not encode X-Wing keys.
  Deleting the overlay fixed it. Prefer deletion when the base passes the real 1.4 build.

## 2. Multi-release linkage (the #2448 class)

```
./gradlew multiReleaseCheckJar -PmrClasspath=<bcprov>,<bcutil>,<bcpkix>,<bcpg>,<bcpgsc>,<bctls>,<bcmail>,<bcjmail>,<bcmls>
./gradlew multiReleaseCheckJar -PmrClasspath=<bcprov>,<bcutil>,<bcpkix>,<bctls-klog>
```

Both must print `OK`. Then run the same task against the published `bctls-jdk18on-1.86.jar` with
1.86 bcprov/bcutil from Maven Central (check the `.sha1`). It must report the `SSLEngineUtil.create`
pairings, or the gate has regressed (see `architecture.md`).

Back the gate with a runtime probe on every JDK the build knows (8, 11, 17, 21, 25), once with
bctls and once with bctls-klog:

- `SSLContext.getInstance("TLS", "BCJSSE")`, `init(null, null, null)`, then `createSSLEngine()`,
  `createSSLEngine(host, port)` and `beginHandshake()`. JDK 8 should load `ProvSSLEngine_8` and
  9+ should load `ProvSSLEngine_9`.
- On 21 and 25, an ML-KEM round trip through `javax.crypto.KEM` with provider `BC`. This covers the
  jdk17/jdk25 `SpiUtil` mirror-image trap.

The published 1.86 bctls on JDK 17 must throw the original `NoSuchMethodError`.

## 3. OSGi resolution (the #2493 class)

**Manifests.** Every bundle has `Bundle-Version: <ver>`, exports at `<ver>`, and every
`org.bouncycastle` import is ranged `[<major.minor>,<next>)`. The floor must never be a patch
version that sibling bundles are not published at. There is no `junit` anywhere in a manifest.
Resolve every import statically against the set's own exports; nothing may be unresolved.

**A real container.** Run Apache Karaf 4.3.x in a throwaway copy:
- Start from a copy with empty `data/` and `deploy/`, move the SSH/RMI ports, and enable the stock
  `karaf` user in `etc/users.properties`.
- Drive it with `bin/client -a <port> -u karaf -p karaf -b < commands`. Batch mode is required
  without a terminal.
- `bundle:install` and `bundle:start` the whole set, then bctls-klog. All must be `Active`.
- Also install the previous release's bcprov/bcutil and use `bundle:requirements <id>` to confirm
  every `org.bouncycastle` import still wired to the **new** bundles.
- Controls: published bctls 1.86.1 with bcprov/bcutil 1.86 must stay `Installed` with
  `missing requirement … (version>=1.86.1)`. Published 1.86.2 must go `Active`.

**The jdk15to18 bundles.** Repeat both halves over the wrapped, signed jars from check 1: these
manifests come from `bnd.sh`, not from the Gradle bnd plugin, so the Gradle result says nothing
about them. Each jar must carry `Bundle-SymbolicName`, `Bundle-Version: <ver>`,
`Bundle-RequiredExecutionEnvironment: J2SE-1.5`, exports at `<ver>` and `org.bouncycastle` imports
ranged `[<ver>,<next>)`, with nothing unresolved against the set. In Karaf, bcprov, bcutil, bcpkix,
bcpg, bctls, bcmail, bcjmail and bcprov-ext must all go `Active` and wire to each other. Two things
differ from the Gradle bundles by construction, and are expected rather than findings: `bcprov`
exports the `org.bouncycastle.internal.*` packages (the `bnd.sh` export is `org.bouncycastle.*`),
and `bctest` is wrapped like the rest but is not a usable bundle - it imports `junit` and exports
main-namespace packages that hold its package-private tests (`org.bouncycastle.est`,
`org.bouncycastle.tls`, ...), so it stays `Installed` with a uses constraint violation against
bcpkix.

## 4. Module descriptors (JPMS)

A missing `exports` line only hurts modular consumers, so no build or class-path test notices it.
Check every jar against its own descriptor:

- **Every distributed module has a descriptor.** Read `META-INF/versions/9/module-info.class` out of
  each jar with `javap`. In 1.87, pgsc, a new module, had none and would have shipped as the
  automatic module `bcpgsc.jdk18on`. (`jar --describe-module` won't take `--release` together with
  `--file` here, so use `javap` for multi-release jars.)
- **Exports match the jar.** Compare the `exports` with the packages that hold classes in the jar,
  counting root and `META-INF/versions/*` entries. Nothing may be exported that is absent, and
  nothing present may be unexported without a reason recorded in the descriptor or in
  `architecture.md`. Today the only such packages are bcprov's `org.bouncycastle.internal.*`,
  concealed by design. 1.87 found `org.bouncycastle.mls.TreeKEM` unexported since 2024, although 31
  public members of exported classes used its types and the OSGi manifest exported it.
- **The graph resolves.** Use `java -p <all jars + javax.mail/activation> --add-modules
  ALL-MODULE-PATH --validate-modules`, and `--list-modules` on JDK 11 and 25. Every BC module must
  appear by its `org.bouncycastle.*` name and none as `automatic`.
  `jdeps --multi-release 25 --module-path <jars> --check <module>` must report no missing
  dependencies other than documented optional ones (pgsc's YubiKit).
- **The two prov descriptors agree.** `diff prov/src/main/jdk1.9/module-info.java
  prov/src/main/ext-jdk1.9/module-info.java` must print nothing.
- **pgsc's YubiKey backend works modularly.** From the module path, with YubiKit (Gradle's
  resolution of `:pgsc:testRuntimeClasspath`, which includes its transitive jars) on the class
  path, `YubikeyOpenPGPSmartCardBackend.createInstance()` must fail with `IllegalAccessError`
  without `--add-reads org.bouncycastle.pgsc=ALL-UNNAMED` and succeed with it, as the descriptor's
  NOTE says.

## 5. Duplicate classes across the binary jars

List the classes in every binary jar of each set - the Gradle `*/build/libs/*.jar` (not the
`-sources` / `-javadoc` jars) and each Ant `build/artifacts/<jdkdir>/jars/*.jar` - and check that no
jar holds an entry twice and that no class turns up in two jars meant to sit on one class path.
Count a `META-INF/versions/N` copy as the same class as its root copy. The overlaps that are
expected, and so the whole of what the check should report:

- `bccore` is contained in `bcprov` (the `core`-into-`prov` build), and nothing in `bccore` is
  missing from `bcprov`.
- `bctls` and `bctls-klog` are alternative builds of one module; klog adds only the key-log classes.
- Ant `bcprov` and `bcprov-ext` have the same class list.
- Ant `bctest` repeats the `org.bouncycastle.util.test` support classes that `bcprov` ships
  (`SimpleTest`, `FixedSecureRandom`, ...); the copies must be byte-identical.
- `bcmail` and `bcjmail` carry the same class names by construction, as the javax and jakarta builds
  of one source tree. Check the pair makes sense rather than that it is disjoint: no `bcmail` class
  may reference `jakarta/mail` and no `bcjmail` class `javax/mail`, the classes that differ in bytes
  are the ones that touch the mail API, and neither jar shares a class with any other jar.

Anything else is a finding: `bcutil`, `bcpkix`, `bcpg`, `bcpgsc` and `bcmls` share no class with any
other jar. Compare the Ant and Gradle builds of the same module while the lists are to hand. The six
`handlers` classes of `bcjmail` come from `jmail/src/main/java` in both builds, but Ant excludes
mail's `handlers` directory outright while Gradle overlays it, so a class added to
`mail/.../smime/handlers` with no jmail counterpart reaches the Gradle `bcjmail` only; in 1.87 that
left an unreferenced `HandlerUtil` there. `jdeps -verbose:class` over the Ant jar, with its
dependencies on the class path, says whether the Ant jar needs what it lacks.

## 6. Signatures

`jarsigner -verify` every jar, legacy and Gradle alike.
