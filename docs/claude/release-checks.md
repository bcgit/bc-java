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

## 4. Signatures

`jarsigner -verify` every jar, legacy and Gradle alike.
