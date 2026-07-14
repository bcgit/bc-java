---
name: build-jdk13-docker
description: Build and test the legacy jdk1.3 (build1-3) distribution on a modern host by running the genuine Sun JDK 1.3.1 inside an i386 / glibc-2.3.6 Docker container. Use this whenever the user wants to run "build1-3" / the "jdk1.3" or "Java 1.3" build, get a bcprov-jdk13 jar, reproduce a genuine-1.3 compile failure, or when a genuine JDK 1.3.1 won't start on the host ("can't find libjava.so", missing libstdc++-libc6.1-1.so.2, or a green-threads Classic VM segfault). Captures the container recipe, why glibc < 2.4 is mandatory, the uname/libstdc++/threads traps, and that the jdk1.3 source overlays have rotted (the real source floor is Java 1.4).
---

# Building and testing the jdk1.3 (build1-3) distribution in Docker

The `jdk1.3` distribution is driven by `sh build1-3` → `ant/jdk13.xml` → `ant/bc+-build.xml`,
compiling with the **real Sun JDK 1.3.1** at `/opt/jdk1.3.1` and running tests on the same JRE.
Like `build1-4` it is a genuine-1.3 *compile* floor (post-1.3 APIs fail at compile time), but it
adds two things the jdk1.4 build does not: it builds its own **clean-room JCE** first (from
`jce/src/`, so **no jar signing** is needed — unlike jdk1.4/jdk15to18), and its preprocessor
rewrites the Java-1.4 cert-path API (`java.security.cert.CertStore/CertPath/PKIX*/…Selector`) to
BC's `org.bouncycastle.jce.cert.*` backport, plus `LinkedHashSet`→`HashSet`.

The blocker this skill solves: **a 2001-era 32-bit Sun JDK 1.3.1 cannot run on a modern Linux
host.** The fix is to run it in a period-appropriate i386 container.

## Quick start

```
.claude/skills/build-jdk13-docker/build-jdk13.sh provider   # build the provider -> bcprov-jdk13 jar
.claude/skills/build-jdk13-docker/build-jdk13.sh test        # full build + tests
.claude/skills/build-jdk13-docker/build-jdk13.sh shell       # interactive 1.3 container (fast iteration)
.claude/skills/build-jdk13-docker/build-jdk13.sh             # full build (no arg)
```

First run builds a tiny image (`bc-jdk13:etch`). i386 executes natively on an x86-64 kernel — **no
qemu**. Everything (JDK, ant, aux jars, the repo) is bind-mounted from the host; only a `uname`
shim is baked into the image. A full `provider` round is ~10 min (the `<replaceregexp>` preprocess
over ~6,800 files dominates, then the nojit Classic VM compiles).

## Why a genuine JDK 1.3.1 won't run on the host — and why etch

`/opt/jdk1.3.1` (→ `/opt/installs/jdk1.3.1_20`) is a 32-bit x86 Sun JDK. On Ubuntu 24.04:

1. **`uname` wall (cosmetic).** Its launch wrapper (`bin/.java_wrapper`) predates x86-64: it reads
   `uname -m`, gets `x86_64` (the container shares the host's amd64 kernel), can't map that to its
   i386 lib dir, and dies with **"can't find libjava.so."** Fixed by the image's `uname -m`→`i686`
   shim (apt is dead on EOL etch, so there is no `linux32`).
2. **VM wall (fatal on the host).** After that:
   - the default `-client`/HotSpot VM uses **native threads** whose launcher binary links the
     extinct **`libstdc++-libc6.1-1.so.2`** (gone from modern distros; and 1.3 native threads on
     NPTL is broken anyway);
   - the `-classic` VM uses **green threads** and needs no libstdc++ — but it **segfaults** on
     glibc ≥ 2.4. Cause: glibc 2.4 added `PTR_MANGLE` pointer mangling; Sun's green threads
     hand-roll `jmp_buf` context switches, so `longjmp` demangles a raw poked-in PC and jumps to
     garbage (`catchsegv` shows `EIP == fault address`, empty backtrace).

So the container base must be **i386 with glibc < 2.4**. `debian/eol:etch` (Debian 4.0, **glibc
2.3.6**) works; `debian/eol:sarge` (2.3.2) also works; anything ≥ 2.4 (jessie 2.19, …) segfaults.
Green threads are user-space, so the shared modern host **kernel** is not a problem.

The recipe therefore forces the **Classic VM / green threads** via a custom `jvm.cfg` (`-classic`
first = default VM → wrapper selects green threads → no libstdc++), sidestepping both VM problems.

## Recipe internals (in this skill dir)

- **`Dockerfile`** — `FROM debian/eol:etch`; the only customization is the `uname -m`→`i686` shim.
- **`jvm.cfg`** — reorders `-classic` to the top so every forked `java`/`javac` defaults to the
  green-threads Classic VM. Mounted over `/opt/jdk1.3.1/jre/lib/jvm.cfg` (works because that file
  already exists in the ro JDK mount).
- **`build-jdk13.sh`** — bind-mounts the JDK at `/opt/jdk1.3.1` (matching `build1-3`'s hardcoded
  `JDKPATH`), ant `/opt/apache-ant-1.6.5`, `/opt/javamail-1.3.1`, `/opt/jaf-1.0.2`, and the repo at
  `/work`; exports the `JAVA_MAIL_HOME`/`JAVA_ACTIVATION_HOME` that `build1-3` uses but forgets to
  set; runs as your uid so build artifacts aren't root-owned.

Two non-obvious mount facts:
- **ORO for `<replaceregexp>`.** JDK 1.3 has no `java.util.regex`, so ant's regexp preprocessing
  needs a Jakarta ORO impl (`/opt/ant/lib` ships only the `ant-apache-oro` *adapter*). The script
  locates an `oro-2.0.x.jar` (default `~/.m2/.../oro/2.0.8`) and injects it with `ANT_ARGS="-lib
  /opt/extralib"`. It is **not** dropped into `/opt/ant/lib` because docker cannot create a new
  mountpoint file inside the read-only `/opt/ant` mount (that fails with "read-only file system").
- `--platform linux/386` sets the userland arch but **not** the syscall personality, so `uname -m`
  still returns `x86_64` — hence the image `uname` shim rather than relying on `linux32`.

## The jdk1.3 overlays have rotted — the real source floor is Java 1.4

`build1-3 provider` does not currently produce a jar out of the box: the current `src/main/java`
uses **Java 1.4 APIs** that the jdk1.3 tree never caught up with. Known breakages (fixed where
noted; expect more to surface as each layer clears):

- **`Throwable.initCause` (Java 1.4, absent in 1.3).** Everything routes through
  `org.bouncycastle.util.Exceptions` and `org.bouncycastle.jcajce.provider.util.SecurityExceptions`,
  whose base classes chain via `initCause`. Handled with **jdk1.3 overlays** that construct
  message-only (1.3 has no `getCause`, so no caller can observe a dropped cause) — keep the message
  text verbatim (test contract) and the factory signatures in lockstep with base. Direct
  `initCause`/`getCause` users outside those two factories need per-file overlays too (grep them:
  `grep -rl '\.initCause(\|\.getCause(' core/src/main/java prov/src/main/java`).
- **`@Deprecated` survived preprocessing** (`illegal character: \64` = `@`, then cascading
  `<identifier> expected`). Root cause: the shared `ant/build.regexp` `${regexp}` strips
  `@Override`/`@SuppressWarnings`/`@FunctionalInterface` but **not** `@Deprecated`; `jdk14.xml` has
  a dedicated `@Deprecated` pass and `jdk13.xml` was missing it. **Fixed** by mirroring that pass
  into `ant/jdk13.xml`. (If a new annotation type appears, add a pass the same way.)

The Java-1.4-vs-1.3 delta is narrow in reachable code (`initCause`/`getCause` a handful of files,
plus a few `java.net.URI`/`java.nio.*` users, most of which already have overlays). There are **no**
`assert` statements or `java.util.regex` uses in reachable main code. So the effort is overlay-sync,
not a rewrite. Follow the overlay discipline in `docs/claude/build-jdk14.md` (prefer deleting an
overlay when base is 1.3-clean after preprocessing; NOTE-comment every overlay that must exist;
keep `core/src/main/jdk1.3/.../util/Properties.java` mirroring base constants).

## Iterating fast

The `<replaceregexp>` preprocess is the ~7-min bottleneck, and the staging tree is **never cleaned**
by the build (stale sources keep compiling), so after changing overlays/excludes:

```
rm -rf build                                         # on the host; build/ is gitignored
.claude/skills/build-jdk13-docker/build-jdk13.sh provider
```

For tighter loops use `shell`: it drops you into the 1.3 container with everything mounted, so you
can run `sh build1-3 provider` (or `ant -f ant/jdk13.xml build-provider`) directly and re-run after
editing overlays in `/work`, without paying container startup each time. Errors go to the console;
failed test suites write per-suite XML under `build/artifacts/jdk1.3/reports/xml/`.

Verify overlay fixes against the real build — the preprocessor plus 1.3 javac is the only authority,
never eyeball. Related: `docs/claude/build-jdk14.md`, the `build-jdk15to18` skill, and CLAUDE.md's
"Main source stays Java 4 compatible" note (the maintained floor is 1.4; 1.3 is stricter still).
