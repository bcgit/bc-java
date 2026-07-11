---
name: legacy-source-javadoc-jars
description: Build Maven-style -sources.jar and -javadoc.jar files for the legacy Ant distributions (jdk1.4 via build1-4, and jdk15to18 via build1-5to1-8) from the src.zip / src and javadoc artifacts the Ant build already produces. Use whenever the user wants source/javadoc jars for the jars in build/artifacts/jdk1.4/jars or build/artifacts/jdk1.5/jars — the Gradle build makes these automatically but the legacy Ant builds do not.
---

# Source & javadoc jars for the legacy Ant distributions (jdk1.4 / jdk15to18)

The Gradle build emits `-sources.jar` / `-javadoc.jar` per module automatically. The **legacy Ant
builds do not** — but they *do* leave everything needed to make them, so this is a repackaging job,
not a rebuild. Reach for this after a `sh build1-4` or `sh build1-5to1-8` run when the user wants the
publishable source/javadoc jars alongside the binary jars.

## What the Ant build leaves you

Each Ant distribution writes, under `build/artifacts/<JDKDIR>/`:

- `jars/` — the compiled binary jars, `<module>-<VMRANGE>-<ver>.jar`.
- `<module>-<VMRANGE>-<ver>/` — one directory per module, containing:
  - `src.zip` — the **preprocessed** 1.4/1.5 source, `org/...` at the archive root (this is what you
    want in a sources jar; do NOT re-run the preprocessor).
  - `javadoc/` — the generated javadoc HTML tree, `index.html` + `org/...` at the root.

| build | script | `<JDKDIR>` | `<VMRANGE>` |
|-------|--------|------------|-------------|
| jdk1.4 | `sh build1-4` | `jdk1.4` | `jdk14` |
| jdk15to18 | `sh build1-5to1-8` | `jdk1.5` | `jdk15to18` |

The module set differs slightly: jdk15to18 adds `bcjmail`; both have `bcprov, bcprov-ext, bcutil,
bcpkix, bcpg, bcmail, bctls, bctest`.

## Three irregular cases (the whole reason this needs a skill, not a one-liner)

1. **`bcprov-ext` has no `src.zip` or `javadoc/` of its own.** The ext jar is the same provider
   content as `bcprov` (byte-near-identical), so its sources/javadoc jars are copies of `bcprov`'s.
   Map `bcprov-ext-<VMRANGE>-<ver>` → the `bcprov-<VMRANGE>-<ver>/` directory.
2. **`bctest` ships `src/` (a directory), not `src.zip`, and has no `javadoc/`.** So `bctest` gets a
   sources jar (from the `src/` tree) but **no** javadoc jar — the Ant build generates no javadoc for
   the test module. This is expected, not a gap to fix.
3. Everything else: `src.zip` → sources jar, `javadoc/` → javadoc jar.

Output naming follows Maven: `<module>-<VMRANGE>-<ver>-sources.jar` and `-javadoc.jar`, written into
the same `jars/` directory as the binary jars.

## The script (parameterised; works for both builds)

Set `JDKDIR` to `jdk1.4` or `jdk1.5` and run. It derives every module from the jars actually present
(so it self-adjusts to bcjmail etc.), handles the `-ext` fallback and the `src.zip`-vs-`src/` split,
and skips javadoc where there is none (bctest).

```bash
JDKDIR=jdk1.4                       # jdk1.4  (build1-4)   |  jdk1.5 (build1-5to1-8)
ROOT="$PWD/build/artifacts/$JDKDIR"
OUT="$ROOT/jars"
JAR="${BC_JDK25:-/opt/jdk-25}/bin/jar"   # any modern jar tool; these are source/doc, not class jars

for jar in "$OUT"/*.jar; do
  base=$(basename "$jar" .jar)
  case "$base" in *-sources|*-javadoc) continue;; esac   # don't reprocess our own output

  moddir="$ROOT/$base"
  [ -d "$moddir" ] || moddir="$ROOT/$(echo "$base" | sed 's/-ext-/-/')"   # bcprov-ext -> bcprov

  # sources: prefer src.zip (repack into a proper jar with a manifest), else a src/ tree
  if [ -f "$moddir/src.zip" ]; then
    tmp=$(mktemp -d); unzip -q -o "$moddir/src.zip" -d "$tmp"
    ( cd "$tmp" && "$JAR" cf "$OUT/$base-sources.jar" . ); rm -rf "$tmp"
  elif [ -d "$moddir/src" ]; then
    ( cd "$moddir/src" && "$JAR" cf "$OUT/$base-sources.jar" . )
  fi

  # javadoc: only if a javadoc/ tree exists (bctest has none)
  [ -d "$moddir/javadoc" ] && ( cd "$moddir/javadoc" && "$JAR" cf "$OUT/$base-javadoc.jar" . )
done

ls -la "$OUT"/*-sources.jar "$OUT"/*-javadoc.jar
```

## Verify

- Sources jar: `jar tf X-sources.jar | grep -c '\.java$'` (bcprov jdk1.4 ≈ 2891), and a spot file like
  `org/bouncycastle/crypto/engines/AESEngine.java`.
- Javadoc jar: `jar tf X-javadoc.jar` shows `index.html` and `overview-summary.html` at the root.
- Expect one sources jar per binary jar, and one javadoc jar per binary jar **except bctest**
  (jdk1.4: 8 sources + 7 javadoc; jdk15to18: 9 sources + 8 javadoc, with bcjmail).

## Notes

- `build/artifacts/` is build output — untracked, nothing to commit.
- These are byte-reproducible from the same Ant build; the `src.zip` is the authoritative source
  (already preprocessed for the target JDK), so never regenerate sources from `*/src/main/java`.
- If `bcprov-ext` and `bcprov` sources/javadoc jars come out identical in size/entry count, that's
  correct — they are the same content.
