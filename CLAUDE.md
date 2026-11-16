# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Always loaded

- @docs/claude/build-and-test.md — driving Gradle (JDK 25), running single tests fast, the Java 1.4 source floor, stash-the-fix verification, why a green run can mean nothing ran, HEAD moving mid-run, OSS-Fuzz compatibility.
- @docs/claude/architecture.md — module graph and the `core`-into-`prov` trap, MR-jar overlays (hook classes, the mirror-image trap, `multiReleaseCheck`), `module-info` / `package-info` / OSGi wiring, `misc/` examples, `.bc` vs `.jcajce` layering, core's import control.
- @docs/claude/conventions.md — tests, exceptions and `SecurityExceptions`, `Properties` constants, release notes and the CVE embargo, version bumps, CONTRIBUTORS, commit messages, URL checking, code style.

## Read on demand — open the file before starting the matching work

| Read | Before |
|---|---|
| `docs/claude/domain-notes.md` (the relevant section) | changing X.509/ASN.1 x509 types, DER time handling, `AlgorithmIdentifier` comparison, `DefaultAlgorithmNameFinder`, a `Signature` SPI's `verify`/`setParameter`, LMS/HSS/XMSS private keys, CMS streaming/recipients/key agreement, PKCS#12 keystore SPIs, OpenPGP packet format or pg operator tests, the dual-located OID tables, a decoder's compatibility retry |
| `docs/claude/build-jdk14.md` | touching `src/main/jdk1.x` / `src/test/jdk1.x` overlays, `ant/*.xml`, running `build1-4` / `build1-5to1-8` / `build1-8+`, or diagnosing a legacy-build failure |
| `docs/claude/release-checks.md` | verifying a release candidate, tagging a release |
| `docs/claude/upstream-lts-ports.md` | porting an `UPSTREAM-*.md` change from the BC-LTS tree |

Skills cover the rest: `bcpqc-add-algorithm` (any PQC port), `build-jdk15to18`, `build-jdk13-docker`, `legacy-source-javadoc-jars`, `windows-build`.

Add new guidance to the file whose topic it fits. Keep the always-loaded files to rules a typical change needs; area-specific detail goes in an on-demand file with a row in the table above.
