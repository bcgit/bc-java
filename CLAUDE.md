# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

The detailed guidance is split across the files below (imported automatically). Add new guidance to the file whose topic it fits, and create a new `docs/claude/<topic>.md` + import line here when a genuinely new topic appears.

- @docs/claude/build-and-test.md — driving the Gradle build, running individual tests fast, the stash-the-fix verification discipline.
- @docs/claude/build-jdk14.md — the jdk1.4 (build1-4) legacy build: source preprocessing (what the regexes fix and what they can't), the real-1.4-javac compile floor, overlay delete-vs-sync discipline, the build → bcsign4 → test flow and its signing/staleness traps.
- @docs/claude/architecture.md — module graph and the `core`-into-`prov` trap, MR-jar overlays, `module-info.java` / `package-info.java` upkeep, where examples live, JCE provider registration, adding a PQC algorithm, `.bc` vs `.jcajce` package layering.
- @docs/claude/conventions.md — test conventions, X.509 / ASN.1 RFC discipline, strict cert parse vs reviewer, DER lenient-read/strict-write, exception-message contract, `SecurityExceptions` cause-chaining, property constants, non-standard interop, PKCS#12 SPI pair, CMS streaming I/O, operator close discipline, duplicated OID tables, release notes, commit messages, URL checking, code style.
