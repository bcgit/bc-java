# Coding conventions

Area-specific notes are in `docs/claude/domain-notes.md` — read the relevant section before changing: X.509/ASN.1 `asn1.x509` types and the strict cert parse / `X509CertificateReviewer`, DER time strictness, `AlgorithmIdentifier` comparison, `DefaultAlgorithmNameFinder`, `Signature.verify()` / `setParameter()` SPIs, stateful hash-based keys (LMS/XMSS), CMS streaming / recipients / key agreement (UKM) tests, PKCS#12 SPIs, OpenPGP packet format and pg operator tests, operator stream close discipline, duplicated OID tables, compatibility retries.

## Test conventions

- About half the tests extend `org.bouncycastle.util.test.SimpleTest` (not JUnit): override `performTest()`, call `fail(msg)` / `isTrue(msg, cond)` / `areEqual(a, b)`. Gradle doesn't discover them; they run from JUnit `AllTests` / `RegressionTest` wrappers. A new `SimpleTest` must be added to its package's `RegressionTest.tests` array or called from a parent test.
- The rest are `junit.framework.TestCase`s aggregated by an `AllTests` suite.
- **An `AllTests.suite()` must return a `TestSetup` wrapper (`return new BCTestSetup(suite);` with a nested `static class BCTestSetup extends TestSetup`, as in `tsp.test.AllTests`), never a bare `TestSuite`, and the class must `extends TestCase`.** Gradle filters on `includeTestsMatching "AllTest*"` per leaf test; JUnit's `JUnit38ClassRunner.filter()` filters a bare `TestSuite` child by child, so every child (`FooTest.testBar`) is rejected and the suite silently reports "no tests found" (six suites, 484 tests, sat in that hole until 2026-08). A `TestDecorator` root isn't filterable and runs whole. Confirm a new suite's results actually appear after a run (see `build-and-test.md` for where core/prov write them).
- bc-test-data is found via `TestResourceFinder` (see `build-and-test.md`); Gradle no longer passes `-Dbc.test.data.home`.
- The `:test` task forks a JVM per test class (`forkEvery = 1`).
- **Line endings vary by platform, so don't hard-code `\n` (or `\r\n`) against text that isn't fixed.** BC output built from `Strings.lineSeparator()` (armor, PEM, `ASN1Dump`, many `toString()`s) is CRLF on Windows, and `.gitattributes` (`text=auto`) checks text test resources out with native line endings. A test that compares or slices such text with literal line endings passes on Linux and fails on Windows (`PGPClearSignedBareCRTest.body()` found its header break only via `\n\n`). Build expected text with `Strings.lineSeparator()`, or search for whichever line ending actually occurs. Keep literal bytes only where the bytes are fixed (a protocol-mandated CRLF, a captured third-party message). Check on Linux with `-Dline.separator=$'\r\n'`.

## Prefer `getInstance(...)` over a cast for ASN.1 objects

Use the target type's static `getInstance(Object)` — `ASN1Integer.getInstance(seq.getObjectAt(0))`, not `(ASN1Integer)seq.getObjectAt(0)`. It normalises across encodings a cast can't (DL/BER vs DER, tagged wrappers) and throws a uniform `IllegalArgumentException("unknown object in getInstance…")` instead of `ClassCastException`. Cast only when no `getInstance` exists or you just built the object yourself.

## Exception messages are part of the test contract

Many tests assert exact message text (`e.getMessage().equals("...")`, `getCause().getMessage()`), often in another module. Before changing any thrown message — even a colon, or wrapping with `Exceptions.illegalArgumentException(...)` — grep the whole tree for the string and update every assertion in lockstep.

## Cause-chaining via `SecurityExceptions`

**In `prov`, never write `new X(msg, cause)` for a `java.security` / `javax.crypto` exception — call the factory in `org.bouncycastle.jcajce.provider.util.SecurityExceptions`**, which attaches the cause via `initCause`. Two groups need it:

- Exceptions with only a `(String)` constructor: `UnrecoverableKeyException`, `IllegalBlockSizeException`, `BadPaddingException`, `NoSuchPaddingException`, `NoSuchProviderException`, `CertificateExpiredException`, `CertificateNotYetValidException`, `InvalidParameterSpecException`, `ShortBufferException`, `AEADBadTagException`. Don't fold `e.getMessage()` into the text and drop the cause.
- Exceptions whose `(String, Throwable)` constructor is Java 5+ (`SignatureException`, `InvalidKeySpecException`, `InvalidAlgorithmParameterException`, `CertPathValidatorException`, …) — the two-arg form breaks the Java-4 source floor (`build-jdk14.md`). Some factories carry a "do not simplify" comment; a file currently behind an `ant/jdk14.xml` exclude is no excuse, excludes move.

```java
catch (Exception e)
{
    throw SecurityExceptions.unrecoverableKeyException("unable to recover key: " + e.getMessage(), e);
}
```

Existing factories: `invalidKeySpecException`, `generalSecurityException`, `invalidKeyException`, `invalidAlgorithmParameterException`, `invalidParameterException`, `noSuchAlgorithmException`, `signatureException`, `unrecoverableKeyException`, `illegalBlockSizeException`, `badPaddingException`, `certPathValidatorException`, `certPathBuilderException`, `certificateEncodingException`. Add a missing one there (one-line shape `return (X) new X(message).initCause(cause);`), never ad hoc at the throw site, and **add it to the `prov/src/main/jdk1.3` overlay of the class too** (diff the two classes' `public static` signatures afterwards). Keep message text verbatim and just add `e`. Throws outside a `catch` have nothing to chain and stay `new X(msg)`. Audit grep: `grep -rnE "new $Cls\(" prov/src/main/java`, filtered to lines with `e.getMessage()` / `e.toString()`.

## System / security property constants

Every property controlling BC behaviour is a `public static final String` in `core/src/main/java/org/bouncycastle/util/Properties.java` (e.g. `Properties.PKCS12_MAX_IT_COUNT`, `Properties.EMULATE_ORACLE`), named `org.bouncycastle.<area>.<flag>`. Reference the constant, not the literal, in production code and in tests using `System.setProperty`. (A new constant used from 1.4-compiled code must also go into the jdk1.4 `Properties` overlay — see `build-jdk14.md`.)

## Non-standard format interop

- Gate reading a non-standard encoding (e.g. SunJCE-shaped PKCS#12 secret keys, `Properties.PKCS12_ALLOW_SUN_SECRET_KEYS`) behind a `Properties.*` boolean **defaulting OFF**. The writer keeps producing the standard form unconditionally. The property's javadoc says what is read, why it's gated and what BC writes instead; the release note cites the issue.
- **Test against files the other implementation wrote**, not a hand-built imitation (which agrees with the parser by construction — the hand-built SunJCE fixture missed both the JDK's plain-`data` ContentInfo and its bare AES OID). Commit them to `bc-test-data` with the generator and a README (`pkix/pkcs12/jdk-secret-keys/` is the model), covering each variant the writer produces, and diff every identifier the other implementation emits against BC's table before writing the mapping.
- BC deliberately does not follow the JDK PKCS#12 per-entry password model (accepted limitation; see `domain-notes.md`, PKCS#12 SPI pair).

## Check whether the type already solves it before fixing a call site

Read the compared type's own `equals` / `getInstance` normalisation before concluding a comparison is too strict — `CertificateID.matchesIssuer` looked broken but `asn1.ocsp.CertID.equals` already tolerates absent vs `NULL`. Prove the defect with a probe, not by reading.

## Release notes

- **CVE embargo: a CVE number stays out of everything until the final release of the version that fixes it** — no release-note entry, Security Advisories list, commit message, source/test comment, javadoc or documentation. Write the defect entry in full without it; the numbers, advisories and cross-references are added when cutting the release. Until then the number lives only in the maintainer's local CVE records.
- Entries go in `docs/releasenotes.md` under the **current** unreleased block — the first `### Version <release>` heading (with `Release: <release>` beneath it).
- **One `-` bullet per entry, on one line** (keeps release-branch merges tractable), citing the GitHub issue where applicable. **Keep it short: one or two sentences, ~200 characters, rarely over 300.** Say what was wrong and what the library does now; keep what a user acts on (issue/PR number, new property name, releases affected, anything that stops existing data or code working). Mechanism, classes touched and reasoning go in the commit, javadoc or issue. The condensed 1.87 block is the model.
- Format: each version is preceded by a raw `<a id="r1rv<NN>"></a>` anchor (stable deep links, since GFM slugs of repeated subheadings shift), then `### Version <release>` matching its `Release:` line, then `####` subheadings `Defects Fixed`, `Additional Features and Functionality`, `Additional Notes`, `Security Advisories.` No section numbers (removed after 1.87, github #2567). A new block goes above the previous one; nothing below changes.
- At release, a CVE-bearing fix appears **twice**: the Defects Fixed entry ending in `(CVE-YYYY-NNNNN)`, and `<li>CVE-YYYY-NNNNN - <one-line summary>.</li>` in the Security Advisories list (`Release <ver> deals with the following CVEs:`), ascending by number. The 1.78 block (`b1e21a374d`) is the worked example. An advisory with no Defects Fixed entry is a gap: write the entry from what the commits changed, not by paraphrasing the advisory.
- No personal attribution ("Reported by" / "Contributed by") in release notes.

## `specifications.md` and `interoperability.md` are updated every release

- `docs/specifications.md` (developer reference: lightweight classes, provider algorithm names, key sizes, system properties, setup) — add what the release added, remove what it removed.
- `docs/interoperability.md` (standards map; source for the bouncycastle.org Specification & Interoperability page) — keep section names and two-column tables stable, add/remove rows; update rows when a cited standard is replaced, and check every new link.

Sources: the release's "Additional Features and Functionality" and removal entries. Removed algorithms (Picnic, Rainbow, GeMSS by 1.86) come out of both.

## Version bumps touch more than the build props

Update all together:

- `gradle.properties` — `version=`, `maxVersion=`.
- `bc-build.properties` — `release.suffix` / `release.version` (numeric, e.g. `1.85.99`) and `release.name` (e.g. `1.86-SNAPSHOT`).
- JCE provider `info` string (`"...Security Provider v<ver>[-SNAPSHOT]"`) and `super(PROVIDER_NAME, 1.<yy>99, info)` double in **every** copy: `prov/src/main/java/.../jce/provider/BouncyCastleProvider.java`, its `prov/src/main/jdk1.1` and `prov/src/main/jdk1.4` overlays, and `prov/src/main/java/.../pqc/jcajce/provider/BouncyCastlePQCProvider.java`. Dev-cycle double is `1.<prev>99` (e.g. `1.8599` while developing 1.86) with `<next>-SNAPSHOT` labels.
- **The OpenPGP armor stamp** (most often forgotten): `ArmoredOutputStream.DEFAULT_VERSION = "BCPG v<ver>"` in `pg/src/main/java/org/bouncycastle/bcpg/ArmoredOutputStream.java` **and** `pg/src/main/jdk1.4/...`, plus the tests asserting the armor `Version:` header (`BCPGOutputStreamTest`, `ArmoredInputStreamTest`, `PGPArmoredTest`, `ECDSAKeyPairTest`, `PGPv6SignatureTest`).

## `CONTRIBUTORS.md` is for contributed code, not for reporting a bug

- An entry is added when someone **opened a PR or otherwise supplied code**, including reworked or discarded patches ("initial implementation of ..."). A bug report alone normally doesn't earn one — the release-note issue number and the commit's `relates to github #NNNN` are the credit. A few older "Reported ..." entries exist; default is no entry, and adding one for a report is the maintainer's call — ask if unsure.
- **Sustained auditing** is the exception, and the maintainer initiates it: the entry names the area swept and what it led to, not individual bugs (`Arpan Sharma`'s "initial audit of BCPQC provider consistency starting with HQC ..."), appended to an existing entry. Don't add one unprompted.
- **Keep an entry under ~250 characters**: name areas, not fixes, and give PR runs as a range (`PRs #2437 to #2503`). If appending would exceed that, rewrite the entry as a summary. Entries whose names alone fill the line may run longer, by the maintainer's call.
- New entries go at the end in the form `- name-or-handle \<email-or-github-url\> - what they contributed (PR #NNNN).` (or `(issue #NNNN)` when it came on an issue); `https://github.com/<handle>` in place of an email is fine. A repeat contributor gets **appended to their existing entry**, not a second bullet.
- Write the `@` of an email as `&#064;`, never literally (grep for a stray `@` before committing), and escape the brackets `\<...\>` so GFM doesn't autolink a `mailto:`.

## Commit messages

A short imperative headline, ending `relates to github #NNNN.` for issue-driven work (e.g. `Corrected casing of Falcon naming when used with NamedParameterSpec, relates to github #2194`). Multi-line bodies are unusual; keep the headline self-contained. No CVE numbers (see Release notes).

## URLs in source, docs, and Javadoc must be checked before they ship

Fetch every URL you add (source, Javadoc, `releasenotes.md`, `README.md`, any tracked doc) and confirm it resolves and still says what you cite it for — hallucinated or rotted URLs look fine by eye.

- Confirm the cited section number actually contains the wording (errata, obsoletions and draft section drift).
- No internal or authenticated URLs in published source; if it needs auth to fetch, it doesn't belong.
- When deleting the only citation of a spec the code depends on, leave a textual hint naming the document.

## Code style

- Match the surrounding file: Allman braces, 4-space indentation, no tabs. Don't reformat untouched code.
- In Javadoc write `@throws`, not `@exception`.
- Braces are **machine-enforced** on every module's `src/main` by Gradle checkstyle (`config/checkstyle/checkstyle.xml`, toolVersion 14.0.0; test sources not checked): `LeftCurly option="nl"` (default token set, so classes, methods, control structures **and lambda bodies**, but not array initializers) and `RightCurly option="alone"`. A violation reads `[ERROR] …Foo.java:913:114: '{' at column 114 should be on a new line. [LeftCurly]`. Run `./gradlew checkstyleMain` (or `:<module>:checkstyleMain`) before pushing — CI fails on any violation. The legacy Ant builds run the same config (`[ant:checkstyle]` prefix).
