# Coding conventions

## Test conventions

- Most tests extend `org.bouncycastle.util.test.SimpleTest` (not JUnit). They override `performTest()` and call `fail(msg)` / `isTrue(msg, cond)` / `areEqual(a, b)`. They are *not* discovered by Gradle directly — they're invoked from JUnit `AllTests` / `RegressionTest` wrappers.
- `RegressionTest.tests` arrays (one per package) list every `SimpleTest` to be run. When you add a new `SimpleTest`, also add a call from a parent test or from `RegressionTest`.
- Tests pass `-Dbc.test.data.home=<core/src/test/data>` for fixture lookups.
- The `:test` task runs each test class in its own JVM (`forkEvery = 1`).

## X.509 ASN.1 changes — check the RFC first

Anything under `core/src/main/java/org/bouncycastle/asn1/x509/` is a wire-format ASN.1 type from a specific PKI RFC. Before changing or extending one of these classes (parsing rules, structural constraints, defaults, error messages thrown for malformed input), verify the proposed behaviour against the authoritative RFC:

- Most extensions and the certificate / CRL container types: **RFC 5280** (extensions in §4.2.x, cert fields in §4.1.x, CRL fields in §5.1.x).
- Attribute certificates (`AttributeCertificateInfo`, `Holder`, `AttCertIssuer`, `V2Form`, `IssuerSerial`, etc.): **RFC 5755** (current; previously RFC 3281).
- OCSP types (`OCSPResponse`, `BasicOCSPResponse`, `ResponseData`, etc.): **RFC 6960**.
- Validation policy / qualified-cert types: RFC 3739 / RFC 3279 / X9.62 as appropriate.

When the RFC contains a "MUST" / "MUST NOT" that the existing code doesn't enforce, that's the actionable spec — cite the section in the commit message and (where helpful) in javadoc. When the RFC is silent, prefer staying compatible with what other major libraries (OpenSSL, Java's CertificateFactory, GnuTLS) accept rather than tightening unilaterally. Same convention applies to neighbouring ASN.1 PKI packages (`asn1/pkcs`, `asn1/cms`, `asn1/cmp`, `asn1/ocsp`) — cite RFC 7292 / 5652 / 4210 / 6960 etc.

For X.509 / WebPKI work specifically, the **CAB Forum** Baseline Requirements (<https://cabforum.org/>) layer additional constraints on top of RFC 5280 — key sizes, signature algorithm sets, extension presence/criticality, profile-specific name encodings, etc. Where a CAB Forum BR or guideline narrows what RFC 5280 allows and the change makes sense for general-purpose BC users (not just publicly-trusted CAs), follow the BR rather than the looser RFC. Cite the BR section alongside the RFC in the commit message / javadoc, and call out in the PR when a change is BR-driven so reviewers know it's deliberately stricter than the RFC.

## Certificate parse stays strict — diagnostics go through a separate reviewer

The cert-parse path deliberately **fails fast**: `org.bouncycastle.asn1.x509.Certificate` / `TBSCertificate` / `Extensions` throw on the first problem and never hand back a partially-parsed object. Do not make them permissive to "report more" — that request (github #1508, PR #1511 — which proposed a permissive parse returning partial objects) was rejected in favour of keeping the parser strict and adding a *reporting* layer on top. The reporting layer is `org.bouncycastle.cert.X509CertificateReviewer` (pkix) — a JCA-free, top-level `cert` class whose `reviewStructure(byte[])` / `reviewStructure(ASN1Sequence)` return a `Review` (a list of `Finding`s plus the recovered `X509CertificateHolder` when, and only when, the strict path would also accept it). It is the parse-side analogue of `PKIXCertPathReviewer`.

`TBSCertificate` and `Extensions` single-source their checks so the strict path and the reviewer apply *exactly* the same rules. The trick is a null-sink: the real work lives in `private void parse(ASN1Sequence seq, List errors)`, and each check calls `reportProblem(errors, msg)` instead of `throw`:

- `errors == null` (the strict `getInstance(...)` path) — `reportProblem` throws `new IllegalArgumentException(msg)`, exactly as the legacy code did. Because it throws, no statement after a call site runs in strict mode, so strict behaviour and messages are provably unchanged; the "continue with a sensible default" branches are reachable only when collecting.
- `errors != null` (the public `reviewStructure(ASN1Sequence)` collector) — `reportProblem` adds the exception to the list and parsing continues, so every problem is enumerated.

So when you add a new structural check to one of these classes, route it through `reportProblem(errors, msg)` — a bare `throw new IllegalArgumentException(...)` in `parse` would be invisible to the reviewer, and duplicating the check in the reviewer would drift. `reviewStructure` returns a `List` of the *exceptions* the strict path would have thrown (not strings), in parse order. `Extensions.reviewStructure`'s list is grouped by `TBSCertificate` under one `org.bouncycastle.util.AggregateRuntimeException` (a `RuntimeException` carrying a `List` of underlying exceptions); `X509CertificateReviewer` expands that into per-extension `Finding`s at location `tbsCertificate.extensions`. Keep the strict `getInstance` and the `reviewStructure` collector in lockstep, and exercise both with the stash-the-fix discipline plus the existing cert batteries (`core` `asn1.test.AllTests`, pkix `cert.test.AllTests`, prov `CertTest`).

## Prefer `getInstance(...)` over a cast for ASN.1 objects

When pulling a typed ASN.1 object out of a container (`ASN1Sequence.getObjectAt(n)`, a tagged object's contents, a decoded `getInstance` argument, etc.), use the target type's static `getInstance(Object)` factory rather than a Java cast — `ASN1Integer.getInstance(seq.getObjectAt(0))`, not `(ASN1Integer)seq.getObjectAt(0)`. Every BC ASN.1 type (and the higher-level structure types in `asn1.x509`, `asn1.pkcs`, `asn1.cms`, …) ships such a factory, and it is the preferred way of dealing with ASN.1 primitives and structures.

`getInstance` does more than a cast: it normalises across encodings the cast can't bridge (e.g. a DL/BER element where a DER one is expected, or an element that arrived wrapped in a tagged object), it throws a uniform `IllegalArgumentException("unknown object in getInstance…")` with a type-meaningful message instead of a bare `ClassCastException`, and it gives one consistent entry point if the type's internal representation later changes. A plain cast only succeeds when the in-memory object is already exactly that class, so it is brittle against the lenient-read encodings BC accepts on the wire. Reserve the cast for the rare case where no `getInstance` exists, or where you have just constructed the object yourself and the type is genuinely known.

## ASN.1 DER strictness: lenient read, strict write

ASN.1 primitives that have multiple legal wire encodings (e.g. `UTCTime` / `GeneralizedTime` — with or without seconds, with `Z` or a `+hhmm` offset, with or without a fractional component) accept all those **legal** variants leniently on read — `createPrimitive(byte[])` does not enforce *DER* restrictions. When DER conformance matters (e.g. for downstream interop with OpenSSL or other strict consumers), gate the enforcement at the **write** side: in `toDERObject()`, check the in-memory contents and throw `DEREncodingException` (`org.bouncycastle.asn1`, extends `IllegalStateException`) when emitting them would produce non-DER bytes. The gate goes behind a `Properties.*` flag **defaulting to `"true"`** — i.e. `Properties.isOverrideSet(name, true)` — so the strict mode is opt-in; flipping the property to `"false"` makes any attempt to write the primitive through a `DEROutputStream` fail without changing default behaviour for anyone else.

Lenient-on-read covers legal-but-non-DER *formatting*, not malformed *content*. For the time primitives, `createPrimitive(byte[])` now also rejects structurally invalid content unconditionally (no property gate): `ASN1UTCTime` / `ASN1GeneralizedTime` route the decode path through `org.bouncycastle.asn1.ASN1TimeFormat.isValidUTCTime` / `isValidGeneralizedTime`, throwing `IllegalArgumentException("invalid UTCTime format" / "invalid GeneralizedTime format")` for non-digit or out-of-range fields (month 01-12, day 01-31, hour 00-23, minute/second 00-59), illegal lengths, and missing/garbage terminators — the malformed inputs an ASN.1 fuzzer surfaces, which the old "first two/four bytes are digits" check let through and `getDate()` then turned into a nonsensical `Date` or a late exception. This is read-side *well-formedness* validation, distinct from read-side DER-strictness (still not enforced) and from the write-side DER gate above; the validator accepts the legal lenient forms (no-seconds, offset, trailing-zero fraction). The message deliberately omits the offending bytes (they may carry control characters). `createPrimitive` validates **before** constructing; programmatic construction (`String`/`Date` constructors) and DER re-encoding (`toDERObject`, which builds the `DER*` subclass via the `byte[]` constructor) do not pass through `createPrimitive` and so are unchanged. Note this narrows the github #2040 case from a write-only gate to an outright read rejection (a 2-digit-year value tagged `GeneralizedTime` has an out-of-range month).

`DEROutputStream`'s three write call sites — `writeElements`, `writePrimitive`, `writePrimitives` — catch `DEREncodingException` and bridge it to `IOException` via `Exceptions.ioException(msg, cause)`, so `getEncoded(ASN1Encoding.DER)` surfaces the failure as a checked `IOException` whose `getCause()` is the original `DEREncodingException`. BER serialization is unaffected. Programmatic construction from a `Date` (or any other in-memory value) is expected to produce DER content, so the gate only matters for primitives whose contents arrived non-conformant from the wire and the caller then tries to re-emit them as DER.

The worked example is `Properties.ASN1_ALLOW_NON_DER_TIME` for time fields (`ASN1UTCTime` / `ASN1GeneralizedTime`, github #1973 / #1986 / #2040). Reuse the same shape — `toDERObject` gate + `DEREncodingException` + default-on `Properties.*` flag — for any future DER-strictness opt-in on a primitive type, so the lenient-on-read convention is preserved and a single property name conveys the same semantic regardless of which primitive flips. This complements "Non-standard format interop" below: that section covers *read-side* concessions that default off; this one covers *write-side* DER restrictions that default off.

## Exception messages are part of the test contract

Many tests assert on exact exception message text (e.g. `isTrue(e.getMessage().equals("..."))` or `getCause().getMessage()` checks). Changing the wording of a thrown exception — even something as small as adding a colon, rewording for clarity, or wrapping with `Exceptions.illegalArgumentException(...)` — will silently break tests in another module. Before modifying any exception message, grep the whole tree for the existing string and update every matching assertion in lockstep.

## Cause-chaining via `SecurityExceptions` for cause-less JDK exceptions

A handful of `java.security` / `javax.crypto` exceptions ship only a `(String)` constructor — no `(String, Throwable)` form — including `UnrecoverableKeyException`, `IllegalBlockSizeException`, `BadPaddingException`, `NoSuchPaddingException`, `NoSuchProviderException`, `CertificateExpiredException`, `CertificateNotYetValidException`, `InvalidParameterSpecException`, `ShortBufferException`, and `AEADBadTagException`. When wrapping a caught exception with one of these inside a `catch (… e)` block, do not fold the underlying text into the new exception's string and discard the cause:

```java
catch (Exception e)
{
    throw new UnrecoverableKeyException("unable to recover key: " + e.getMessage()); // anti-pattern: cause is dropped
}
```

Route the throw through `org.bouncycastle.jcajce.provider.util.SecurityExceptions` — a `prov` utility class carrying `(String message, Throwable cause)` factories that attach the cause via `initCause`:

```java
catch (Exception e)
{
    throw SecurityExceptions.unrecoverableKeyException("unable to recover key: " + e.getMessage(), e);
}
```

Factories exist today for `unrecoverableKeyException`, `illegalBlockSizeException` and `badPaddingException`. Add a new factory there (same one-line shape — `return (X) new X(message).initCause(cause);`) when migrating throws of any other cause-less class above; do **not** roll `new X(msg).initCause(e)` ad-hoc at the throw site. The migration is purely additive: keep the existing message text verbatim (it is almost certainly under test assertions per the previous section) and add `e` as the second argument — callers that do not care still see the same exception type and message, while callers that do can walk `getCause()`.

Throw sites *outside* a `catch` block — value-check branches like `if (x.size() == 0) throw new UnrecoverableKeyException("…")` — have nothing to chain and stay as plain `new X(msg)`. The audit grep when adding a factory is `grep -rnE "new $Cls\(" prov/src/main/java` filtered by which lines contain `e.getMessage()` / `e.toString()` (the cause-folding pattern); pure-literal throws are not candidates.

## System / security property constants

Any system or security property that controls BC behaviour belongs in `core/src/main/java/org/bouncycastle/util/Properties.java` as a `public static final String`, e.g. `Properties.PKCS12_MAX_IT_COUNT`, `Properties.PKCS12_IGNORE_USELESS_PASSWD`, `Properties.EMULATE_ORACLE`. Callers should reference the constant rather than inlining the literal `"org.bouncycastle.…"` name — both in production code and in tests that flip the property via `System.setProperty`. New properties should be added to `Properties` with the same naming pattern (`org.bouncycastle.<area>.<flag>`).

## Non-standard format interop

When supporting a non-standard wire encoding for interop with another implementation (e.g. SunJCE-shaped PKCS#12 secret keys per `Properties.PKCS12_ALLOW_SUN_SECRET_KEYS`, or vendor-specific TLS quirks), gate the new code path behind a `Properties.*` boolean and default it OFF. Keep the writer producing the standards-compliant form unconditionally — interop is a one-way concession on the read side, not a license to round-trip non-standard output. Cite the deviation in the property's javadoc (what's read, why it's gated, what BC writes instead) and reference the issue number in the release note so future maintainers can find the rationale.

## PKCS#12 SPI pair

The PKCS#12 keystore comes in two SPI flavours that share the bag-handling pipeline: `PKCS12KeyStoreSpi` (legacy MAC) and `PKCS12PBMAC1KeyStoreSpi` (RFC 9579 PBMAC1). When changing entry-type acceptance, bag dispatch in `engineLoad`, the cert/key write passes in `engineStore`, or the `getUsedCertificateSet` / `cryptData` helpers, the change usually needs mirroring in the other SPI. Shared static helpers — algorithm-OID lookup, key-size table, content/iteration-count helpers — live in the package-private `org.bouncycastle.jcajce.provider.keystore.pkcs12.PKCS12Util` so both SPIs can call them without one having to fully-qualify the other; new helpers should land there too rather than as static methods on either SPI.

## CMS streaming I/O: caller owns the outer stream

The streaming classes under `pkix/src/main/java/org/bouncycastle/cms/CMS*{Parser,StreamGenerator}.java` deliberately do **not** cascade close to caller-supplied streams, unlike `GZIPOutputStream` / `CipherOutputStream`. Stream generators finalize the CMS structure on `close()` of the returned `OutputStream` (writes signer infos, MAC, end-of-contents markers) but do not close the target `OutputStream` — if the target is a buffering encoder whose tail state only flushes on close (e.g. Apache Commons `Base64OutputStream`), the caller has to close it themselves. Parsers read only enough of the supplied `InputStream` to expose CMS metadata; encapsulated content drains lazily through `getContentStream()` / `getSignedContent()`, and the `InputStream` is closed only when the caller invokes `parser.close()` (inherited from `CMSContentInfoParser`). This convention is long-standing — changing it has been explicitly rejected (github #1572).

When updating CMS class-level javadoc, verify by tracing rather than paraphrasing aspirational behaviour: between Aug–Dec 2025 the `CMSAuthEnvelopedDataParser` doc claimed the constructor "fully drains and closes" the InputStream and that "plaintext content is buffered in memory" — both were wrong (the constructor reads ~84% of the input, no buffering happens), and the doc was corrected as part of github #2133. The model `<b>Stream handling note:</b>` blocks added across the package under that issue are the template to follow.

## Operator OutputStream close discipline

When writing data to a `ContentSigner.getOutputStream()` (or the symmetric `ContentVerifier.getOutputStream()`), **always call `close()` on the returned stream before calling `getSignature()` / `verify(...)`**. Many implementations finalise digest / signature state inside `close()` — feeding bytes without closing can produce truncated input, missing trailing-block computations, or a downstream JCA `Signature.SignatureException`. The canonical pattern (see `X509v3CertificateBuilder.generateSig`):

```java
OutputStream sOut = signer.getOutputStream();
tbsObj.encodeTo(sOut, ASN1Encoding.DER);
sOut.close();
return signer.getSignature();
```

Same applies on the verifier side — `X509CertificateHolder.isSignatureValid` follows this pattern. The chained one-liner `signer.getOutputStream().write(bytes)` skips the close and is a latent bug; introduce a named local for the stream so the close is unmistakable.

## Two locations for the same OID-table class

A handful of less-common arc OID classes are duplicated in the tree:

- `core/src/main/java/org/bouncycastle/internal/asn1/<arc>/<X>ObjectIdentifiers.java` — the **`internal.asn1`** copy, bundled into `core` (and so into `prov` via the core-into-prov srcDirs trick).
- `util/src/main/java/org/bouncycastle/asn1/<arc>/<X>ObjectIdentifiers.java` — the **public** copy, the API surface for downstream consumers.

Affected arcs include `kisa` (SEED), `nsri` (ARIA), `ntt` (Camellia), `oiw`, `gnu`, `eac`, `cms`, `bsi`, `cryptlib`, `edec`, `iso`, `isara`, `isismtt`, `microsoft`, `misc`, `rosstandart`, etc. When importing from inside `core` or `prov` use the `internal.asn1.<arc>.<X>ObjectIdentifiers` form — `util` isn't on those modules' compile classpath, and the obvious `org.bouncycastle.asn1.<arc>` import will fail with a misleading "package does not exist". From `pkix` upward (or any module that already depends on `util`), the public form is fine.

The `iana` arc is *not* dual-located: `org.bouncycastle.asn1.iana.IANAObjectIdentifiers` lives only in `core` (public package, bundled into `bcprov` via the core-into-prov trick and exported by `prov`'s `module-info`), so `core` / `prov` and everything above import the same `org.bouncycastle.asn1.iana` form. It was consolidated out of the `util` copy + `internal.asn1.iana` copy in the 1.85 cycle (github #2176) — don't reintroduce an `internal.asn1.iana` copy.

## Release notes

Defects fixed and additional features go into `docs/releasenotes.html` under the **current** unreleased version block (e.g. section 2.1 with header "Release: 1.85"). Each entry is a single `<li>...</li>` referencing the GitHub issue number where applicable. The file is hand-edited HTML; preserve the existing prose style and `<ul>` structure.

## Commit messages

Existing convention: a short imperative sentence ending with `relates to github #NNNN.` for issue-driven work (e.g. `Corrected casing of Falcon naming when used with NamedParameterSpec, relates to github #2194`). Multi-line bodies are unusual — keep the headline self-contained.

## URLs in source, docs, and Javadoc must be checked before they ship

Any URL you add to a source file, Javadoc, `releasenotes.html`, `README.md`, or any other tracked document has to actually resolve to the page you're citing — and the page has to still say what you're citing it for. Hallucinated paths, rotted spec URLs, and "I made up an OID page on iana.org" all read identically when reviewed by eye; the only way to catch them is to fetch the URL and confirm. The model fetches I have available are good enough to do this — use them, before committing.

Two non-obvious failure modes worth pre-empting:
- **The URL works but the cited section number is wrong.** When citing "RFC 5280 sec. 4.2.1.12" or "RFC 9162 sec. 7.1", confirm the linked section actually contains the wording you're paraphrasing. RFC errata, RFC obsoletions, and section-number drift in IETF drafts all surface here.
- **Internal / authenticated URLs in public files.** A `https://internal.example.com/...` or a private-Confluence link in a Javadoc block ships to Maven Central along with the source — sometimes for years before a reader notices. If a URL needs auth to fetch, it doesn't belong in published source.

The rule applies symmetrically to URLs you delete: if you're removing the only citation of a spec the surrounding code depends on, leave a textual hint behind so the next reader knows what document to look at.

## Code style

Match the surrounding file: Allman braces (open brace on its own line for class / method / control structures), 4-space indentation, no tabs. Don't reformat untouched code while editing — diffs that include unrelated whitespace changes are noisy and slow review.

The brace convention is **machine-enforced** on every module's `src/main` by the Gradle `checkstyle` plugin against `config/checkstyle/checkstyle.xml`:

- `LeftCurly option="nl"` — every opening `{` on its own new line. This uses checkstyle's default token set, so it covers not just classes / methods / control structures (`if` / `for` / `while` / `try` / `switch` / …) but also **lambda bodies** — an inline `{` on a lambda trips it too. (Array initializers are *not* in the default set.)
- `RightCurly option="alone"` — every closing `}` alone on its own line.

It's scoped to `sourceSets = [project.sourceSets.main]` (test sources are not checked) at toolVersion 9.0. A violation reads like `[ERROR] …Foo.java:913:114: '{' at column 114 should be on a new line. [LeftCurly]`. Run `./gradlew checkstyleMain` (or `:<module>:checkstyleMain`) before pushing to catch these locally — CI fails the build on any violation. The legacy Ant builds (`ant/jdk18+.xml` etc.) run the same shared config and report with an `[ant:checkstyle]` prefix.
