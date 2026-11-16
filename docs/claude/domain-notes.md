# Domain notes (read on demand)

These notes are **not** loaded into every session. Read the relevant section before changing code in
its area; the trigger for each is given below. General conventions are in `conventions.md`.

- [X.509 ASN.1 changes: check the RFC first](#x509-asn1-changes--check-the-rfc-first) — before changing anything in `core/.../asn1/x509` (or `asn1/pkcs`, `asn1/cms`, `asn1/cmp`, `asn1/ocsp`).
- [Certificate parse stays strict](#certificate-parse-stays-strict--diagnostics-go-through-a-separate-reviewer) — before adding or changing a check in `Certificate` / `TBSCertificate` / `Extensions`, or touching `X509CertificateReviewer`.
- [ASN.1 DER strictness: lenient read, strict write](#asn1-der-strictness-lenient-read-strict-write) — before changing primitive decode/encode, the time types, or `DEROutputStream`.
- [Comparing `AlgorithmIdentifier`s on the receive side](#comparing-algorithmidentifiers-on-the-receive-side-use-areequivalent-not-equals) — whenever code checks a peer named the expected algorithm.
- [`DefaultAlgorithmNameFinder` and its test](#adding-an-entry-to-defaultalgorithmnamefinder-means-editing-its-test-too) — before adding a name-finder entry.
- [`Signature.verify()` reports; it never throws unchecked](#signatureverify-reports-it-never-throws-unchecked) — before touching any `SignatureSpi` verify path.
- [`Signature.setParameter()` either side of init](#signaturesetparameter-takes-the-context-on-either-side-of-init) — before touching an SPI's `engineSetParameter`.
- [Stateful hash-based private keys](#stateful-hash-based-private-keys-the-position-is-stored-twice-so-cross-check-it) — before changing LMS/HSS or XMSS/XMSS^MT private-key encoding, parsing or state.
- [A compatibility retry must not report its own exception](#a-compatibility-retry-must-not-report-its-own-exception) — whenever a decoder catches and tries a second interpretation.
- [Key agreement tests with and without a UKM](#key-agreement-tests-run-with-and-without-a-ukm) — before writing or changing a CMS/JCA key agreement test or KDF.
- [pg operator tests: three defaults](#pg-operator-tests-three-defaults-that-silently-pick-a-different-path) — before writing OpenPGP encryption / key-protection tests.
- [OpenPGP new vs legacy packet format](#openpgp-new-vs-legacy-packet-format) — before changing a `bcpg` packet constructor or `BCPGOutputStream` format handling.
- [PKCS#12 SPI pair](#pkcs12-spi-pair) — before changing either PKCS#12 keystore SPI.
- [CMS streaming I/O: caller owns the outer stream](#cms-streaming-io-caller-owns-the-outer-stream) — before changing close/drain behaviour or javadoc of `CMS*Parser` / `CMS*StreamGenerator`.
- [CMS recipients extend `AbstractRecipient`](#every-cms-recipient-extends-abstractrecipient-and-checks-before-it-unwraps) — before adding or changing a CMS recipient, or `CMSUtils.getAEADMacLength`.
- [Operator OutputStream close discipline](#operator-outputstream-close-discipline) — when feeding a `ContentSigner` / `ContentVerifier`.
- [Two locations for the same OID-table class](#two-locations-for-the-same-oid-table-class) — when importing an `*ObjectIdentifiers` class from `core` / `prov`.

## X.509 ASN.1 changes — check the RFC first

Everything under `core/src/main/java/org/bouncycastle/asn1/x509/` is a wire-format type from a PKI RFC. Before changing parsing rules, structural constraints, defaults or error messages, check the proposed behaviour against the RFC:

- Extensions and certificate / CRL containers: **RFC 5280** (extensions §4.2.x, cert fields §4.1.x, CRL fields §5.1.x).
- Attribute certificates (`AttributeCertificateInfo`, `Holder`, `AttCertIssuer`, `V2Form`, `IssuerSerial`, …): **RFC 5755** (previously RFC 3281).
- OCSP types (`OCSPResponse`, `BasicOCSPResponse`, `ResponseData`, …): **RFC 6960**.
- Validation policy / qualified-cert types: RFC 3739 / RFC 3279 / X9.62 as appropriate.

An unenforced RFC "MUST" / "MUST NOT" is the actionable spec — cite the section in the commit message and, where helpful, javadoc. Where the RFC is silent, stay compatible with what OpenSSL, Java's `CertificateFactory` and GnuTLS accept rather than tightening unilaterally. The same applies to `asn1/pkcs`, `asn1/cms`, `asn1/cmp`, `asn1/ocsp` (RFC 7292 / 5652 / 4210 / 6960 etc.).

For X.509 / WebPKI work, the **CAB Forum** Baseline Requirements (<https://cabforum.org/>) narrow RFC 5280 (key sizes, signature algorithms, extension presence/criticality, name encodings). Where a BR narrows the RFC and the change makes sense for general BC users (not just public CAs), follow the BR; cite the BR section alongside the RFC and say in the PR that the change is deliberately stricter than the RFC.

## Certificate parse stays strict — diagnostics go through a separate reviewer

`org.bouncycastle.asn1.x509.Certificate` / `TBSCertificate` / `Extensions` **fail fast**: throw on the first problem, never return a partial object. Don't make them permissive to "report more" (github #1508 / PR #1511 proposed that and was rejected). Reporting goes through `org.bouncycastle.cert.X509CertificateReviewer` (pkix; JCA-free, top-level `cert`): `reviewStructure(byte[])` / `reviewStructure(ASN1Sequence)` return a `Review` — a list of `Finding`s plus the recovered `X509CertificateHolder` only when the strict path would also accept it. It is the parse-side analogue of `PKIXCertPathReviewer`.

`TBSCertificate` and `Extensions` single-source their checks via a null-sink: the work is in `private void parse(ASN1Sequence seq, List errors)`, and each check calls `reportProblem(errors, msg)`:

- `errors == null` (strict `getInstance`) — throws `new IllegalArgumentException(msg)`, so nothing after a call site runs and strict behaviour and messages are unchanged; the "continue with a default" branches are reachable only when collecting.
- `errors != null` (public `reviewStructure(ASN1Sequence)`) — adds the exception and parsing continues.

So a new structural check in `parse` must go through `reportProblem` — a bare `throw` is invisible to the reviewer, and duplicating the check in the reviewer drifts. `reviewStructure` returns the *exceptions* the strict path would throw, in parse order. `Extensions.reviewStructure`'s list is grouped under one `org.bouncycastle.util.AggregateRuntimeException` by `TBSCertificate`; `X509CertificateReviewer` expands it into per-extension `Finding`s at location `tbsCertificate.extensions`. Exercise both paths with stash-the-fix plus the cert batteries (`core` `asn1.test.AllTests`, pkix `cert.test.AllTests`, prov `CertTest`).

## ASN.1 DER strictness: lenient read, strict write

Primitives with several legal encodings (`UTCTime` / `GeneralizedTime`: with/without seconds, `Z` or `+hhmm`, with/without fraction) accept all legal variants on read; `createPrimitive(byte[])` does not enforce *DER*. Where DER conformance matters, enforce it on **write**: in `toDERObject()`, throw `DEREncodingException` (`org.bouncycastle.asn1`, extends `IllegalStateException`) if the contents would produce non-DER bytes, gated behind a `Properties.*` flag read as `Properties.isOverrideSet(name, true)` — default `"true"` (allow), so strictness is opt-in by setting it to `"false"`.

Lenient read covers legal-but-non-DER *formatting*, not malformed *content*. `ASN1UTCTime` / `ASN1GeneralizedTime` route `createPrimitive` through `org.bouncycastle.asn1.ASN1TimeFormat.isValidUTCTime` / `isValidGeneralizedTime` unconditionally (no property), throwing `IllegalArgumentException("invalid UTCTime format" / "invalid GeneralizedTime format")` for non-digits, out-of-range fields (month 01-12, day 01-31, hour 00-23, minute/second 00-59), bad lengths and bad terminators; the legal lenient forms still pass. The message deliberately omits the offending bytes. Validation happens before construction; the `String`/`Date` constructors and `toDERObject` (which uses the `byte[]` constructor) bypass `createPrimitive` and are unchanged. This turned the github #2040 case (2-digit year tagged `GeneralizedTime`) into a read rejection.

`DEROutputStream`'s `writeElements`, `writePrimitive` and `writePrimitives` catch `DEREncodingException` and rethrow via `Exceptions.ioException(msg, cause)`, so `getEncoded(ASN1Encoding.DER)` throws `IOException` with the `DEREncodingException` as cause. BER is unaffected. In-memory construction should produce DER anyway; the gate matters for wire-sourced content re-emitted as DER.

Worked example: `Properties.ASN1_ALLOW_NON_DER_TIME` (github #1973 / #1986 / #2040). Reuse the same shape — `toDERObject` gate + `DEREncodingException` + default-allow `Properties.*` flag — for any future DER-strictness opt-in.

## Comparing `AlgorithmIdentifier`s on the receive side: use `areEquivalent`, not `equals`

`AlgorithmIdentifier.equals()` compares encodings, so absent parameters and explicit `NULL` differ. [RFC 5754 sec. 2](https://www.rfc-editor.org/rfc/rfc5754#section-2) requires receivers to accept both for SHA-2 (and generators to omit them, which BC does). When checking that a peer named the expected algorithm, use `AlgorithmIdentifier.areEquivalent(a, b)` (core, `asn1.x509`): same OID, parameters equal or each absent-or-`NULL`. It equates absent only with `NULL`, so RSASSA-PSS and parameterised GOST stay strict. `asn1.ocsp.CertID` implements the same rule inline in `equals`/`hashCode` (predates the helper).

Keep `equals()` where it is not receiver-side identity:

- map/cache keys, where `equals` must match `hashCode` (`ERSCachingData`);
- deciding whether a DER `DEFAULT` may be omitted on encode — changing it changes bytes (`RSAESOAEPparams`, `RSASSAPSSparams`);
- a gate admitting exactly one algorithm (`RespID` requires SHA-1).

Worked example: RFC 4998 evidence records (github #2379) — a TSA's SHA-256 with `NULL` was rejected as "time stamp imprint for wrong algorithm".

## Adding an entry to `DefaultAlgorithmNameFinder` means editing its test too

`pkix/src/test/java/org/bouncycastle/operator/test/AllTests.java` asserts `values.length == nameFinder.getOIDSet().size()`, so every `addAlgorithm(...)` needs a matching `new Object[]{oid, "NAME"}` row or `testAgainstKnownList` fails with `expected:<N> but was:<N-k>` — deliberately. The test also resolves each name through BC as `MessageDigest` / `Cipher` / `Signature`; failure only prints "Could not resolve" (the `fail` is commented out), but it usually means the mapping is wrong.

## `Signature.verify()` reports; it never throws unchecked

A provider `SignatureSpi` has three answers at the JCA boundary:

- **Well-formed but does not verify** — return `false`.
- **Will not decode** (empty, truncated, trailing data, garbage) — also `false`.
- **Decodes, but names a different algorithm / parameter set / OTS type than the key** — throw `SignatureException` (via `SecurityExceptions.signatureException`).

The lightweight `org.bouncycastle.crypto.*` signers and their parse helpers throw unchecked on malformed input by design; translating is the SPI's job. The malformed-signature battery for github #2408 is: empty / 3 bytes / zeroed / signature+1 / signature-1. ML-DSA, SLH-DSA, Falcon, XMSS, XMSS^MT, Ed25519 and RSA return `false`; ECDSA throws `SignatureException` on DER decode failure (JCA-documented, fine); LMS leaked `IllegalStateException("cannot parse signature")` and was fixed. Run the battery against any signer you touch.

- **Scope the catch to the decode call.** Past the parse, BC verifiers already return `false` for inconsistent signatures (see `LMSEngine.verifySignature`'s "fail gracefully" branch); a whole-body `catch (RuntimeException)` adds nothing now and would silently turn future internal errors into `false`.
- **Reset the accumulated message in a `finally`**, so any exit leaves the state `engineInitVerify` left. `slhdsa/SignatureSpi` is the model (`try { … } finally { bOut.reset(); }`), `lms/LMSSignatureSpi` follows it.

Related, for fixed-size encodings: length-check the whole signature on parse (see `architecture.md`, "Two JCA-boundary details").

## `Signature.setParameter()` takes the context on either side of init

`engineSetParameter` is declared `throws InvalidAlgorithmParameterException` and must not leak unchecked exceptions; the usual cause is re-initialising the signer with a key that doesn't exist yet. Base shape (github #2396, `BaseDeterministicOrRandomSignature.setContext`): record the context, clear `engineParams`, re-initialise **only** `if (keyParams != null)`. The composite ML-DSA SPI had its own `engineSetParameter` and repeated the defect across 37 services (github #2412) — any SPI with its own `engineSetParameter` needs checking against this shape.

- **Clear the cached `AlgorithmParameters`.** `engineGetParameters()` caches lazily; test `set` / `get` / `set` / `get` — asking only after the second set can't see a stale cache.
- **Don't mutate and then throw in the same branch.** Use `if (context != null) { setContext(…); } else { throw …; }` so a caller seeing the exception knows nothing was applied (the composite `SpecUtil.getContextFrom` branch applied it and then threw "unknown parameterSpec…").
- **Record anything else the spec sets before the algorithm is known.** For the generic `COMPOSITE` service the algorithm comes with the key, so the pre-hash choice from `CompositeSignatureSpec` is held in a field and applied at init with the context.

Measurement: loop every registered service in the family, `getInstance(name)` then `setParameter(new ContextParameterSpec(…))` with no init, counting unchecked throws.

## Stateful hash-based private keys: the position is stored twice, so cross-check it

LMS/HSS and XMSS/XMSS^MT private keys record their position in **two** places (github #2414):

- HSS: top-level `index`, and each component key's one-time index `q`.
- XMSS^MT: global `index`, and the per-layer BDS traversal states.
- XMSS: `index` and the BDS state's own index (already checked).

Look for this shape — two records of one value never compared — elsewhere too: the key also stores the tree `root` twice (own field and BDS root node), uncompared. A key whose index rolled back while state stayed advanced signs twice under a one-time key **and the signature verifies** (RFC 8554 sec. 1, RFC 8391 sec. 1.1). Bit rot, partial writes and backup restores get there without an attacker, so "an attacker with the key has the seed anyway" is no reason to skip the check.

**Derive invariants by enumeration, not by reading the code.** A wrong check rejects legitimate keys, which is worse than the bug. Walk a small key across its whole index space and print both records at each step:

- HSS is exact: `index == sum over levels i<d-1 of (q_i - 1) * 2^(heights below i) + q_last`.
- XMSS^MT needs one allowance: when a layer's expected leaf index is 0, its state may still hold the previous subtree's final index (`2^h - 1`), because `updateState` skips the advance on a subtree's last leaf. Absent (lazily built) layers are skipped.

Every such test needs a **compatibility half**, which matters more than the rejection half: walk every reachable index, encode/decode at each, and assert the decoded key still signs verifiably (912 XMSS^MT indices across five parameter sets and 2124 HSS indices, plus a shard, backed the allowances above).

### What "validated" means differs by scheme — say which you have

- **LMS**: every cached node's children are cached, so interior nodes can be **recomputed** (31 hashes, ~20us, independent of `h`) — a semantic check.
- **XMSS**: BDS auth-path / stack / retain / keep nodes lack their children, so recomputing means rebuilding subtrees. The state carries a **checksum** instead (SHA-256 over the owning key's `publicSeed` then the state) — error detection only; anyone who can rewrite the key recomputes it, so the encoding's allocation bounds still carry the DoS load.

Bind the *public* seed: root and index are already in the encoding, hashing secret material would make the checksum a commitment to it for no gain, and `secretKeyPRF` doesn't affect the state.

- **Verify-first changes which error a crafted encoding hits.** It is right (rejects before allocation), but a test asserting e.g. `"BDS authentication path size out of bounds"` must recompute the checksum after patching.
- **`docs/formats/{lms,xmss}-private-key.md` document the encodings byte by byte with hex examples from fixed seeds.** A format change means regenerating them: reproduce the example, confirm a known value (the root) still matches, then update the hex and every byte count.

## A compatibility retry must not report its own exception

`HSSPrivateKeyParameters.getInstance(byte[])` retries a failed parse as a pre-HSS single LMS key and used to report the retry's failure, so every new HSS field check surfaced as `"expected version 0 lms private key"` through the byte-array (JCA) entry point. Keep the original exception and throw it if the retry also fails. Whenever a decoder catches and tries a second interpretation, check which exception escapes.

## Key agreement tests run with and without a UKM

Test every CMS or JCA key agreement scheme **both with and without a user keying material value** where the scheme admits one — they are different derivations (a UKM typically feeds the KDF info and, for HKDF schemes, the salt).

RFC 8418 sec. 2.2 (github #2454):

```
if ukm is provided, then salt = ukm, else salt is not provided
PRK = HKDF-Extract(salt, K)
KEK = HKDF-Expand(PRK, DER(ECC-CMS-SharedInfo), SizeInOctets(KEK))
```

BC put the UKM in `entityUInfo` but not the HKDF salt, and 1.86 shipped it because `testRFC8418X25519AndX448` never set a UKM.

A self round trip can't see this class of defect — BC agrees with itself either way. Where the spec states the derivation, derive the key independently in the test, unwrap/verify with it, and assert the *wrong* derivation fails (`NewEnvelopedDataTest.checkRFC8418Kek` is the model). The 1-Pass ECMQV KDF input was likewise wrong from 1.53 to 1.86 (raw addedukm instead of DER ECC-CMS-SharedInfo), hidden by BC-to-BC tests and a legacy retry.

Key agreement vectors are therefore **shared across implementations** in `bc-test-data`: `pkix/cms/ecdh-ukm` and `pkix/cms/mqv-ukm` (each `.pem` opens with a plain-text header naming scheme, ukm and its RFC 5753 placement; `recipient_p256.pem` is the PKCS#8 recipient key). bc-java's `NewEnvelopedDataTest` and bc-csharp's `EnvelopedDataTest` decrypt every file and re-derive the KEK independently. A new scheme or KDF form gets a sample there, generated by a known-conformant library, and a consumer in both. `pkix/cms/mqv-legacy-kdf` holds BC's pre-fix raw-addedukm messages for testing the compatibility retry (`Properties.CMS_ALLOW_LEGACY_KEYAGREE_KDF`) — labelled non-conformant, never vectors.

## pg operator tests: three defaults that silently pick a different path

Each surfaced as a confusing failure one layer from the cause (found writing `PGPRFC9980KeyPairTest`).

- **`BcPGPDataEncryptorBuilder` / `JcePGPDataEncryptorBuilder.setWithAEAD(...)` selects the LibrePGP v5-style OCB packet**, not RFC 9580 v2 SEIPD. Add `.setUseV6AEAD()` for a v6 PKESK + v2 SEIPD; without it `PublicKeyKeyEncryptionMethodGenerator.generate` emits a v3 PKESK even for a v6 key.
- **AEAD secret-key protection binds the key packet, tag included, as associated data.** `PGPSecretKey(privKey, pubKey, ...)` makes an encryption-only key a subkey packet regardless of `isMasterKey`, so an encryptor built from the primary-form `pubKey.getPublicKeyPacket()` fails with "mac check in OCB failed". Convert with `keyPair.asSubkey(fingerprintCalculator)` first and build the encryptor from that packet.
- **`PreferredAEADCiphersuites.builder(...)` always appends the mandatory AES-128/OCB**, so a certificate built through it never has an unusable AEAD list; a negotiation test needing one must use the v1 SEIPD path (Features with MDC only, symmetric preferences set directly).

`pg` has its own `TestResourceFinder` (since 1.87) under `pg/src/test/java/org/bouncycastle/test/`, reading `bc-test-data/openpgp/openpgp-pqc/rfc9980` for the RFC 9980 Appendix A vectors.

## OpenPGP new vs legacy packet format

Each `org.bouncycastle.bcpg` packet carries a `newPacketFormat` flag (`Packet(tag, newPacketFormat)` → `hasNewPacketFormat()`). `BCPGOutputStream`'s `PacketFormat`: `LEGACY` forces old, `CURRENT` forces new, `ROUNDTRIP` (default) honours each packet's flag.

- **Parse preserves the wire format; generation picks a default.** `BCPGInputStream` builds each packet with the on-wire format (`newPacket = (hdr & 0x40) != 0`) — never hardcode a format in a parse constructor. A freshly generated packet's default comes from its public constructor's `super(TAG, …)`. RFC 9580 sec. 4.2: Legacy "SHOULD NOT be used to generate new data". The established split (`SignaturePacket`, and `OnePassSignaturePacket` for v6): **v6 constructor → `super(TAG, true)`, v3/v4 → `super(TAG)` (Legacy)**; mirror it per version rather than flipping a shared default (github #2347).
- **The high-level API already forces new format**: `OpenPGPMessageOutputStream` writes through `new BCPGOutputStream(out, PacketFormat.CURRENT)`. Per-packet defaults matter on the lower-level path (`PGPSignatureGenerator` etc. through a default `ROUNDTRIP` stream), which is where Legacy-header v6 interop bugs appear.

## PKCS#12 SPI pair

`PKCS12KeyStoreSpi` (legacy MAC) and `PKCS12PBMAC1KeyStoreSpi` (RFC 9579 PBMAC1) share the bag pipeline. Changes to entry-type acceptance, `engineLoad` bag dispatch, `engineStore` cert/key passes, or `getUsedCertificateSet` / `cryptData` usually need mirroring in the other. Shared static helpers (OID lookup, key-size table, content/iteration-count helpers) go in package-private `org.bouncycastle.jcajce.provider.keystore.pkcs12.PKCS12Util`.

BC deliberately does not follow the JDK's per-entry password model: it decrypts every bag at load with the store password and ignores the `getKey` password, so JDK stores with a null store password or differing entry passwords can't be loaded. Accepted limitation, not a bug. (Interop fixtures: `bc-test-data` `pkix/pkcs12/jdk-secret-keys/`, see "Non-standard format interop" in `conventions.md`.)

## CMS streaming I/O: caller owns the outer stream

The `pkix/src/main/java/org/bouncycastle/cms/CMS*{Parser,StreamGenerator}.java` classes deliberately do **not** cascade close to caller-supplied streams (unlike `GZIPOutputStream` / `CipherOutputStream`); changing this was rejected (github #1572).

- Stream generators finalise the structure (signer infos, MAC, end-of-contents) on `close()` of the returned stream but don't close the target — a buffering encoder that flushes on close (e.g. Commons `Base64OutputStream`) must be closed by the caller.
- Parsers read only enough to expose metadata; content drains lazily through `getContentStream()` / `getSignedContent()`, and the `InputStream` is closed only by `parser.close()` (from `CMSContentInfoParser`).

When editing CMS class javadoc, trace the behaviour rather than paraphrase: `CMSAuthEnvelopedDataParser`'s doc wrongly claimed full drain-and-close and in-memory buffering until github #2133. The `<b>Stream handling note:</b>` blocks added under that issue are the template.

## Every CMS recipient extends `AbstractRecipient` and checks before it unwraps

Every recipient in `org.bouncycastle.cms` (Jce and Bc; key transport, key agreement, KEK, password, KEM, KTS) extends `org.bouncycastle.cms.AbstractRecipient` and, at the **top** of `extractSecretKey` before unwrapping, enforces `isContentAlgorithmAllowed(algOid)` (false → `CMSAlgorithmNotAllowedException`) and `checkTagSize(algId)` (throws `CMSTagLengthException`) — both on the not-yet-authenticated content-encryption `AlgorithmIdentifier`. A new recipient must follow this shape and expose fluent `setAllowedContentAlgorithms` / `setMinimumTagSize` with javadoc mirrored from `JceKeyTransRecipient`. `JceKTSKeyTransRecipient` slipped through (fixed `915e7f3ffb`) — nothing fails, the caller's hardening just doesn't apply.

Invariant: `CMSUtils.getAEADMacLength` returns `-1` only for non-AEAD ("check doesn't apply") and `0` for AEAD with absent/unusable parameters (fail-closed, the `catch (RuntimeException) { return 0; }` branch). A negative value there would let `checkTagSize` skip the floor. Model tests: `testKeyTransAllowedContentAlgorithms` (pkix `NewEnvelopedDataTest`) and `testKeyTransMinimumTagSize` (pkix `AuthEnvelopedDataTest`); KTS has no AuthEnveloped variant, so its tag test drives GCM through `EnvelopedData`.

## Operator OutputStream close discipline

Always `close()` the stream from `ContentSigner.getOutputStream()` / `ContentVerifier.getOutputStream()` before `getSignature()` / `verify(...)`; many implementations finalise in `close()`. Pattern (`X509v3CertificateBuilder.generateSig`; verifier side `X509CertificateHolder.isSignatureValid`):

```java
OutputStream sOut = signer.getOutputStream();
tbsObj.encodeTo(sOut, ASN1Encoding.DER);
sOut.close();
return signer.getSignature();
```

`signer.getOutputStream().write(bytes)` skips the close and is a latent bug.

## Two locations for the same OID-table class

Several less-common arc OID classes exist twice:

- `core/src/main/java/org/bouncycastle/internal/asn1/<arc>/<X>ObjectIdentifiers.java` — bundled into `core` (and `prov`).
- `util/src/main/java/org/bouncycastle/asn1/<arc>/<X>ObjectIdentifiers.java` — the public API copy.

Arcs include `kisa`, `nsri`, `ntt`, `oiw`, `gnu`, `eac`, `cms`, `bsi`, `cryptlib`, `edec`, `iso`, `isara`, `isismtt`, `microsoft`, `misc`, `rosstandart`, etc. From `core` / `prov` import the `internal.asn1.<arc>` form — `util` isn't on their classpath and the public import fails with a misleading "package does not exist". From `pkix` upward the public form is fine.

`iana` is *not* dual-located: `org.bouncycastle.asn1.iana.IANAObjectIdentifiers` lives only in `core` (public, exported by `prov`), consolidated in 1.85 (github #2176) — don't reintroduce an `internal.asn1.iana` copy.
