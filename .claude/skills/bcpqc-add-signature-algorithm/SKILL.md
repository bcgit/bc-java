---
name: bcpqc-add-signature-algorithm
description: Port a post-quantum signature algorithm into the BCPQC provider, end to end — lightweight engine plus JCA/JCE wiring, OID converter plumbing, BC↔BCPQC bridge, module-info, tests, and release notes. Use this skill whenever the user wants to add a new PQC signature scheme (FAEST, SNOVA, MAYO, HAWK, etc.) to BCPQC, port a reference C/Rust implementation into BC, or finish a half-wired PQC algorithm whose certs/keys can't be decoded through the standard BC provider. Reach for this skill even when the user only mentions the algorithm name and the verb is "add", "port", "wire up", or "integrate" — the file set and the BC-vs-BCPQC split that this skill captures are non-obvious and easy to half-finish.
---

# Adding a PQC signature algorithm to BCPQC

This skill walks through the cross-file plumbing required to introduce a new post-quantum signature algorithm into the Bouncy Castle PQC provider. The file set is large (~15 files for a 12-parameter-set algorithm), several of the connections are non-obvious from reading any single file, and one critical step — wiring the algorithm into the *plain* `BC` provider as well as `BCPQC` — is easy to miss and silently breaks `CertificateFactory` / `KeyFactory` users.

The walk-through below uses **SNOVA as the canonical reference template**. The 2025 FAEST port followed it verbatim and that's the working pattern; reach for SNOVA's files first whenever something here is ambiguous.

## When to invoke

- "Add `<algorithm>` to BCPQC" / "port `<algorithm>` into BC" / "wire `<algorithm>` up as a signature provider"
- A lightweight `org.bouncycastle.pqc.crypto.<alg>` package exists but `Signature.getInstance("<alg>", "BCPQC")` doesn't resolve
- A new PQC algorithm round-trips via BCPQC but `CertificateFactory.getInstance("X.509", "BC").generateCertificate(...)` can't decode a certificate whose `SubjectPublicKeyInfo` carries the new OID — this is the BC↔BCPQC bridge gap (see "Pitfall 1" below)
- A reference C / Rust implementation has been ported into `core/src/main/java/org/bouncycastle/pqc/crypto/<alg>/` and needs the JCA/JCE shell built around it

## Prerequisites — what should already exist

Before this skill kicks in, the lightweight side of the algorithm must already be in place:

- OIDs in `core/src/main/java/org/bouncycastle/asn1/bc/BCObjectIdentifiers.java` (one per parameter set), typically grouped under a parent arc like `BCObjectIdentifiers.faest = bc_sig.branch("12")`
- A parameter-set class `<Alg>Parameters` with public static constants for every parameter set, exposing `getName()` returning the canonical (typically lower-case) name
- `<Alg>PublicKeyParameters` and `<Alg>PrivateKeyParameters` extending `AsymmetricKeyParameter` with `getEncoded()` and `getParameters()`
- `<Alg>KeyPairGenerator` implementing `AsymmetricCipherKeyPairGenerator`
- `<Alg>KeyGenerationParameters` extending `KeyGenerationParameters`, wrapping a `SecureRandom` + `<Alg>Parameters`
- `<Alg>Signer` implementing `MessageSigner` (or `Signer` for streaming) with `init(boolean, CipherParameters)`, `generateSignature(byte[])`, `verifySignature(byte[], byte[])`

If any of these are missing, that's a separate task (porting the reference implementation). This skill picks up *after* that's done.

## The two-provider split — read this first

Bouncy Castle ships two JCE providers:

- **`BC`** (`BouncyCastleProvider` in `prov/src/main/java/org/bouncycastle/jce/provider/`) — the standard provider, registered as `"BC"`. The vast majority of caller code uses only this one.
- **`BCPQC`** (`BouncyCastlePQCProvider` in `prov/src/main/java/org/bouncycastle/pqc/jcajce/provider/`) — the post-quantum provider, registered as `"BCPQC"`.

The two have **independent service tables**. Adding `KeyPairGenerator.Faest` to BCPQC makes `KeyPairGenerator.getInstance("Faest", "BCPQC")` work, but it does NOT make `BC` recognise FAEST. In particular:

- `CertificateFactory.getInstance("X.509", "BC").generateCertificate(...)` parses the embedded `SubjectPublicKeyInfo` through `BC`'s converter map only. If FAEST isn't there, the public key in the cert comes back as `null` or as an opaque blob.
- The same applies to PKCS#8 parsing, S/MIME signed-message verification, CMS, and any other high-level facade routed through `BC`.

The fix is `BouncyCastleProvider.loadPQCKeys()`. It's called from `BouncyCastleProvider`'s constructor and registers an `AsymmetricKeyInfoConverter` (the BCPQC-side `<Alg>KeyFactorySpi`) against every PQC OID via `addKeyInfoConverter(OID, new <Alg>KeyFactorySpi())`. **Forgetting to add the new algorithm's OIDs to `loadPQCKeys()` is the single most common way to half-wire a PQC port.** The unit test that catches this is described in "Step 11" below.

## Step-by-step checklist

The numbered order is roughly the layering order: lightweight plumbing → BCPQC keys/SPIs → BCPQC registration → BC bridge → module-info → tests → release notes. You can work in parallel across files but every step should be present in the final patch.

### Step 1 — `core/.../pqc/crypto/util/Utils.java`

Add the OID↔Parameters maps and lookup helpers. Pattern (one block per algorithm):

```java
// Field declarations
static final Map faestOids = new HashMap<ASN1ObjectIdentifier, FaestParameters>();
static final Map faestParams = new HashMap<FaestParameters, ASN1ObjectIdentifier>();

// In the static initializer block
faestOids.put(FaestParameters.faest_128s, BCObjectIdentifiers.faest_128s);
// ... one per parameter set ...
faestParams.put(BCObjectIdentifiers.faest_128s, FaestParameters.faest_128s);
// ... one per parameter set ...

// Lookup helpers at end of class
static ASN1ObjectIdentifier faestOidLookup(FaestParameters params)
{
    return (ASN1ObjectIdentifier)faestOids.get(params);
}

static FaestParameters faestParamsLookup(ASN1ObjectIdentifier oid)
{
    return (FaestParameters)faestParams.get(oid);
}
```

### Step 2 — `core/.../pqc/crypto/util/PublicKeyFactory.java`

Add a `<Alg>Converter` inner class and one `converters.put(...)` per OID:

```java
// In the static initializer block
converters.put(BCObjectIdentifiers.faest_128s, new FaestConverter());
// ... one per parameter set ...

// Inner class
private static class FaestConverter
    extends SubjectPublicKeyInfoConverter
{
    AsymmetricKeyParameter getPublicKeyParameters(SubjectPublicKeyInfo keyInfo, Object defaultParams)
        throws IOException
    {
        byte[] keyEnc = ASN1OctetString.getInstance(keyInfo.parsePublicKey()).getOctets();
        FaestParameters faestParams = Utils.faestParamsLookup(keyInfo.getAlgorithm().getAlgorithm());
        return new FaestPublicKeyParameters(faestParams, keyEnc);
    }
}
```

### Step 3 — `core/.../pqc/crypto/util/PrivateKeyFactory.java`

Add an `else if (algOID.on(BCObjectIdentifiers.<alg>))` branch using the parent OID of the algorithm's parameter-set arc (one branch covers all parameter sets):

```java
else if (algOID.on(BCObjectIdentifiers.faest))
{
    byte[] keyEnc = ASN1OctetString.getInstance(keyInfo.parsePrivateKey()).getOctets();
    FaestParameters faestParams = Utils.faestParamsLookup(algOID);
    return new FaestPrivateKeyParameters(faestParams, keyEnc);
}
```

### Step 4 — `core/.../pqc/crypto/util/SubjectPublicKeyInfoFactory.java` and `PrivateKeyInfoFactory.java`

Add `instanceof <Alg>PublicKeyParameters` / `<Alg>PrivateKeyParameters` branches that take the lightweight key parameters object and wrap it as an X.509 / PKCS#8 info:

```java
// SubjectPublicKeyInfoFactory.java
else if (publicKey instanceof FaestPublicKeyParameters)
{
    FaestPublicKeyParameters params = (FaestPublicKeyParameters)publicKey;
    byte[] encoding = params.getEncoded();
    AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(Utils.faestOidLookup(params.getParameters()));
    return new SubjectPublicKeyInfo(algorithmIdentifier, new DEROctetString(encoding));
}

// PrivateKeyInfoFactory.java — mirror with PrivateKeyInfo + attributes
```

### Step 5 — `prov/.../pqc/jcajce/spec/<Alg>ParameterSpec.java`

`AlgorithmParameterSpec` with public static constants for every parameter set + `fromName(String)`. Treat case-insensitively (the existing SNOVA spec does this via `Strings.toLowerCase`).

### Step 6 — `prov/.../pqc/jcajce/interfaces/<Alg>Key.java`

Tiny marker interface — `extends Key` and adds `getParameterSpec()`:

```java
public interface FaestKey
    extends Key
{
    FaestParameterSpec getParameterSpec();
}
```

### Step 7 — `prov/.../pqc/jcajce/provider/<alg>/BC<Alg>PublicKey.java` and `BC<Alg>PrivateKey.java`

Standard BC key wrapper pattern. Copy `BCSnovaPublicKey` / `BCSnovaPrivateKey` and rename.

**Critical:** the private key's `equals()` must use `Arrays.constantTimeAreEqual(...)`, not `Arrays.areEqual(...)`. The public key uses plain `Arrays.areEqual`. This protects against timing side-channels when private keys are kept in maps or used in equality checks against attacker-influenced values.

Both classes implement serialization via `readObject` / `writeObject` writing the encoded form.

### Step 8 — `prov/.../pqc/jcajce/provider/<alg>/<Alg>KeyFactorySpi.java`

Extends `BaseKeyFactorySpi`. Includes a static `keyOids` `HashSet<ASN1ObjectIdentifier>` initialized with all parameter-set OIDs, the standard `engineGetKeySpec` / `engineTranslateKey` / `generatePrivate` / `generatePublic` overrides, **and one public static inner class per parameter set** calling `super(BCObjectIdentifiers.<paramset_oid>)`. The inner classes are referenced by name from the Mappings class.

### Step 9 — `prov/.../pqc/jcajce/provider/<alg>/<Alg>KeyPairGeneratorSpi.java`

Extends `java.security.KeyPairGenerator`. Contains:

- A static `parameters` `HashMap<String, <Alg>Parameters>` registering each parameter set by both its raw name and its `ParameterSpec.getName()` form (both lower-cased) so lookup works regardless of casing.
- `initialize(int, SecureRandom)` throws "use AlgorithmParameterSpec".
- `initialize(AlgorithmParameterSpec, SecureRandom)` extracts a name, looks up the parameter set, creates `<Alg>KeyGenerationParameters`, inits the engine.
- `generateKeyPair()` runs the engine, wraps in BC key classes, returns a `KeyPair`.
- **One public static inner class per parameter set** calling `super(<Alg>Parameters.<paramset>)`.

### Step 10 — `prov/.../pqc/jcajce/provider/<alg>/SignatureSpi.java`

Extends `java.security.Signature`. Contains a `ByteArrayOutputStream bOut` for message accumulation, the standard `engineInitSign` / `engineInitVerify` / `engineUpdate` / `engineSign` / `engineVerify` overrides, a `Base` inner class with no parameter binding (used when the caller selects via `"Faest"` and the actual parameter set comes from the key), and **one public static inner class per parameter set** that hard-pins the parameter check.

In `engineInitVerify` / `engineInitSign`, when the SPI was constructed with a specific parameter set, verify the key's algorithm matches the SPI's parameter set with an exact-message error — `"signature configured for " + canonicalAlg`. Tests in other algorithms assert on that exact string, so the message format is part of the contract; copy it verbatim from SNOVA's `SignatureSpi`.

### Step 11 — `prov/.../pqc/jcajce/provider/<Alg>.java` (the Mappings class)

The `<Alg>$Mappings` class (extends `AsymmetricAlgorithmProvider`) is what BCPQC loads via reflection. It calls:

- `provider.addAlgorithm("KeyFactory.<Alg>", PREFIX + "<Alg>KeyFactorySpi");`
- `addKeyFactoryAlgorithm(...)` once per parameter set, registering the per-parameter inner classes against their OIDs
- `provider.addAlgorithm("KeyPairGenerator.<Alg>", PREFIX + "<Alg>KeyPairGeneratorSpi");`
- `addKeyPairGeneratorAlgorithm(...)` once per parameter set
- `addSignatureAlgorithm(provider, "<Alg>", PREFIX + "SignatureSpi$Base", BCObjectIdentifiers.<alg>);`
- `addSignatureAlgorithm(...)` once per parameter set

Use SNOVA's `Snova.java` as the template — it's the largest and most exemplary.

### Step 12 — `prov/.../pqc/jcajce/provider/BouncyCastlePQCProvider.java`

Append the algorithm short-name to the `ALGORITHMS` array. The provider's `setup()` method then loads `<Alg>$Mappings` reflectively.

```java
private static final String[] ALGORITHMS =
    {
        ...
        "Mayo", "Snova",
        "NTRUPlus", "Faest"           // <-- add here
    };
```

### Step 13 — THE BC↔BCPQC BRIDGE — `prov/.../jce/provider/BouncyCastleProvider.loadPQCKeys()`

**This is the easy-to-miss step.** Add the new import and `addKeyInfoConverter(<oid>, new <Alg>KeyFactorySpi())` lines — one per parameter set — typically at the end of `loadPQCKeys()`:

```java
import org.bouncycastle.pqc.jcajce.provider.faest.FaestKeyFactorySpi;
...
addKeyInfoConverter(BCObjectIdentifiers.faest_128s, new FaestKeyFactorySpi());
addKeyInfoConverter(BCObjectIdentifiers.faest_128f, new FaestKeyFactorySpi());
// ... one per parameter set ...
```

Without this, `BouncyCastleProvider.getPublicKey(SubjectPublicKeyInfo)` returns `null` for the new OIDs and every `BC` provider consumer (X.509 CertificateFactory, PKCS#8 KeyFactory, S/MIME, CMS, …) silently fails to parse the new keys. With it, `BC` decodes them via the BCPQC-side `<Alg>KeyFactorySpi` instance.

### Step 14 — `prov/src/main/jdk1.9/module-info.java` (JPMS)

Add three things:

```
opens org.bouncycastle.pqc.jcajce.provider.<alg> to java.base;
exports org.bouncycastle.pqc.crypto.<alg>;
exports org.bouncycastle.pqc.jcajce.provider.<alg>;
```

`org.bouncycastle.pqc.jcajce.spec` and `org.bouncycastle.pqc.jcajce.interfaces` are already exported in aggregate; no per-algorithm entry needed there.

Also mirror the `pqc.crypto.<alg>` export in `prov/src/main/ext-jdk1.9/module-info.java` (the legacy ant-build descriptor). Do NOT add the `provider.<alg>` line there — the legacy distribution intentionally omits the jcajce-side provider package exports for SNOVA / Mayo / NTRUPlus, and the new algorithm should follow that precedent.

### Step 15 — Tests

Add `prov/src/test/java/org/bouncycastle/pqc/jcajce/provider/test/<Alg>Test.java` (extends `junit.framework.TestCase`) covering:

1. **`testPrivateKeyRecovery`** — generate a keypair, encode/decode the private key via the BCPQC `KeyFactory`, assert equality, serialize/deserialize.
2. **`testPublicKeyRecovery`** — same for the public key.
3. **`testRestrictedKeyPairGen`** — for each parameter set, `KeyPairGenerator.getInstance(spec.getName(), "BCPQC")` should produce keys whose `getAlgorithm()` matches.
4. **`test<Alg>Sign`** — for each parameter set, sign + verify with `Signature.getInstance(spec.getName(), "BCPQC")`. Confirm that initVerify-with-wrong-key throws `InvalidKeyException("signature configured for ...")`.
5. **`test<Alg>RandomSig`** — sign+verify with the non-parameter-bound `Signature.getInstance("<Alg>", "BCPQC")` form.
6. **`testBcProviderKeyInfoConverter`** — **the bridge regression test.** For every parameter set, generate a keypair via BCPQC, then call `BouncyCastleProvider.getPublicKey(SubjectPublicKeyInfo.getInstance(pubEnc))` and `BouncyCastleProvider.getPrivateKey(...)` and assert each returned key is a `<Alg>Key` with the right `getParameterSpec().getName()` and `.equals()` the original. If this test passes but tests 1-5 also pass, the algorithm is end-to-end wired. If 1-5 pass but `testBcProviderKeyInfoConverter` fails, step 13 was forgotten.

Add `suite.addTestSuite(<Alg>Test.class);` to `prov/src/test/java/org/bouncycastle/pqc/jcajce/provider/test/AllTests.java`.

### Step 16 — Release notes

Add a single `<li>` to `docs/releasenotes.html` under the current unreleased version's "Additional Features and Functionality" block. Mention: the algorithm name and spec version, the parameter sets supported, that `BouncyCastlePQCProvider` exposes `KeyPairGenerator.<Alg>` / `Signature.<Alg>` / `KeyFactory.<Alg>` plus per-parameter-set aliases, and that `BouncyCastleProvider.loadPQCKeys()` registers the OIDs so the standard `BC` provider can decode certificates and PKCS#8 keys.

## Verification commands

After all 16 steps are done:

```bash
# Compile both providers and the test sources
./gradlew :core:compileJava :prov:compileJava :prov:compileTestJava

# Run the new test directly (faster than going through :prov:test which only runs AllTests*)
CP="prov/build/classes/java/main:prov/build/classes/java/test:core/build/classes/java/main:core/build/classes/java/test:util/build/classes/java/main:prov/build/resources/main:core/build/resources/main:$(find ~/.gradle -name 'junit-*.jar' | head -1):$(find ~/.gradle -name 'hamcrest-core-1*.jar' | head -1)"
java -cp "$CP" junit.textui.TestRunner org.bouncycastle.pqc.jcajce.provider.test.<Alg>Test

# Run the full BCPQC provider test aggregate
java -cp "$CP" junit.textui.TestRunner org.bouncycastle.pqc.jcajce.provider.test.AllTests

# Final regression sweep
./gradlew :prov:build
```

## Pitfalls

**1. The BC↔BCPQC bridge (step 13).** This bears repeating because it's the bug that catches every BCPQC port. Symptom: `Signature.getInstance("<Alg>", "BCPQC")` works fine; `CertificateFactory.getInstance("X.509", "BC").generateCertificate(certWithAlgKey)` returns a cert whose `getPublicKey()` is null. Cause: forgot the `loadPQCKeys()` entries. Test: `testBcProviderKeyInfoConverter` (step 15).

**2. Stale `prov/build/classes` shadowing a `core/` edit.** The `core` sources are copied into `prov`'s `srcDirs` via the `core`-into-`prov` trap (see CLAUDE.md "Module graph"), so a `core/.../pqc/crypto/util/Utils.java` change is compiled into BOTH `core/build/classes` and `prov/build/classes`. If one is stale, the JVM may load the old class from `prov` and the new lookup in `Utils.faestParamsLookup` returns null. When in doubt: `./gradlew :prov:compileJava --rerun-tasks`.

**3. `<Alg>ParameterSpec.fromName` case folding.** SNOVA's `fromName` lower-cases the input before lookup but the keys are registered in UPPER case in some places — this is a pre-existing oddity in `SnovaParameterSpec.java`. If you copy SNOVA verbatim, make sure your parameter-set names match the casing of the keys you `put()` into the `parameters` HashMap. FAEST's parameter names are already lower-case (`faest_128s` etc.) so this falls out for free; SNOVA-like upper-case names need the casing reconciled.

**4. Per-parameter-set inner class explosion.** With 12 parameter sets there are typically 12 inner classes in each of three SPIs (KeyFactory, KeyPairGenerator, Signature) and 12 entries in three or more registration tables (Utils, PublicKeyFactory, the Mappings class, loadPQCKeys). When adding or removing a parameter set partway through, grep for the OID name to make sure no site was missed.

**5. Module-info — modular consumers only.** The compile-time error that catches a missing `exports` line in `module-info.java` only fires when a downstream module-path consumer tries to use the new package. A class-path-only test run won't surface the omission. Manually verify the descriptor edits even when the build passes.

**6. CLAUDE.md's "Adding a PQC algorithm" section** is the shorter sibling of this skill — it lists the same file checklist in prose form for the case where Claude isn't loading this skill but is reading CLAUDE.md. Keep both in sync if you change the workflow.

## Reference template files

When in doubt, mimic these files for the corresponding step:

| Step | Reference file (SNOVA) |
|------|------------------------|
| 1 | `core/.../pqc/crypto/util/Utils.java` lines around `snovaOids` |
| 2 | `core/.../pqc/crypto/util/PublicKeyFactory.java` `SnovaConverter` inner class |
| 3 | `core/.../pqc/crypto/util/PrivateKeyFactory.java` `algOID.on(BCObjectIdentifiers.snova)` branch |
| 4 | `core/.../pqc/crypto/util/SubjectPublicKeyInfoFactory.java` / `PrivateKeyInfoFactory.java` `instanceof Snova*Parameters` branches |
| 5 | `prov/.../pqc/jcajce/spec/SnovaParameterSpec.java` |
| 6 | `prov/.../pqc/jcajce/interfaces/SnovaKey.java` |
| 7 | `prov/.../pqc/jcajce/provider/snova/BCSnovaPublicKey.java` and `BCSnovaPrivateKey.java` |
| 8 | `prov/.../pqc/jcajce/provider/snova/SnovaKeyFactorySpi.java` |
| 9 | `prov/.../pqc/jcajce/provider/snova/SnovaKeyPairGeneratorSpi.java` |
| 10 | `prov/.../pqc/jcajce/provider/snova/SignatureSpi.java` |
| 11 | `prov/.../pqc/jcajce/provider/Snova.java` |
| 12 | `prov/.../pqc/jcajce/provider/BouncyCastlePQCProvider.java` ALGORITHMS array |
| 13 | `prov/.../jce/provider/BouncyCastleProvider.java` `loadPQCKeys()` snova section |
| 14 | `prov/src/main/jdk1.9/module-info.java` snova entries |
| 15 | `prov/src/test/java/org/bouncycastle/pqc/jcajce/provider/test/SnovaTest.java` (mostly — but add a `testBcProviderKeyInfoConverter`; SNOVA's existing test doesn't cover that path, but FAEST's does) |
| 16 | `docs/releasenotes.html` — look at the FAEST entry under 1.85 for the prose template |

The FAEST entries (added in 1.85 alongside the introduction of this skill) are the most recent worked example of the full pipeline and are a useful cross-check.
