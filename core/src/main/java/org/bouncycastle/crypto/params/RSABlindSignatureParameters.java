package org.bouncycastle.crypto.params;

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA384Digest;

/**
 * Variant parameters for the RSA Blind Signature Scheme with Appendix (RSABSSA)
 * defined in RFC 9474. Each variant fixes a content digest, an EMSA-PSS salt
 * length, and whether the message-preparation step is identity or randomised
 * (32-byte prefix per RFC 9474 sec. 4.1). The four named variants from RFC 9474
 * sec. 5 are exposed as constants; SHA-384 with MGF1(SHA-384) is the only hash
 * profile named by the RFC.
 * <p>
 * The randomised variants are RECOMMENDED by RFC 9474 sec. 5; the deterministic
 * variants are useful for interop with callers that must derive the prepared
 * message from {@code msg} alone.
 */
public final class RSABlindSignatureParameters
{
    /**
     * Length in bytes of the random prefix prepended to {@code msg} by
     * {@code PrepareRandomize} (RFC 9474 sec. 4.1).
     */
    public static final int RANDOMIZED_PREFIX_LEN = 32;

    /**
     * RSABSSA-SHA384-PSS-Randomized — SHA-384, 48-byte salt, 32-byte random
     * prefix. RECOMMENDED by RFC 9474 sec. 5.
     */
    public static final RSABlindSignatureParameters RSABSSA_SHA384_PSS_RANDOMIZED =
        new RSABlindSignatureParameters("RSABSSA-SHA384-PSS-Randomized", 48, true);

    /**
     * RSABSSA-SHA384-PSSZERO-Randomized — SHA-384, empty salt, 32-byte random
     * prefix. RECOMMENDED by RFC 9474 sec. 5; the empty salt makes the signature
     * deterministic given a fixed prepared message, while the prefix preserves
     * blindness.
     */
    public static final RSABlindSignatureParameters RSABSSA_SHA384_PSSZERO_RANDOMIZED =
        new RSABlindSignatureParameters("RSABSSA-SHA384-PSSZERO-Randomized", 0, true);

    /**
     * RSABSSA-SHA384-PSS-Deterministic — SHA-384, 48-byte salt, identity
     * preparation. Use only when the caller has another source of message
     * unlinkability; see RFC 9474 sec. 7.3.
     */
    public static final RSABlindSignatureParameters RSABSSA_SHA384_PSS_DETERMINISTIC =
        new RSABlindSignatureParameters("RSABSSA-SHA384-PSS-Deterministic", 48, false);

    /**
     * RSABSSA-SHA384-PSSZERO-Deterministic — SHA-384, empty salt, identity
     * preparation. RFC 9474 sec. 5 warns this combination yields fully
     * deterministic signatures; use only when the caller actively wants that.
     */
    public static final RSABlindSignatureParameters RSABSSA_SHA384_PSSZERO_DETERMINISTIC =
        new RSABlindSignatureParameters("RSABSSA-SHA384-PSSZERO-Deterministic", 0, false);

    private final String name;
    private final int saltLength;
    private final boolean randomized;

    private RSABlindSignatureParameters(String name, int saltLength, boolean randomized)
    {
        this.name = name;
        this.saltLength = saltLength;
        this.randomized = randomized;
    }

    /**
     * Return the RFC 9474 sec. 5 variant name (e.g. {@code RSABSSA-SHA384-PSS-Randomized}).
     */
    public String getName()
    {
        return name;
    }

    /**
     * Return the EMSA-PSS salt length, in bytes.
     */
    public int getSaltLength()
    {
        return saltLength;
    }

    /**
     * Return true if the {@code Prepare} step prepends a fresh 32-byte random
     * prefix (RFC 9474 sec. 4.1 — PrepareRandomize); false if {@code Prepare}
     * is the identity (RFC 9474 sec. 4.1 — PrepareIdentity).
     */
    public boolean isRandomized()
    {
        return randomized;
    }

    /**
     * Return a fresh {@link Digest} instance for the variant's content hash
     * (SHA-384 for every variant defined in RFC 9474 sec. 5).
     */
    public Digest createDigest()
    {
        return new SHA384Digest();
    }
}
