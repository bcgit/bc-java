package org.bouncycastle.pqc.crypto.hqc;

import org.bouncycastle.crypto.CryptoServicePurpose;
import org.bouncycastle.crypto.digests.SHAKEDigest;

/**
 * The XOF of the HQC specification (2026-10-12, Section 3.1): XOF.Init(seed) absorbs the seed into
 * SHAKE256 and XOF.GetBytes squeezes. Earlier specifications appended a fixed domain byte (0x01) to
 * every seed; the current one does not, and the only domain separation left on the XOF is the
 * parameter set's k appended to seedKEM when the KEM key is expanded, see
 * {@link HQCEngine#expandSecretKey}.
 */
class Shake256RandomGenerator
{
    private final SHAKEDigest digest = new SHAKEDigest(256, CryptoServicePurpose.INTERNAL);

    /**
     * XOF.Init(seed).
     */
    Shake256RandomGenerator(byte[] seed, int off, int len)
    {
        digest.update(seed, off, len);
    }

    /**
     * XOF.Init(seed || domain), the KEM seed expansion's parameter-set binding.
     */
    Shake256RandomGenerator(byte[] seed, int off, int len, byte domain)
    {
        digest.update(seed, off, len);
        digest.update(domain);
    }

    /**
     * Re-initialise as XOF.Init(seed), discarding any state.
     */
    void init(byte[] seed, int off, int len)
    {
        digest.reset();
        digest.update(seed, off, len);
    }

    void nextBytes(byte[] bytes)
    {
        digest.doOutput(bytes, 0, bytes.length);
    }

    void nextBytes(byte[] output, int off, int len)
    {
        digest.doOutput(output, off, len);
    }

    /**
     * XOF.GetBytes: a plain squeeze of exactly {@code outLen} bytes. The earlier reference code
     * squeezed in 8-byte units and discarded the tail of the last unit; the 2026-10-12 reference
     * code squeezes exactly what it uses, so a short read no longer skips bytes of the stream.
     */
    void xofGetBytes(byte[] output, int outLen)
    {
        digest.doOutput(output, 0, outLen);
    }
}
