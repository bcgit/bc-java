package org.bouncycastle.crypto.generators;

import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.DerivationFunction;
import org.bouncycastle.crypto.DerivationParameters;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.Mac;
import org.bouncycastle.crypto.macs.KMAC;
import org.bouncycastle.crypto.params.KDFParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Pack;

/**
 * The one-step key derivation function of NIST SP 800-56C Rev. 2, Section 4.1, with any of its three
 * auxiliary functions: a hash (Option 1), HMAC keyed with the salt (Option 2), or KMAC keyed with the
 * salt and customised with "KDF" (Option 3).
 * <p>
 * For the hash and HMAC options the output is the concatenation of H(counter || Z || FixedInfo) for a
 * 32-bit big-endian counter starting at 1, truncated to the requested length; with the hash option this is
 * the Concatenation KDF of SP 800-56A ({@link org.bouncycastle.crypto.agreement.kdf.ConcatenationKDFGenerator}).
 * With the KMAC option the standard sets the KMAC output length to the requested length so that a single
 * call, with the counter at 1, produces the whole output. When no salt is given the default salt of the
 * standard is used: for HMAC an all-zero string the size of the hash block (which HMAC's key padding makes
 * equivalent to an empty key), for KMAC128 164 zero bytes and for KMAC256 132 zero bytes.
 * <p>
 * Initialise with a {@link KDFParameters} carrying the shared secret Z and the FixedInfo.
 */
public class OneStepKDFBytesGenerator
    implements DerivationFunction
{
    private static final int KMAC128_DEFAULT_SALT_LENGTH = 164;
    private static final int KMAC256_DEFAULT_SALT_LENGTH = 132;

    private final Digest digest;
    private final Mac mac;
    private final byte[] salt;
    private final int hLen;

    private byte[] z;
    private byte[] fixedInfo;

    /**
     * Option 1: a hash function as the auxiliary function.
     *
     * @param digest the hash function.
     */
    public OneStepKDFBytesGenerator(Digest digest)
    {
        this.digest = digest;
        this.mac = null;
        this.salt = null;
        this.hLen = digest.getDigestSize();
    }

    /**
     * Option 2 or 3: HMAC or KMAC as the auxiliary function, keyed with the salt. A KMAC must have been
     * constructed with the customization string "KDF" as the standard requires.
     *
     * @param mac  the HMAC or KMAC to use.
     * @param salt the salt, or null for the standard's default salt.
     */
    public OneStepKDFBytesGenerator(Mac mac, byte[] salt)
    {
        this.digest = null;
        this.mac = mac;
        this.hLen = mac.getMacSize();

        if (salt == null || salt.length == 0)
        {
            if (mac instanceof KMAC)
            {
                this.salt = new byte[mac.getMacSize() == 32 ? KMAC128_DEFAULT_SALT_LENGTH : KMAC256_DEFAULT_SALT_LENGTH];
            }
            else
            {
                this.salt = new byte[0];
            }
        }
        else
        {
            this.salt = Arrays.clone(salt);
        }
    }

    public void init(DerivationParameters param)
    {
        if (!(param instanceof KDFParameters))
        {
            throw new IllegalArgumentException("KDF parameters required for OneStepKDFBytesGenerator");
        }

        KDFParameters p = (KDFParameters)param;

        this.z = p.getSharedSecret();
        this.fixedInfo = p.getIV();

        if (this.z == null)
        {
            throw new IllegalArgumentException("shared secret Z required");
        }
        if (this.fixedInfo == null)
        {
            this.fixedInfo = new byte[0];
        }
    }

    public Digest getDigest()
    {
        return digest;
    }

    public int generateBytes(byte[] out, int outOff, int len)
        throws DataLengthException, IllegalArgumentException
    {
        if ((out.length - len) < outOff)
        {
            throw new DataLengthException("output buffer too small");
        }
        if (len <= 0)
        {
            throw new IllegalArgumentException("len must be positive");
        }
        if (z == null)
        {
            throw new IllegalStateException("generator not initialised");
        }

        byte[] counter = Pack.intToBigEndian(1);

        if (mac instanceof KMAC)
        {
            // Option 3: H_outputBits is L, so one invocation with the counter at 1 delivers the whole output
            mac.init(new KeyParameter(salt));
            mac.update(counter, 0, counter.length);
            mac.update(z, 0, z.length);
            mac.update(fixedInfo, 0, fixedInfo.length);
            ((KMAC)mac).doFinal(out, outOff, len);

            return len;
        }

        long reps = ((long)len + hLen - 1) / hLen;
        if (reps > 0xFFFFFFFFL)
        {
            throw new IllegalArgumentException("output length too large");
        }

        byte[] block = new byte[hLen];
        int outPos = outOff;
        int remaining = len;

        for (int i = 1; remaining > 0; i++)
        {
            Pack.intToBigEndian(i, counter, 0);

            if (digest != null)
            {
                digest.update(counter, 0, counter.length);
                digest.update(z, 0, z.length);
                digest.update(fixedInfo, 0, fixedInfo.length);
                digest.doFinal(block, 0);
            }
            else
            {
                mac.init(new KeyParameter(salt));
                mac.update(counter, 0, counter.length);
                mac.update(z, 0, z.length);
                mac.update(fixedInfo, 0, fixedInfo.length);
                mac.doFinal(block, 0);
            }

            int toCopy = Math.min(hLen, remaining);
            System.arraycopy(block, 0, out, outPos, toCopy);
            outPos += toCopy;
            remaining -= toCopy;
        }

        Arrays.clear(block);

        return len;
    }
}
