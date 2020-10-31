package org.bouncycastle.crypto.digests;

import org.bouncycastle.util.Arrays;

/**
 * Customizable SHAKE function.
 */
public class CSHAKEDigest
    extends SHAKEDigest
{
    private static final byte[] padding = new byte[100];
    private final byte[] diff;

    /**
     * Base constructor.
     *
     * @param bitLength bit length of the underlying SHAKE function, 128 or 256.
     * @param N         the function name string, note this is reserved for use by NIST. Avoid using it if not required.
     * @param S         the customization string - available for local use.
     */
    public CSHAKEDigest(int bitLength, byte[] N, byte[] S)
    {
        super(bitLength);

        if ((N == null || N.length == 0) && (S == null || S.length == 0))
        {
            diff = null;
        }
        else
        {
            diff = Arrays.concatenate(XofUtils.leftEncode(rate / 8), encodeString(N), encodeString(S));
            diffPadAndAbsorb();
        }
    }

    // bytepad in SP 800-185
    private void diffPadAndAbsorb()
    {
        int blockSize = rate / 8;
        absorb(diff, 0, diff.length);

        int delta = diff.length % blockSize;

        // only add padding if needed
        if (delta != 0)
        {
            int required = blockSize - delta;

            while (required > padding.length)
            {
                absorb(padding, 0, padding.length);
                required -= padding.length;
            }

            absorb(padding, 0, required);
        }
    }

    private byte[] encodeString(byte[] str)
    {
        if (str == null || str.length == 0)
        {
            return XofUtils.leftEncode(0);
        }

        return Arrays.concatenate(XofUtils.leftEncode(str.length * 8L), str);
    }

    public String getAlgorithmName()
    {
        return "CSHAKE" + fixedOutputLength;
    }

    public int doOutput(byte[] out, int outOff, int outLen)
    {
        if (diff != null)
        {
            if (!squeezing)
            {
                absorbBits(0x00, 2);
            }

            squeeze(out, outOff, ((long)outLen) * 8);

            return outLen;
        }
        else
        {
            return super.doOutput(out, outOff, outLen);
        }
    }

    public void reset()
    {
        super.reset();

        if (diff != null)
        {
            diffPadAndAbsorb();
        }
    }
}
