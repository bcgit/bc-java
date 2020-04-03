package org.bouncycastle.crypto.digests;

import org.bouncycastle.crypto.Xof;


/**
 * implementation of SHAKE based on following KeccakNISTInterface.c from http://keccak.noekeon.org/
 * <p>
 * Following the naming conventions used in the C source code to enable easy review of the implementation.
 */
public class SHAKEDigest
    extends KeccakDigest
    implements Xof
{
    private static int checkBitLength(int bitLength)
    {
        switch (bitLength)
        {
        case 128:
        case 256:
            return bitLength;
        default:
            throw new IllegalArgumentException("'bitLength' " + bitLength + " not supported for SHAKE");
        }
    }

    public SHAKEDigest()
    {
        this(128);
    }

    public SHAKEDigest(int bitLength)
    {
        super(checkBitLength(bitLength));
    }

    public SHAKEDigest(SHAKEDigest source) {
        super(source);
    }

    public String getAlgorithmName()
    {
        return "SHAKE" + fixedOutputLength;
    }

    public int doFinal(byte[] out, int outOff)
    {
        return doFinal(out, outOff, getDigestSize());
    }

    public int doFinal(byte[] out, int outOff, int outLen)
    {
        int length = doOutput(out, outOff, outLen);

        reset();

        return length;
    }

    public int doOutput(byte[] out, int outOff, int outLen)
    {
        if (!squeezing)
        {
            absorbBits(0x0F, 4);
        }

        squeeze(out, outOff, ((long)outLen) * 8);

        return outLen;
    }

    /*
     * TODO Possible API change to support partial-byte suffixes.
     */
    protected int doFinal(byte[] out, int outOff, byte partialByte, int partialBits)
    {
        return doFinal(out, outOff, getDigestSize(), partialByte, partialBits);
    }

    /*
     * TODO Possible API change to support partial-byte suffixes.
     */
    protected int doFinal(byte[] out, int outOff, int outLen, byte partialByte, int partialBits)
    {
        if (partialBits < 0 || partialBits > 7)
        {
            throw new IllegalArgumentException("'partialBits' must be in the range [0,7]");
        }

        int finalInput = (partialByte & ((1 << partialBits) - 1)) | (0x0F << partialBits);
        int finalBits = partialBits + 4;

        if (finalBits >= 8)
        {
            absorb((byte)finalInput);
            finalBits -= 8;
            finalInput >>>= 8;
        }

        if (finalBits > 0)
        {
            absorbBits(finalInput, finalBits);
        }

        squeeze(out, outOff, ((long)outLen) * 8);

        reset();

        return outLen;
    }
}
