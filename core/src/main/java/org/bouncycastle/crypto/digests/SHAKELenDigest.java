package org.bouncycastle.crypto.digests;

import org.bouncycastle.crypto.ExtendedDigest;

/**
 * SHAKE implementation with explicit digest bit length.
 */
public class SHAKELenDigest
    implements ExtendedDigest
{
    private SHAKEDigest shake;

    private int digestSize;

    private final String algorithmName;

    public SHAKELenDigest(int bitLength, int digestBitLength)
    {
        shake = new SHAKEDigest(bitLength);
        if (digestBitLength % 8 != 0)
        {
            throw new IllegalArgumentException("invalid digestBitLength");
        }

        this.digestSize = digestBitLength / 8;
        algorithmName = "SHAKE" + bitLength + "-" + digestBitLength;
    }

    public String getAlgorithmName()
    {
        return algorithmName;
    }

    public int getDigestSize()
    {
        return digestSize;
    }

    public int doFinal(byte[] out, int outOff)
    {
        return shake.doFinal(out, outOff, getDigestSize());
    }

    @Override
    public void update(byte in) {
        shake.update(in);
    }

    @Override
    public void update(byte[] in, int inOff, int len) {
        shake.update(in, inOff, len);
    }

    @Override
    public void reset() {
        shake.reset();
    }

    @Override
    public int getByteLength() {
        return shake.getByteLength();
    }

}
