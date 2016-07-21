package org.bouncycastle.crypto.digests;

import org.bouncycastle.util.Memoable;

/**
 * implementation of GOST R 34.11-2012 256-bit
 */
public final class GOST3411_2012_256Digest extends GOST3411_2012Digest {
    private final static byte[] IV = {
            0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
            0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
            0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
            0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
            0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
            0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
            0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
            0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01
    };

    public GOST3411_2012_256Digest() {
        super(IV);
    }

    public GOST3411_2012_256Digest(GOST3411_2012_256Digest other) {
        super(IV);
        reset(other);
    }

    @Override
    public String getAlgorithmName() {
        return "GOST3411-2012-265";
    }

    @Override
    public int getDigestSize() {
        return 32;
    }

    @Override
    public int doFinal(byte[] out, int outOff) {
        byte[] result = new byte[64];
        super.doFinal(result, 0);

        System.arraycopy(result, 0, out, outOff, 32);

        return 32;
    }

    public Memoable copy() {
        return new GOST3411_2012_256Digest(this);
    }
}
