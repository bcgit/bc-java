package org.bouncycastle.pqc.crypto.crystals.kyber;

import org.bouncycastle.crypto.digests.SHAKEDigest;

class Symmetric
{
    public static SHAKEDigest KyberXOF(byte[] seed, int a, int b)
    {
        SHAKEDigest xof = new SHAKEDigest(128);
        byte[] buf = new byte[seed.length + 2];
        System.arraycopy(seed, 0, buf, 0, seed.length);
        buf[seed.length] = (byte)a;
        buf[seed.length + 1] = (byte)b;

        xof.update(buf, 0, seed.length + 2);


        return xof;
    }

    public final static int SHAKE128_rate = 168;

    public static SHAKEDigest KyberPRF(byte[] seed, byte nonce)
    {
        SHAKEDigest prf = new SHAKEDigest(256);

        byte[] extSeed = new byte[seed.length + 1];
        System.arraycopy(seed, 0, extSeed, 0, seed.length);
        extSeed[seed.length] = nonce;
        prf.update(extSeed, 0, extSeed.length);
        return prf;
    }
}
