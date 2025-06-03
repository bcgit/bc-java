package org.bouncycastle.pqc.crypto.cross;

import java.security.SecureRandom;

import org.bouncycastle.crypto.digests.SHAKEDigest;
import org.bouncycastle.util.Arrays;

public class CsprngSecureRandom
    extends SecureRandom
{
    byte[] seed;
    private SHAKEDigest digest;

    public CsprngSecureRandom(byte[] seed)
    {
        this.seed = Arrays.clone(seed);
    }

    public void init(int category, byte[] dsc)
    {
        digest = new SHAKEDigest(category == 1 ? 128 : 256);
        digest.update(seed, 0, seed.length);
        digest.update(dsc, 0, 2);
    }

    public void setSeed(byte[] seed, byte[] dsc)
    {
        digest.update(seed, 0, seed.length);
        digest.update(dsc, 0, 2);
    }

    @Override
    public void nextBytes(byte[] x)
    {
        digest.doOutput(x, 0, x.length);
    }
}
