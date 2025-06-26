package org.bouncycastle.pqc.crypto.cross;

import java.security.SecureRandom;

import org.bouncycastle.crypto.digests.SHAKEDigest;
import org.bouncycastle.util.Arrays;

public class CsprngSecureRandom
    extends SecureRandom
{
    byte[] seed;
    private SHAKEDigest digest;
    int count;
    int files;

    public CsprngSecureRandom(byte[] seed)
    {
        this.seed = Arrays.clone(seed);
        digest = new SHAKEDigest(128);//category == 1 ? 128 : 256
        digest.update(seed, 0, seed.length);
        digest.update(new byte[2], 0, 2);
        count = 0;
        files = 0;
    }

    public void init(int category, byte[] dsc)
    {
        if (count == 100)
        {
            digest = new SHAKEDigest(128);//category == 1 ? 128 : 256
            digest.update(seed, 0, seed.length);
            digest.update(new byte[2], 0, 2);
            count = 0;
        }
        count++;
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
