package org.bouncycastle.pqc.crypto.hqc;

import org.bouncycastle.crypto.digests.SHAKEDigest;

class Shake256RandomGenerator
{
    private final SHAKEDigest digest = new SHAKEDigest(256);

    public Shake256RandomGenerator(byte[] seed, byte domain)
    {
        digest.update(seed, 0, seed.length);
        digest.update(domain);
    }

    public Shake256RandomGenerator(byte[] seed, int off, int len, byte domain)
    {
        digest.update(seed, off, len);
        digest.update(domain);
    }

    public void init(byte[] seed, int off, int len, byte domain)
    {
        digest.reset();
        digest.update(seed, off, len);
        digest.update(domain);
    }

    public void nextBytes(byte[] bytes)
    {
        digest.doOutput(bytes, 0, bytes.length);
    }

    public void nextBytes(byte[] output, int off, int len)
    {
        digest.doOutput(output, off, len);
    }

    public void xofGetBytes(byte[] output, int outLen)
    {
        final int remainder = outLen & 7;
        int tmpLen = outLen - remainder;
        digest.doOutput(output, 0, tmpLen);
        if (remainder != 0)
        {
            byte[] tmp = new byte[8];
            digest.doOutput(tmp, 0, 8);
            System.arraycopy(tmp, 0, output, tmpLen, remainder);
        }
    }
}
