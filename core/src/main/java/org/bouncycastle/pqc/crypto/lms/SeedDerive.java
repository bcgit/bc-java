package org.bouncycastle.pqc.crypto.lms;

import org.bouncycastle.crypto.Digest;

public class SeedDerive
{
    private final byte[] I;
    private final byte[] masterSeed;
    private final Digest digest;
    private int q;
    private int j;
    private boolean incJ = false;


    public SeedDerive(byte[] I, byte[] masterSeed, Digest digest)
    {
        this.I = I;
        this.masterSeed = masterSeed;
        this.digest = digest;
    }

    public int getQ()
    {
        return q;
    }

    public void setQ(int q)
    {
        this.q = q;
    }

    public int getJ()
    {
        return j;
    }

    public void setJ(int j)
    {
        this.j = j;
    }

    public byte[] getI()
    {
        return I;
    }

    public byte[] getMasterSeed()
    {
        return masterSeed;
    }

    public byte[] deriveSeed()
    {
        return deriveSeed(new byte[digest.getDigestSize()]);
    }


    public byte[] deriveSeed(byte[] target)
    {
        if (target.length < digest.getDigestSize())
        {
            throw new IllegalArgumentException("target length is less than digest size.");
        }

        digest.update(I, 0, I.length);
        digest.update((byte)(q >>> 24));
        digest.update((byte)(q >>> 16));
        digest.update((byte)(q >>> 8));
        digest.update((byte)(q));

        digest.update((byte)(j >>> 8));
        digest.update((byte)(j));
        digest.update((byte)0xFF);
        digest.update(masterSeed, 0, masterSeed.length);

        digest.doFinal(target, 0); // Digest resets here.

        if (incJ)
        {
            j++;
        }

        return target;
    }

    public byte[] deriveSeed(byte[] target, boolean incJ) {
        return deriveSeed(target,incJ,0);
    }



    public byte[] deriveSeed(byte[] target, boolean incJ, int offset)
    {
        if (target.length < digest.getDigestSize())
        {
            throw new IllegalArgumentException("target length is less than digest size.");
        }

        digest.update(I, 0, I.length);
        digest.update((byte)(q >>> 24));
        digest.update((byte)(q >>> 16));
        digest.update((byte)(q >>> 8));
        digest.update((byte)(q));

        digest.update((byte)(j >>> 8));
        digest.update((byte)(j));
        digest.update((byte)0xFF);
        digest.update(masterSeed, 0, masterSeed.length);

        digest.doFinal(target, offset); // Digest resets here.

        if (incJ)
        {
            j++;
        }

        return target;
    }
}
