package org.bouncycastle.crypto.modes.kgcm;

public class BasicKGCMMultiplier_128
    implements KGCMMultiplier
{
    private final long[] H = new long[KGCMUtil_128.SIZE];

    public void init(long[] H)
    {
        KGCMUtil_128.copy(H,  this.H);
    }

    public void multiplyH(long[] z)
    {
        KGCMUtil_128.multiply(z, H, z);
    }
}
