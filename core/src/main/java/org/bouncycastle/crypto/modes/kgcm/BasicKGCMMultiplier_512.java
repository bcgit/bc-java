package org.bouncycastle.crypto.modes.kgcm;

public class BasicKGCMMultiplier_512
    implements KGCMMultiplier
{
    private final long[] H = new long[KGCMUtil_512.SIZE];

    public void init(long[] H)
    {
        KGCMUtil_512.copy(H,  this.H);
    }

    public void multiplyH(long[] z)
    {
        KGCMUtil_512.multiply(z, H, z);
    }
}
