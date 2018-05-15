package org.bouncycastle.crypto.modes.kgcm;

public class BasicKGCMMultiplier_256
    implements KGCMMultiplier
{
    private final long[] H = new long[KGCMUtil_256.SIZE];

    public void init(long[] H)
    {
        KGCMUtil_256.copy(H,  this.H);
    }

    public void multiplyH(long[] z)
    {
        KGCMUtil_256.multiply(z, H, z);
    }
}
