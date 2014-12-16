package org.bouncycastle.crypto.modes.gcm;

public class BasicGCMMultiplier implements GCMMultiplier
{
    private int[] H;

    public void init(byte[] H)
    {
        this.H = GCMUtil.asInts(H);
    }

    public void multiplyH(byte[] x)
    {
        int[] t = GCMUtil.asInts(x);
        GCMUtil.multiply(t, H);
        GCMUtil.asBytes(t, x);
    }
}
