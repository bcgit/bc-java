package org.bouncycastle.crypto.modes.gcm;

public class BasicGCMMultiplier
    implements GCMMultiplier
{
    private long[] H;

    public void init(byte[] H)
    {
        this.H = GCMUtil.asLongs(H);
    }

    public void multiplyH(byte[] x)
    {
        GCMUtil.multiply(x, H);
    }
}
