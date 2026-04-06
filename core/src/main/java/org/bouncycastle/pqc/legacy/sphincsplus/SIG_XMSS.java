package org.bouncycastle.pqc.legacy.sphincsplus;

class SIG_XMSS
{
    final byte[] sig;
    final byte[][] auth;

    public SIG_XMSS(byte[] sig, byte[][] auth)
    {
        this.sig = sig;
        this.auth = auth;
    }

    public byte[] getWOTSSig()
    {
        return sig;
    }

    public byte[][] getXMSSAUTH()
    {
        return auth;
    }
}
