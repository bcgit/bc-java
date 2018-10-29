package org.bouncycastle.tls;

public class NamedGroupTypes
{
    private boolean dh;
    private boolean ecdh;
    private boolean ecdsa;

    public boolean hasDH()
    {
        return dh;
    }

    public boolean hasECDH()
    {
        return ecdh;
    }

    public boolean hasECDSA()
    {
        return ecdsa;
    }

    public void setDH(boolean dh)
    {
        this.dh = dh;
    }

    public void setECDH(boolean ecdh)
    {
        this.ecdh = ecdh;
    }

    public void setECDSA(boolean ecdsa)
    {
        this.ecdsa = ecdsa;
    }
}
