package org.bouncycastle.tls.crypto;

public class TlsKEMConfig
{
    protected final int namedGroup;
    protected final TlsCryptoParameters cryptoParams;
    protected final int kemNamedGroup;

    public TlsKEMConfig(int namedGroup, TlsCryptoParameters cryptoParams)
    {
        this.namedGroup = namedGroup;
        this.cryptoParams = cryptoParams;
        this.kemNamedGroup = getKEMNamedGroup(namedGroup);
    }
    
    public int getNamedGroup()
    {
        return namedGroup;
    }
    
    public boolean isServer()
    {
        return cryptoParams.isServer();
    }

    public int getKEMNamedGroup()
    {
        return kemNamedGroup;
    }
    
    private int getKEMNamedGroup(int namedGroup)
    {
        return namedGroup;
    }
}
