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
        // switch (namedGroup)
        // {
        // case NamedGroup.kyber512:
        // case NamedGroup.secp256Kyber512:
        // case NamedGroup.x25519Kyber512:
        //     return NamedGroup.kyber512;
        // case NamedGroup.kyber768:
        // case NamedGroup.secp384Kyber768:
        // case NamedGroup.x25519Kyber768:
        // case NamedGroup.x448Kyber768:
        //     return NamedGroup.kyber768;
        // case NamedGroup.kyber1024:
        // case NamedGroup.secp521Kyber1024:
        //     return NamedGroup.kyber1024;
        // default:
        //     return namedGroup;
        // }
    }
}
