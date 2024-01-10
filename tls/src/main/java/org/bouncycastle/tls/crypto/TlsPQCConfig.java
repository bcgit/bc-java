package org.bouncycastle.tls.crypto;

import org.bouncycastle.tls.NamedGroup;

public class TlsPQCConfig
{
    protected final int namedGroup;
    protected final TlsPQCKemMode mode;
    protected final int pqcNamedGroup;

    public TlsPQCConfig(int namedGroup)
    {
        this(namedGroup, TlsPQCKemMode.PQC_KEM_SERVER);
    }

    public TlsPQCConfig(int namedGroup, TlsPQCKemMode mode)
    {
        this.namedGroup = namedGroup;
        this.mode = mode;
        this.pqcNamedGroup = getPQCNamedGroup(namedGroup);
    }
    
    public int getNamedGroup()
    {
        return namedGroup;
    }
    
    public TlsPQCKemMode getTlsPQCKemMode()
    {
        return mode;
    }

    public int getPQCNamedGroup()
    {
        return pqcNamedGroup;
    }
    
    private int getPQCNamedGroup(int namedGroup)
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
