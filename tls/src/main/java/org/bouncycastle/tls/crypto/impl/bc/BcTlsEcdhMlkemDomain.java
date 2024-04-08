package org.bouncycastle.tls.crypto.impl.bc;

import org.bouncycastle.tls.NamedGroup;
import org.bouncycastle.tls.crypto.TlsAgreement;
import org.bouncycastle.tls.crypto.TlsECConfig;
import org.bouncycastle.tls.crypto.TlsKemConfig;
import org.bouncycastle.tls.crypto.TlsKemDomain;

public class BcTlsEcdhMlkemDomain implements TlsKemDomain
{
    protected final BcTlsCrypto crypto;
    protected final boolean isServer;
    private final BcTlsECDomain ecDomain;
    private final BcTlsMLKemDomain mlkemDomain;

    public BcTlsEcdhMlkemDomain(BcTlsCrypto crypto, TlsKemConfig kemConfig)
    {
        this.crypto = crypto;
        this.ecDomain = getBcTlsECDomain(crypto, kemConfig);
        this.mlkemDomain = new BcTlsMLKemDomain(crypto, kemConfig);
        this.isServer = kemConfig.isServer();
    }

    public BcTlsSecret adoptLocalSecret(byte[] secret)
    {
        return crypto.adoptLocalSecret(secret);
    }

    public TlsAgreement createKem()
    {
        return new BcTlsEcdhMlkem(this);
    }

    public boolean isServer()
    {
        return isServer;
    }

    public BcTlsECDomain getEcDomain()
    {
        return ecDomain;
    }

    public BcTlsMLKemDomain getMlkemDomain()
    {
        return mlkemDomain;
    }

    private BcTlsECDomain getBcTlsECDomain(BcTlsCrypto crypto, TlsKemConfig kemConfig)
    {
        switch (kemConfig.getNamedGroup())
        {
        case NamedGroup.OQS_secp256Mlkem512:
            return new BcTlsECDomain(crypto, new TlsECConfig(NamedGroup.secp256r1));
        case NamedGroup.OQS_secp384Mlkem768:
            return new BcTlsECDomain(crypto, new TlsECConfig(NamedGroup.secp384r1));
        case NamedGroup.OQS_secp521Mlkem1024:
            return new BcTlsECDomain(crypto, new TlsECConfig(NamedGroup.secp521r1));
        default:
            return null;
        }
    }
}
