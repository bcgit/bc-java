package org.bouncycastle.tls.crypto.impl.bc;

import org.bouncycastle.tls.NamedGroup;
import org.bouncycastle.tls.crypto.TlsAgreement;
import org.bouncycastle.tls.crypto.TlsECConfig;
import org.bouncycastle.tls.crypto.TlsKemConfig;
import org.bouncycastle.tls.crypto.TlsKemDomain;

public class BcTlsECDHMLKemDomain implements TlsKemDomain
{
    protected final BcTlsCrypto crypto;
    protected final boolean isServer;
    private final BcTlsECDomain ecDomain;
    private final BcTlsMLKemDomain mlkemDomain;

    public BcTlsECDHMLKemDomain(BcTlsCrypto crypto, TlsKemConfig kemConfig)
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
        return new BcTlsECDHMLKem(this);
    }

    public boolean isServer()
    {
        return isServer;
    }

    public BcTlsECDomain getECDomain()
    {
        return ecDomain;
    }

    public BcTlsMLKemDomain getMLKemDomain()
    {
        return mlkemDomain;
    }

    private BcTlsECDomain getBcTlsECDomain(BcTlsCrypto crypto, TlsKemConfig kemConfig)
    {
        switch (kemConfig.getNamedGroup())
        {
        case NamedGroup.SecP256r1MLKEM768:
            return new BcTlsECDomain(crypto, new TlsECConfig(NamedGroup.secp256r1));
        case NamedGroup.SecP384r1MLKEM1024:
            return new BcTlsECDomain(crypto, new TlsECConfig(NamedGroup.secp384r1));
        default:
            return null;
        }
    }
}
