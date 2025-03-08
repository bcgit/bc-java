package org.bouncycastle.tls.crypto.impl.jcajce;

import org.bouncycastle.tls.NamedGroup;
import org.bouncycastle.tls.crypto.TlsAgreement;
import org.bouncycastle.tls.crypto.TlsECConfig;
import org.bouncycastle.tls.crypto.TlsKemConfig;
import org.bouncycastle.tls.crypto.TlsKemDomain;

public class JceTlsECDHMLKemDomain implements TlsKemDomain
{
    protected final JcaTlsCrypto crypto;
    protected final boolean isServer;
    private final JceTlsECDomain ecDomain;
    private final JceTlsMLKemDomain mlkemDomain;

    public JceTlsECDHMLKemDomain(JcaTlsCrypto crypto, TlsKemConfig kemConfig)
    {
        this.crypto = crypto;
        this.ecDomain = getJceTlsECDomain(crypto, kemConfig);
        this.mlkemDomain = new JceTlsMLKemDomain(crypto, kemConfig);
        this.isServer = kemConfig.isServer();
    }

    public JceTlsSecret adoptLocalSecret(byte[] secret)
    {
        return crypto.adoptLocalSecret(secret);
    }

    public TlsAgreement createKem()
    {
        return new JceTlsECDHMLKem(this);
    }

    public boolean isServer()
    {
        return isServer;
    }

    public JceTlsECDomain getECDomain()
    {
        return ecDomain;
    }

    public JceTlsMLKemDomain getMLKemDomain()
    {
        return mlkemDomain;
    }

    private JceTlsECDomain getJceTlsECDomain(JcaTlsCrypto crypto, TlsKemConfig kemConfig)
    {
        switch (kemConfig.getNamedGroup())
        {
        case NamedGroup.SecP256r1MLKEM768:
            return new JceTlsECDomain(crypto, new TlsECConfig(NamedGroup.secp256r1));
        case NamedGroup.SecP384r1MLKEM1024:
            return new JceTlsECDomain(crypto, new TlsECConfig(NamedGroup.secp384r1));
        default:
            return null;
        }
    }
}
