package org.bouncycastle.tls.crypto.impl.jcajce;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.SecretWithEncapsulation;
import org.bouncycastle.pqc.crypto.crystals.kyber.KyberKEMExtractor;
import org.bouncycastle.pqc.crypto.crystals.kyber.KyberKEMGenerator;
import org.bouncycastle.pqc.crypto.crystals.kyber.KyberKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.crystals.kyber.KyberKeyPairGenerator;
import org.bouncycastle.pqc.crypto.crystals.kyber.KyberParameters;
import org.bouncycastle.pqc.crypto.crystals.kyber.KyberPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.crystals.kyber.KyberPublicKeyParameters;
import org.bouncycastle.tls.NamedGroup;
import org.bouncycastle.tls.crypto.TlsAgreement;
import org.bouncycastle.tls.crypto.TlsECConfig;
import org.bouncycastle.tls.crypto.TlsKemConfig;
import org.bouncycastle.tls.crypto.TlsKemDomain;

public class JceTlsEcdhMlkemDomain implements TlsKemDomain
{
    protected final JcaTlsCrypto crypto;
    protected final boolean isServer;
    private final JceTlsECDomain ecDomain;
    private final JceTlsMLKemDomain mlkemDomain;

    public JceTlsEcdhMlkemDomain(JcaTlsCrypto crypto, TlsKemConfig kemConfig)
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
        return new JceTlsEcdhMlkem(this);
    }

    public boolean isServer()
    {
        return isServer;
    }

    public JceTlsECDomain getEcDomain()
    {
        return ecDomain;
    }

    public JceTlsMLKemDomain getMlkemDomain()
    {
        return mlkemDomain;
    }

    private JceTlsECDomain getJceTlsECDomain(JcaTlsCrypto crypto, TlsKemConfig kemConfig)
    {
        switch (kemConfig.getNamedGroup())
        {
        case NamedGroup.OQS_secp256Mlkem512:
            return new JceTlsECDomain(crypto, new TlsECConfig(NamedGroup.secp256r1));
        case NamedGroup.OQS_secp384Mlkem768:
            return new JceTlsECDomain(crypto, new TlsECConfig(NamedGroup.secp384r1));
        case NamedGroup.OQS_secp521Mlkem1024:
            return new JceTlsECDomain(crypto, new TlsECConfig(NamedGroup.secp521r1));
        default:
            return null;
        }
    }
}
