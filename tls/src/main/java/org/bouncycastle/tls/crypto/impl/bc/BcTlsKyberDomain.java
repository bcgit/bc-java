package org.bouncycastle.tls.crypto.impl.bc;

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
import org.bouncycastle.tls.crypto.TlsPQCConfig;
import org.bouncycastle.tls.crypto.TlsPQCDomain;
import org.bouncycastle.tls.crypto.TlsSecret;

public class BcTlsKyberDomain implements TlsPQCDomain
{
    public static KyberParameters getKyberParameters(TlsPQCConfig pqcConfig)
    {
        switch (pqcConfig.getPQCNamedGroup())
        {
        case NamedGroup.kyber512:
            return KyberParameters.kyber512;
        case NamedGroup.kyber768:
            return KyberParameters.kyber768;
        case NamedGroup.kyber1024:
            return KyberParameters.kyber1024;
        default:
            return null;
        }
    }

    protected final BcTlsCrypto crypto;
    protected final TlsPQCConfig pqcConfig;
    protected final KyberParameters kyberParameters;

    public TlsPQCConfig getTlsPQCConfig()
    {
        return pqcConfig;
    }

    public BcTlsKyberDomain(BcTlsCrypto crypto, TlsPQCConfig pqcConfig)
    {
        this.crypto = crypto;
        this.pqcConfig = pqcConfig;
        this.kyberParameters = getKyberParameters(pqcConfig);
    }

    public TlsAgreement createPQC()
    {
        return new BcTlsKyber(this);
    }

    public KyberPublicKeyParameters decodePublicKey(byte[] encoding)
    {
        return new KyberPublicKeyParameters(kyberParameters, encoding);
    }

    public byte[] encodePublicKey(KyberPublicKeyParameters kyberPublicKeyParameters)
    {
        return kyberPublicKeyParameters.getEncoded();
    }

    public AsymmetricCipherKeyPair generateKeyPair()
    {
        KyberKeyPairGenerator keyPairGenerator = new KyberKeyPairGenerator();
        keyPairGenerator.init(new KyberKeyGenerationParameters(crypto.getSecureRandom(), kyberParameters));
        return keyPairGenerator.generateKeyPair();
    }

    public TlsSecret adoptLocalSecret(byte[] secret)
    {
        return crypto.adoptLocalSecret(secret);
    }

    public SecretWithEncapsulation enCap(KyberPublicKeyParameters peerPublicKey)
    {
        KyberKEMGenerator kemGen = new KyberKEMGenerator(crypto.getSecureRandom());
        return kemGen.generateEncapsulated(peerPublicKey);
    }

    public byte[] deCap(KyberPrivateKeyParameters kyberPrivateKeyParameters, byte[] cipherText)
    {
        KyberKEMExtractor kemExtract = new KyberKEMExtractor(kyberPrivateKeyParameters);
        byte[] secret = kemExtract.extractSecret(cipherText);
        return secret;
    }
}
