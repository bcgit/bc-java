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
import org.bouncycastle.tls.crypto.TlsKemConfig;
import org.bouncycastle.tls.crypto.TlsKemDomain;

public class BcTlsMLKemDomain implements TlsKemDomain
{
    protected static KyberParameters getKyberParameters(int namedGroup)
    {
        switch (namedGroup)
        {
        case NamedGroup.OQS_mlkem512:
            return KyberParameters.kyber512;
        case NamedGroup.OQS_mlkem768:
        case NamedGroup.DRAFT_mlkem768:
            return KyberParameters.kyber768;
        case NamedGroup.OQS_mlkem1024:
        case NamedGroup.DRAFT_mlkem1024:
            return KyberParameters.kyber1024;
        default:
            return null;
        }
    }

    protected final BcTlsCrypto crypto;
    protected final KyberParameters kyberParameters;
    protected final boolean isServer;

    public BcTlsMLKemDomain(BcTlsCrypto crypto, TlsKemConfig kemConfig)
    {
        this.crypto = crypto;
        this.kyberParameters = getKyberParameters(kemConfig.getNamedGroup());
        this.isServer = kemConfig.isServer();
    }

    public BcTlsSecret adoptLocalSecret(byte[] secret)
    {
        return crypto.adoptLocalSecret(secret);
    }

    public TlsAgreement createKem()
    {
        return new BcTlsMLKem(this);
    }

    public BcTlsSecret decapsulate(KyberPrivateKeyParameters privateKey, byte[] ciphertext)
    {
        KyberKEMExtractor kemExtract = new KyberKEMExtractor(privateKey);
        byte[] secret = kemExtract.extractSecret(ciphertext);
        return adoptLocalSecret(secret);
    }

    public KyberPublicKeyParameters decodePublicKey(byte[] encoding)
    {
        return new KyberPublicKeyParameters(kyberParameters, encoding);
    }

    public SecretWithEncapsulation encapsulate(KyberPublicKeyParameters publicKey)
    {
        KyberKEMGenerator kemGen = new KyberKEMGenerator(crypto.getSecureRandom());
        return kemGen.generateEncapsulated(publicKey);
    }

    public byte[] encodePublicKey(KyberPublicKeyParameters publicKey)
    {
        return publicKey.getEncoded();
    }

    public AsymmetricCipherKeyPair generateKeyPair()
    {
        KyberKeyPairGenerator keyPairGenerator = new KyberKeyPairGenerator();
        keyPairGenerator.init(new KyberKeyGenerationParameters(crypto.getSecureRandom(), kyberParameters));
        return keyPairGenerator.generateKeyPair();
    }

    public boolean isServer()
    {
        return isServer;
    }
}
