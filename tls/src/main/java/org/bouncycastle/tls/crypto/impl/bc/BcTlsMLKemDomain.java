package org.bouncycastle.tls.crypto.impl.bc;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.SecretWithEncapsulation;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMExtractor;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMGenerator;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMKeyPairGenerator;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMParameters;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMPublicKeyParameters;
import org.bouncycastle.tls.NamedGroup;
import org.bouncycastle.tls.crypto.TlsAgreement;
import org.bouncycastle.tls.crypto.TlsKemConfig;
import org.bouncycastle.tls.crypto.TlsKemDomain;

public class BcTlsMLKemDomain implements TlsKemDomain
{
    protected static MLKEMParameters getKyberParameters(int namedGroup)
    {
        switch (namedGroup)
        {
        case NamedGroup.OQS_mlkem512:
            return MLKEMParameters.kyber512;
        case NamedGroup.OQS_mlkem768:
        case NamedGroup.DRAFT_mlkem768:
            return MLKEMParameters.kyber768;
        case NamedGroup.OQS_mlkem1024:
        case NamedGroup.DRAFT_mlkem1024:
            return MLKEMParameters.kyber1024;
        default:
            return null;
        }
    }

    protected final BcTlsCrypto crypto;
    protected final MLKEMParameters kyberParameters;
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

    public BcTlsSecret decapsulate(MLKEMPrivateKeyParameters privateKey, byte[] ciphertext)
    {
        MLKEMExtractor kemExtract = new MLKEMExtractor(privateKey);
        byte[] secret = kemExtract.extractSecret(ciphertext);
        return adoptLocalSecret(secret);
    }

    public MLKEMPublicKeyParameters decodePublicKey(byte[] encoding)
    {
        return new MLKEMPublicKeyParameters(kyberParameters, encoding);
    }

    public SecretWithEncapsulation encapsulate(MLKEMPublicKeyParameters publicKey)
    {
        MLKEMGenerator kemGen = new MLKEMGenerator(crypto.getSecureRandom());
        return kemGen.generateEncapsulated(publicKey);
    }

    public byte[] encodePublicKey(MLKEMPublicKeyParameters publicKey)
    {
        return publicKey.getEncoded();
    }

    public AsymmetricCipherKeyPair generateKeyPair()
    {
        MLKEMKeyPairGenerator keyPairGenerator = new MLKEMKeyPairGenerator();
        keyPairGenerator.init(new MLKEMKeyGenerationParameters(crypto.getSecureRandom(), kyberParameters));
        return keyPairGenerator.generateKeyPair();
    }

    public boolean isServer()
    {
        return isServer;
    }
}
