package org.bouncycastle.tls.crypto.impl.bc;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.SecretWithEncapsulation;
import org.bouncycastle.crypto.generators.MLKEMKeyPairGenerator;
import org.bouncycastle.crypto.kems.MLKEMExtractor;
import org.bouncycastle.crypto.kems.MLKEMGenerator;
import org.bouncycastle.crypto.params.MLKEMKeyGenerationParameters;
import org.bouncycastle.crypto.params.MLKEMParameters;
import org.bouncycastle.crypto.params.MLKEMPrivateKeyParameters;
import org.bouncycastle.crypto.params.MLKEMPublicKeyParameters;
import org.bouncycastle.tls.NamedGroup;
import org.bouncycastle.tls.crypto.TlsAgreement;
import org.bouncycastle.tls.crypto.TlsKemConfig;
import org.bouncycastle.tls.crypto.TlsKemDomain;

public class BcTlsMLKemDomain implements TlsKemDomain
{
    public static MLKEMParameters getDomainParameters(TlsKemConfig kemConfig)
    {
        switch (kemConfig.getNamedGroup())
        {
        case NamedGroup.OQS_mlkem512:
        case NamedGroup.MLKEM512:
            return MLKEMParameters.ml_kem_512;
        case NamedGroup.OQS_mlkem768:
        case NamedGroup.MLKEM768:
            return MLKEMParameters.ml_kem_768;
        case NamedGroup.OQS_mlkem1024:
        case NamedGroup.MLKEM1024:
            return MLKEMParameters.ml_kem_1024;
        default:
            throw new IllegalArgumentException("No ML-KEM configuration provided");
        }
    }

    protected final BcTlsCrypto crypto;
    protected final MLKEMParameters domainParameters;
    protected final boolean isServer;

    public BcTlsMLKemDomain(BcTlsCrypto crypto, TlsKemConfig kemConfig)
    {
        this.crypto = crypto;
        this.domainParameters = getDomainParameters(kemConfig);
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
        return new MLKEMPublicKeyParameters(domainParameters, encoding);
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
        keyPairGenerator.init(new MLKEMKeyGenerationParameters(crypto.getSecureRandom(), domainParameters));
        return keyPairGenerator.generateKeyPair();
    }

    public boolean isServer()
    {
        return isServer;
    }
}
