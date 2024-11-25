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
    protected final TlsKemConfig config;
    protected final MLKEMParameters domainParameters;
    protected final boolean isServer;

    public BcTlsMLKemDomain(BcTlsCrypto crypto, TlsKemConfig kemConfig)
    {
        this.crypto = crypto;
        this.config = kemConfig;
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
