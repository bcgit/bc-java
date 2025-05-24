package org.bouncycastle.tls.crypto.impl.jcajce;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;

import javax.crypto.KeyGenerator;

import org.bouncycastle.jcajce.SecretKeyWithEncapsulation;
import org.bouncycastle.jcajce.provider.asymmetric.mlkem.BCMLKEMPublicKey;
import org.bouncycastle.jcajce.spec.KEMExtractSpec;
import org.bouncycastle.jcajce.spec.KEMGenerateSpec;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMParameters;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMPublicKeyParameters;
import org.bouncycastle.tls.NamedGroup;
import org.bouncycastle.tls.crypto.TlsAgreement;
import org.bouncycastle.tls.crypto.TlsKemConfig;
import org.bouncycastle.tls.crypto.TlsKemDomain;

public class JceTlsMLKemDomain implements TlsKemDomain
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

    protected final JcaTlsCrypto crypto;
    protected final TlsKemConfig config;
    protected final MLKEMParameters domainParameters;
    protected final boolean isServer;
    protected KeyGenerator keyGen;
//    protected KeyPairGenerator kpg;
//    protected Cipher cipher;


    public JceTlsMLKemDomain(JcaTlsCrypto crypto, TlsKemConfig kemConfig)
    {
        this.crypto = crypto;
        this.config = kemConfig;
        this.domainParameters = getDomainParameters(kemConfig);
        this.isServer = kemConfig.isServer();
        try
        {
            this.keyGen = crypto.getHelper().createKeyGenerator(domainParameters.getName());
        }
        catch (NoSuchAlgorithmException e)
        {
            throw new RuntimeException(e);
        }
        catch (NoSuchProviderException e)
        {
            throw new RuntimeException(e);
        }
    }

    public JceTlsSecret adoptLocalSecret(byte[] secret)
    {
        return crypto.adoptLocalSecret(secret);
    }

    public TlsAgreement createKem()
    {
        return new JceTlsMLKem(this);
    }

    public JceTlsSecret decapsulate(PrivateKey privateKey, byte[] ciphertext)
    {
        try
        {
            keyGen.init(new KEMExtractSpec.Builder(privateKey, ciphertext, "DEF", 256).withNoKdf().build());
            SecretKeyWithEncapsulation secEnc = (SecretKeyWithEncapsulation)keyGen.generateKey();

            return adoptLocalSecret(secEnc.getEncoded());
        }
        catch (Exception e)
        {
            throw Exceptions.illegalArgumentException("invalid key: " + e.getMessage(), e);
        }


//        MLKEMExtractor kemExtract = new MLKEMExtractor(privateKey);
//        byte[] secret = kemExtract.extractSecret(ciphertext);
//        return adoptLocalSecret(secret);
    }

    public BCMLKEMPublicKey decodePublicKey(byte[] encoding)
    {
        return new BCMLKEMPublicKey(new MLKEMPublicKeyParameters(domainParameters, encoding));
    }

    public SecretKeyWithEncapsulation encapsulate(PublicKey publicKey)
    {
        try
        {
            keyGen.init(new KEMGenerateSpec.Builder(publicKey, "DEF", 256).withNoKdf().build());
            return (SecretKeyWithEncapsulation)keyGen.generateKey();
        }
        catch (Exception e)
        {
            throw Exceptions.illegalArgumentException("invalid key: " + e.getMessage(), e);
        }
    }

    public byte[] encodePublicKey(MLKEMPublicKeyParameters publicKey)
    {
        return publicKey.getEncoded();
    }

    private void init()
    {
//        try
//        {
////            kpg = KeyPairGenerator.getInstance("MLKEM");
////            kpg.initialize(MLKEMParameterSpec.fromName(domainParameters.getName()), crypto.getSecureRandom());
////            keyGen = KeyGenerator.getInstance(domainParameters.getName(), "BC");
//
////            cipher = KemUtil.getCipher(crypto, domainParameters.getName());
//
//
//        }
//        catch (GeneralSecurityException e)
//        {
//            throw Exceptions.illegalStateException("unable to create key pair: " + e.getMessage(), e);
//        }


    }
    public KeyPair generateKeyPair()
    {
//        AlgorithmParameters params = KemUtil.getAlgorithmParameters(crypto, domainParameters.getName());
//        if (params == null)
//        {
//            throw new IllegalStateException("KEM parameters unavailable");
//        }
        KeyPairGenerator kpg = null;
        try
        {
            kpg = crypto.getHelper().createKeyPairGenerator(domainParameters.getName());
        }
        catch (NoSuchAlgorithmException e)
        {
            throw new RuntimeException(e);
        }
        catch (NoSuchProviderException e)
        {
            throw new RuntimeException(e);
        }
        return kpg.generateKeyPair();
    }

    public boolean isServer()
    {
        return isServer;
    }
}
