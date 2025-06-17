package org.bouncycastle.tls.crypto.impl.jcajce;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;

import javax.crypto.KeyGenerator;

import org.bouncycastle.jcajce.SecretKeyWithEncapsulation;
import org.bouncycastle.jcajce.spec.KEMExtractSpec;
import org.bouncycastle.jcajce.spec.KEMGenerateSpec;
import org.bouncycastle.jcajce.spec.MLKEMParameterSpec;
import org.bouncycastle.tls.NamedGroup;
import org.bouncycastle.tls.crypto.TlsAgreement;
import org.bouncycastle.tls.crypto.TlsKemConfig;
import org.bouncycastle.tls.crypto.TlsKemDomain;

public class JceTlsMLKemDomain implements TlsKemDomain
{
    protected final JcaTlsCrypto crypto;
    protected final String kemName;
    protected final boolean isServer;

    public JceTlsMLKemDomain(JcaTlsCrypto crypto, TlsKemConfig kemConfig)
    {
        this.crypto = crypto;
        this.kemName = NamedGroup.getKemName(kemConfig.getNamedGroup());
        this.isServer = kemConfig.isServer();
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
            KeyGenerator keyGenerator = crypto.getHelper().createKeyGenerator(kemName);
            keyGenerator.init(new KEMExtractSpec.Builder(privateKey, ciphertext, "DEF", 256).withNoKdf().build());
            SecretKeyWithEncapsulation secEnc = (SecretKeyWithEncapsulation)keyGenerator.generateKey();
            return adoptLocalSecret(secEnc.getEncoded());
        }
        catch (Exception e)
        {
            throw Exceptions.illegalArgumentException("invalid key: " + e.getMessage(), e);
        }
    }

    public PublicKey decodePublicKey(byte[] encoding)
        throws IOException
    {
        return KemUtil.decodePublicKey(crypto, kemName, encoding);
    }

    public SecretKeyWithEncapsulation encapsulate(PublicKey publicKey)
    {
        try
        {
            KeyGenerator keyGenerator = crypto.getHelper().createKeyGenerator(kemName);
            keyGenerator.init(new KEMGenerateSpec.Builder(publicKey, "DEF", 256).withNoKdf().build());
            return (SecretKeyWithEncapsulation)keyGenerator.generateKey();
        }
        catch (Exception e)
        {
            throw Exceptions.illegalArgumentException("invalid key: " + e.getMessage(), e);
        }
    }

    public byte[] encodePublicKey(PublicKey publicKey)
        throws IOException
    {
        return KemUtil.encodePublicKey(publicKey);
    }

    public KeyPair generateKeyPair()
    {
        try
        {
            // TODO How to pass only the SecureRandom to initialize if we use the full name in the getInstance?
//            KeyPairGenerator keyPairGenerator = KemUtil.getKeyPairGenerator(crypto, kemName);
//            keyPairGenerator.initialize((AlgorithmParameterSpec)null, crypto.getSecureRandom());
//            return keyPairGenerator.generateKeyPair();

            KeyPairGenerator keyPairGenerator = crypto.getHelper().createKeyPairGenerator("ML-KEM");
            keyPairGenerator.initialize(MLKEMParameterSpec.fromName(kemName), crypto.getSecureRandom());
            return keyPairGenerator.generateKeyPair();
        }
        catch (GeneralSecurityException e)
        {
            throw Exceptions.illegalStateException("unable to create key pair: " + e.getMessage(), e);
        }
    }

    public boolean isServer()
    {
        return isServer;
    }
}
