package org.bouncycastle.jcajce.util;

import java.security.AlgorithmParameterGenerator;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyFactory;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.cert.CertPathBuilder;
import java.security.cert.CertPathValidator;
import java.security.cert.CertStore;
import java.security.cert.CertStoreParameters;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;

import javax.crypto.Cipher;
import javax.crypto.ExemptionMechanism;
import javax.crypto.KeyAgreement;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKeyFactory;

/**
 * {@link JcaJceHelper} that obtains all algorithms from a specific {@link Provider} instance.
 */
public class ProviderJcaJceHelper
    implements JcaJceHelper
{
    protected final Provider provider;

    public ProviderJcaJceHelper(Provider provider)
    {
        this.provider = provider;
    }

    public Cipher createCipher(
        String algorithm)
        throws NoSuchAlgorithmException, NoSuchPaddingException
    {
        return Cipher.getInstance(algorithm, provider);
    }

    public Mac createMac(String algorithm)
        throws NoSuchAlgorithmException
    {
        return Mac.getInstance(algorithm, provider);
    }

    public KeyAgreement createKeyAgreement(String algorithm)
        throws NoSuchAlgorithmException
    {
        return KeyAgreement.getInstance(algorithm, provider);
    }

    public AlgorithmParameterGenerator createAlgorithmParameterGenerator(String algorithm)
        throws NoSuchAlgorithmException
    {
        return AlgorithmParameterGenerator.getInstance(algorithm, provider);
    }

    public AlgorithmParameters createAlgorithmParameters(String algorithm)
        throws NoSuchAlgorithmException
    {
        return AlgorithmParameters.getInstance(algorithm, provider);
    }

    public KeyGenerator createKeyGenerator(String algorithm)
        throws NoSuchAlgorithmException
    {
        return KeyGenerator.getInstance(algorithm, provider);
    }

    public KeyFactory createKeyFactory(String algorithm)
        throws NoSuchAlgorithmException
    {
        return KeyFactory.getInstance(algorithm, provider);
    }

    public SecretKeyFactory createSecretKeyFactory(String algorithm)
        throws NoSuchAlgorithmException
    {
        return SecretKeyFactory.getInstance(algorithm, provider);
    }

    public KeyPairGenerator createKeyPairGenerator(String algorithm)
        throws NoSuchAlgorithmException
    {
        return KeyPairGenerator.getInstance(algorithm, provider);
    }

    /** @deprecated Use createMessageDigest instead */
    public MessageDigest createDigest(String algorithm)
        throws NoSuchAlgorithmException
    {
        return MessageDigest.getInstance(algorithm, provider);
    }

    public MessageDigest createMessageDigest(String algorithm)
        throws NoSuchAlgorithmException
    {
        return MessageDigest.getInstance(algorithm, provider);
    }

    public Signature createSignature(String algorithm)
        throws NoSuchAlgorithmException
    {
        return Signature.getInstance(algorithm, provider);
    }

    public CertificateFactory createCertificateFactory(String algorithm)
        throws CertificateException
    {
        return CertificateFactory.getInstance(algorithm, provider);
    }

    public SecureRandom createSecureRandom(String algorithm)
        throws NoSuchAlgorithmException
    {
        return SecureRandom.getInstance(algorithm, provider);
    }

    public CertPathBuilder createCertPathBuilder(String algorithm)
        throws NoSuchAlgorithmException
    {
        return CertPathBuilder.getInstance(algorithm, provider);
    }

    public CertPathValidator createCertPathValidator(String algorithm)
        throws NoSuchAlgorithmException
    {
        return CertPathValidator.getInstance(algorithm, provider);
    }

    public CertStore createCertStore(String type, CertStoreParameters params)
        throws NoSuchAlgorithmException, InvalidAlgorithmParameterException
    {
        return CertStore.getInstance(type, params, provider);
    }

    public ExemptionMechanism createExemptionMechanism(String algorithm)
        throws NoSuchAlgorithmException
    {
        return ExemptionMechanism.getInstance(algorithm, provider);
    }

    public KeyStore createKeyStore(String type)
        throws KeyStoreException
    {
        return KeyStore.getInstance(type, provider);
    }
}
