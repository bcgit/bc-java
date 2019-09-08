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
import java.security.NoSuchProviderException;
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

import org.bouncycastle.crypto.CryptoServicesRegistrar;

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
        throws NoSuchAlgorithmException, NoSuchPaddingException, NoSuchProviderException
    {
        return Cipher.getInstance(algorithm, provider.getName());
    }

    public Mac createMac(String algorithm)
        throws NoSuchAlgorithmException, NoSuchProviderException
    {
        return Mac.getInstance(algorithm, provider.getName());
    }

    public KeyAgreement createKeyAgreement(String algorithm)
        throws NoSuchAlgorithmException, NoSuchProviderException
    {
        return KeyAgreement.getInstance(algorithm, provider.getName());
    }

    public AlgorithmParameterGenerator createAlgorithmParameterGenerator(String algorithm)
        throws NoSuchAlgorithmException, NoSuchProviderException
    {
        return AlgorithmParameterGenerator.getInstance(algorithm, provider.getName());
    }

    public AlgorithmParameters createAlgorithmParameters(String algorithm)
        throws NoSuchAlgorithmException, NoSuchProviderException
    {
        return AlgorithmParameters.getInstance(algorithm, provider.getName());
    }

    public KeyGenerator createKeyGenerator(String algorithm)
        throws NoSuchAlgorithmException, NoSuchProviderException
    {
        return KeyGenerator.getInstance(algorithm, provider.getName());
    }

    public KeyFactory createKeyFactory(String algorithm)
        throws NoSuchAlgorithmException, NoSuchProviderException
    {
        return KeyFactory.getInstance(algorithm, provider.getName());
    }

    public SecretKeyFactory createSecretKeyFactory(String algorithm)
        throws NoSuchAlgorithmException, NoSuchProviderException
    {
        return SecretKeyFactory.getInstance(algorithm, provider.getName());
    }

    public KeyPairGenerator createKeyPairGenerator(String algorithm)
        throws NoSuchAlgorithmException, NoSuchProviderException
    {
        return KeyPairGenerator.getInstance(algorithm, provider.getName());
    }

    /** @deprecated Use createMessageDigest instead */
    public MessageDigest createDigest(String algorithm)
        throws NoSuchAlgorithmException, NoSuchProviderException
    {
        return MessageDigest.getInstance(algorithm, provider.getName());
    }

    public MessageDigest createMessageDigest(String algorithm)
        throws NoSuchAlgorithmException, NoSuchProviderException
    {
        return MessageDigest.getInstance(algorithm, provider.getName());
    }

    public Signature createSignature(String algorithm)
        throws NoSuchAlgorithmException, NoSuchProviderException
    {
        return Signature.getInstance(algorithm, provider.getName());
    }

    public CertificateFactory createCertificateFactory(String algorithm)
        throws CertificateException, NoSuchProviderException
    {
        return CertificateFactory.getInstance(algorithm, provider.getName());
    }

    public SecureRandom createSecureRandom(String algorithm)
        throws NoSuchAlgorithmException, NoSuchProviderException
    {
        return CryptoServicesRegistrar.getSecureRandom();
    }

    public KeyStore createKeyStore(String type)
        throws KeyStoreException, NoSuchProviderException
    {
        return KeyStore.getInstance(type, provider.getName());
    }
}
