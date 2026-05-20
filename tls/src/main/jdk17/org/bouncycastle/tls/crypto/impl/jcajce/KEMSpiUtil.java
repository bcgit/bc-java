package org.bouncycastle.tls.crypto.impl.jcajce;

import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.NamedParameterSpec;

import javax.crypto.DecapsulateException;
import javax.crypto.KEM;
import javax.crypto.SecretKey;

import org.bouncycastle.jcajce.SecretKeyWithEncapsulation;
import org.bouncycastle.jcajce.util.JcaJceHelper;
import org.bouncycastle.jcajce.util.NamedJcaJceHelper;
import org.bouncycastle.jcajce.util.ProviderJcaJceHelper;

class KEMSpiUtil
{
    private static KEM createKEM(JcaJceHelper helper, String kemName)
        throws GeneralSecurityException
    {
        if (helper instanceof NamedJcaJceHelper withName)
        {
            return KEM.getInstance(kemName, withName.getProviderName());
        }
        else if (helper instanceof ProviderJcaJceHelper withProvider)
        {
            return KEM.getInstance(kemName, withProvider.getProvider());
        }
        else
        {
            return KEM.getInstance(kemName);
        }
    }

    static JceTlsSecret decapsulate(JcaTlsCrypto crypto, String kemName, PrivateKey privateKey, byte[] ciphertext)
    {
        KEM kem;
        try
        {
            kem = createKEM(crypto.getHelper(), kemName);
        }
        catch (GeneralSecurityException e)
        {
            throw Exceptions.illegalArgumentException("unable to create KEM", e);
        }

        KEM.Decapsulator decapsulator;
        try
        {
            decapsulator = kem.newDecapsulator(privateKey);
        }
        catch (InvalidKeyException e)
        {
            throw Exceptions.illegalArgumentException("invalid key", e);
        }

        SecretKey sharedSecret;
        try
        {
            sharedSecret = decapsulator.decapsulate(ciphertext);
        }
        catch (DecapsulateException e)
        {
            throw Exceptions.illegalArgumentException("decapsulation failed", e);
        }

        try
        {
            return crypto.adoptLocalSecret(sharedSecret.getEncoded());
        }
        finally
        {
            SecretKeyUtil.destroy(sharedSecret);
        }
    }

    static SecretKeyWithEncapsulation encapsulate(JcaTlsCrypto crypto, String kemName, PublicKey publicKey)
    {
        KEM kem;
        try
        {
            kem = createKEM(crypto.getHelper(), kemName);
        }
        catch (GeneralSecurityException e)
        {
            throw Exceptions.illegalArgumentException("unable to create KEM", e);
        }

        KEM.Encapsulator encapsulator;
        try
        {
            encapsulator = kem.newEncapsulator(publicKey, crypto.getSecureRandom());
        }
        catch (InvalidKeyException e)
        {
            throw Exceptions.illegalArgumentException("invalid key", e);
        }

        KEM.Encapsulated encapsulated = encapsulator.encapsulate();
        return new SecretKeyWithEncapsulation(encapsulated.key(), encapsulated.encapsulation());
    }

    static KeyPair generateKeyPair(JcaTlsCrypto crypto, String kemName)
    {
        try
        {
            KeyPairGenerator keyPairGenerator = crypto.getHelper().createKeyPairGenerator(kemName);
            keyPairGenerator.initialize(getNamedParameterSpec(kemName), crypto.getSecureRandom());
            return keyPairGenerator.generateKeyPair();
        }
        catch (GeneralSecurityException e)
        {
            throw Exceptions.illegalStateException("unable to create key pair: " + e.getMessage(), e);
        }
    }

    private static AlgorithmParameterSpec getNamedParameterSpec(String kemName)
    {
        // TODO ML-KEM NamedParameterSpec instances available since 24
        return new NamedParameterSpec(kemName);
    }

    static boolean isKemSupported(JcaTlsCrypto crypto, String kemName)
    {
        if (kemName != null)
        {
            try
            {
                JcaJceHelper helper = crypto.getHelper();
                helper.createKeyPairGenerator(kemName);
                createKEM(helper, kemName);
                return true;
            }
            catch (AssertionError e)
            {
            }
            catch (Exception e)
            {
            }
        }
        return false;
    }
}
