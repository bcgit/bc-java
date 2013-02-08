package org.bouncycastle.openssl.jcajce;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.jcajce.DefaultJcaJceHelper;
import org.bouncycastle.jcajce.JcaJceHelper;
import org.bouncycastle.jcajce.NamedJcaJceHelper;
import org.bouncycastle.jcajce.ProviderJcaJceHelper;
import org.bouncycastle.openssl.PEMException;
import org.bouncycastle.openssl.PEMKeyPair;

public class JcaPEMKeyConverter
{
    private JcaJceHelper helper = new DefaultJcaJceHelper();

    public JcaPEMKeyConverter setProvider(Provider provider)
    {
        this.helper = new ProviderJcaJceHelper(provider);

        return this;
    }

    public JcaPEMKeyConverter setProvider(String providerName)
    {
        this.helper = new NamedJcaJceHelper(providerName);

        return this;
    }

    public KeyPair getKeyPair(PEMKeyPair keyPair)
        throws PEMException
    {
        try
        {
            String algorithm =  keyPair.getPrivateKeyInfo().getPrivateKeyAlgorithm().getAlgorithm().getId();

            if (X9ObjectIdentifiers.id_ecPublicKey.getId().equals(algorithm))
            {
                algorithm = "ECDSA";
            }

            KeyFactory keyFactory = helper.createKeyFactory(algorithm);

            return new KeyPair(keyFactory.generatePublic(new X509EncodedKeySpec(keyPair.getPublicKeyInfo().getEncoded())),
                                keyFactory.generatePrivate(new PKCS8EncodedKeySpec(keyPair.getPrivateKeyInfo().getEncoded())));
        }
        catch (Exception e)
        {
            throw new PEMException("unable to convert key pair: " + e.getMessage(), e);
        }
    }

    public PublicKey getPublicKey(SubjectPublicKeyInfo publicKeyInfo)
        throws PEMException
    {
        try
        {
            String algorithm =  publicKeyInfo.getAlgorithm().getAlgorithm().getId();

            if (X9ObjectIdentifiers.id_ecPublicKey.getId().equals(algorithm))
            {
                algorithm = "ECDSA";
            }

            KeyFactory keyFactory = helper.createKeyFactory(algorithm);

            return keyFactory.generatePublic(new X509EncodedKeySpec(publicKeyInfo.getEncoded()));
        }
        catch (Exception e)
        {
            throw new PEMException("unable to convert key pair: " + e.getMessage(), e);
        }
    }

    public PrivateKey getPrivateKey(PrivateKeyInfo privateKeyInfo)
        throws PEMException
    {
        try
        {
            String algorithm =  privateKeyInfo.getPrivateKeyAlgorithm().getAlgorithm().getId();

            if (X9ObjectIdentifiers.id_ecPublicKey.getId().equals(algorithm))
            {
                algorithm = "ECDSA";
            }

            KeyFactory keyFactory = helper.createKeyFactory(algorithm);

            return keyFactory.generatePrivate(new PKCS8EncodedKeySpec(privateKeyInfo.getEncoded()));
        }
        catch (Exception e)
        {
            throw new PEMException("unable to convert key pair: " + e.getMessage(), e);
        }
    }
}
