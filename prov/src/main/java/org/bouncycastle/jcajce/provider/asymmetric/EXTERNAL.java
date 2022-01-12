package org.bouncycastle.jcajce.provider.asymmetric;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.asn1.bc.BCObjectIdentifiers;
import org.bouncycastle.asn1.bc.ExternalValue;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.jcajce.ExternalPublicKey;
import org.bouncycastle.jcajce.provider.asymmetric.util.BaseKeyFactorySpi;
import org.bouncycastle.jcajce.provider.config.ConfigurableProvider;
import org.bouncycastle.jcajce.provider.util.AsymmetricAlgorithmProvider;
import org.bouncycastle.jcajce.provider.util.AsymmetricKeyInfoConverter;

public class EXTERNAL
{
    private static final String PREFIX = "org.bouncycastle.jcajce.provider.asymmetric.EXTERNAL";

    private static final Map<String, String> externalAttributes = new HashMap<String, String>();

    static
    {
        externalAttributes.put("SupportedKeyClasses", "org.bouncycastle.jcajce.ExternalPublicKey");
        externalAttributes.put("SupportedKeyFormats", "X.509");
    }

    private static AsymmetricKeyInfoConverter baseConverter;

    public static class KeyFactory
        extends BaseKeyFactorySpi
    {
        protected Key engineTranslateKey(Key key)
            throws InvalidKeyException
        {
            try
            {
                if (key instanceof PrivateKey)
                {
                    return generatePrivate(PrivateKeyInfo.getInstance(key.getEncoded()));
                }
                else if (key instanceof PublicKey)
                {
                    return generatePublic(SubjectPublicKeyInfo.getInstance(key.getEncoded()));
                }
            }
            catch (IOException e)
            {
                throw new InvalidKeyException("key could not be parsed: " + e.getMessage());
            }

            throw new InvalidKeyException("key not recognized");
        }

        public PrivateKey generatePrivate(PrivateKeyInfo keyInfo)
            throws IOException
        {
            return baseConverter.generatePrivate(keyInfo);
        }

        public PublicKey generatePublic(SubjectPublicKeyInfo keyInfo)
            throws IOException
        {
            return baseConverter.generatePublic(keyInfo);
        }
    }

    private static class ExternalKeyInfoConverter
        implements AsymmetricKeyInfoConverter
    {
        private final ConfigurableProvider provider;

        public ExternalKeyInfoConverter(ConfigurableProvider provider)
        {
            this.provider = provider;
        }

        public PrivateKey generatePrivate(PrivateKeyInfo keyInfo)
            throws IOException
        {
            throw new UnsupportedOperationException("no support for private key");
        }

        public PublicKey generatePublic(SubjectPublicKeyInfo keyInfo)
            throws IOException
        {
            ExternalValue extKey = ExternalValue.getInstance(keyInfo.parsePublicKey());

            // TODO: maybe implement some sort of cache lookup?

            return new ExternalPublicKey(extKey);
        }
    }

    public static class Mappings
        extends AsymmetricAlgorithmProvider
    {
        public Mappings()
        {
        }

        public void configure(ConfigurableProvider provider)
        {
            provider.addAlgorithm("KeyFactory.EXTERNAL", PREFIX + "$KeyFactory");
            provider.addAlgorithm("KeyFactory." + BCObjectIdentifiers.external_value, PREFIX + "$KeyFactory");
            provider.addAlgorithm("KeyFactory.OID." + BCObjectIdentifiers.external_value, PREFIX + "$KeyFactory");

            baseConverter = new ExternalKeyInfoConverter(provider);

            provider.addKeyInfoConverter(BCObjectIdentifiers.external_value, baseConverter);
        }
    }
}
