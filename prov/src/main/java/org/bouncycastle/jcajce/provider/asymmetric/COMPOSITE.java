package org.bouncycastle.jcajce.provider.asymmetric;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.internal.asn1.misc.MiscObjectIdentifiers;
import org.bouncycastle.jcajce.provider.asymmetric.compositesignatures.KeyFactorySpi;
import org.bouncycastle.jcajce.provider.asymmetric.util.BaseKeyFactorySpi;
import org.bouncycastle.jcajce.provider.config.ConfigurableProvider;
import org.bouncycastle.jcajce.provider.util.AsymmetricAlgorithmProvider;
import org.bouncycastle.jcajce.provider.util.AsymmetricKeyInfoConverter;
import org.bouncycastle.jcajce.util.ProviderJcaJceHelper;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class COMPOSITE
{
    private static final String PREFIX = "org.bouncycastle.jcajce.provider.asymmetric.COMPOSITE";

    private static final Map<String, String> compositeAttributes = new HashMap<String, String>();

    static
    {
        compositeAttributes.put("SupportedKeyClasses", "org.bouncycastle.jcajce.CompositePublicKey|org.bouncycastle.jcajce.CompositePrivateKey");
        compositeAttributes.put("SupportedKeyFormats", "PKCS#8|X.509");
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

    public static class Mappings
        extends AsymmetricAlgorithmProvider
    {
        public Mappings()
        {
        }

        public void configure(ConfigurableProvider provider)
        {
            provider.addAlgorithm("KeyFactory.COMPOSITE", PREFIX + "$KeyFactory");
            provider.addAlgorithm("KeyFactory." + MiscObjectIdentifiers.id_alg_composite, PREFIX + "$KeyFactory");
            provider.addAlgorithm("KeyFactory.OID." + MiscObjectIdentifiers.id_alg_composite, PREFIX + "$KeyFactory");
            provider.addAlgorithm("KeyFactory." + MiscObjectIdentifiers.id_composite_key, PREFIX + "$KeyFactory");
            provider.addAlgorithm("KeyFactory.OID." + MiscObjectIdentifiers.id_composite_key, PREFIX + "$KeyFactory");

            baseConverter = new KeyFactorySpi(new ProviderJcaJceHelper((BouncyCastleProvider)provider));

            provider.addKeyInfoConverter(MiscObjectIdentifiers.id_alg_composite, baseConverter);
            provider.addKeyInfoConverter(MiscObjectIdentifiers.id_composite_key, baseConverter);
        }
    }
}
