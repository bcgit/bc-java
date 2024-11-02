package org.bouncycastle.jcajce.provider.asymmetric;

import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.jcajce.provider.asymmetric.compositesignatures.CompositeIndex;
import org.bouncycastle.jcajce.provider.asymmetric.compositesignatures.KeyFactorySpi;
import org.bouncycastle.jcajce.provider.config.ConfigurableProvider;
import org.bouncycastle.jcajce.provider.util.AsymmetricAlgorithmProvider;

/**
 * Experimental implementation of composite signatures according to https://www.ietf.org/archive/id/draft-ounsworth-pq-composite-sigs-13.
 */
public class CompositeSignatures
{
    private static final String PREFIX = "org.bouncycastle.jcajce.provider.asymmetric" + ".compositesignatures.";

    private static final Map<String, String> compositesAttributes = new HashMap<String, String>();

    static
    {
        compositesAttributes.put("SupportedKeyClasses", "org.bouncycastle.jcajce.CompositePublicKey|org.bouncycastle.jcajce.CompositePrivateKey");
        compositesAttributes.put("SupportedKeyFormats", "PKCS#8|X.509");
    }

    public static class Mappings
            extends AsymmetricAlgorithmProvider
    {
        public Mappings()
        {
        }

        public void configure(ConfigurableProvider provider)
        {
            for (ASN1ObjectIdentifier oid : CompositeIndex.getSupportedIdentifiers())
            {
                String algorithmName = CompositeIndex.getAlgorithmName(oid);
                String className = algorithmName.replace('-', '_');

                provider.addAlgorithm("Alg.Alias.KeyFactory", oid, "COMPOSITE");
                provider.addAlgorithm("Alg.Alias.KeyFactory." + algorithmName, "COMPOSITE");
                
                provider.addAlgorithm("KeyPairGenerator." + algorithmName, PREFIX + "KeyPairGeneratorSpi$" + className);
                provider.addAlgorithm("Alg.Alias.KeyPairGenerator", oid, algorithmName);

                provider.addAlgorithm("Signature." + algorithmName, PREFIX + "SignatureSpi$" + className);
                provider.addAlgorithm("Alg.Alias.Signature", oid, algorithmName);

                provider.addKeyInfoConverter(oid, new KeyFactorySpi());
            }
        }
    }
}
