package org.bouncycastle.jcajce.provider.asymmetric;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.jcajce.provider.asymmetric.compositesignatures.CompositeSignaturesConstants;
import org.bouncycastle.jcajce.provider.asymmetric.compositesignatures.KeyFactorySpi;
import org.bouncycastle.jcajce.provider.config.ConfigurableProvider;
import org.bouncycastle.jcajce.provider.util.AsymmetricAlgorithmProvider;

import java.util.HashMap;
import java.util.Map;

public class CompositeSignatures
{
    private static final String PREFIX = "org.bouncycastle.jcajce.provider.asymmetric" + ".compositesignatures.";

    private static final Map<String, String> compositesAttributes = new HashMap<>();

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
            for (ASN1ObjectIdentifier oid : CompositeSignaturesConstants.supportedIdentifiers) {
                String algName = CompositeSignaturesConstants.ASN1IdentifierAlgorithmNameMap.get(oid);
                provider.addAlgorithm("KeyFactory." + algName, PREFIX + "KeyFactorySpi"); //Key factory is the same for all composite signatures.
                provider.addAlgorithm("Alg.Alias.KeyFactory", oid, algName);

                provider.addAlgorithm("KeyPairGenerator." + algName, PREFIX + "KeyPairGeneratorSpi$" + algName);
                provider.addAlgorithm("Alg.Alias.KeyPairGenerator", oid, algName);

                provider.addAlgorithm("Signature." + algName, PREFIX + "SignatureSpi$" + algName);
                provider.addAlgorithm("Alg.Alias.Signature", oid, algName);

                provider.addKeyInfoConverter(oid, new KeyFactorySpi());
            }
        }
    }
}
