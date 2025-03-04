package org.bouncycastle.pqc.jcajce.provider;

import org.bouncycastle.asn1.bc.BCObjectIdentifiers;
import org.bouncycastle.jcajce.provider.config.ConfigurableProvider;
import org.bouncycastle.jcajce.provider.util.AsymmetricAlgorithmProvider;
import org.bouncycastle.pqc.jcajce.provider.mayo.MayoKeyFactorySpi;

public class Mayo
{
    private static final String PREFIX = "org.bouncycastle.pqc.jcajce.provider.mayo.";

    public static class Mappings
        extends AsymmetricAlgorithmProvider
    {
        public Mappings()
        {
        }

        public void configure(ConfigurableProvider provider)
        {
            provider.addAlgorithm("KeyFactory.Mayo", PREFIX + "MayoKeyFactorySpi");

            addKeyFactoryAlgorithm(provider, "MAYO_1", PREFIX + "MayoKeyFactorySpi$Mayo1", BCObjectIdentifiers.mayo1, new MayoKeyFactorySpi.Mayo1());
            addKeyFactoryAlgorithm(provider, "MAYO_2", PREFIX + "MayoKeyFactorySpi$Mayo2", BCObjectIdentifiers.mayo2, new MayoKeyFactorySpi.Mayo2());
            addKeyFactoryAlgorithm(provider, "MAYO_3", PREFIX + "MayoKeyFactorySpi$Mayo3", BCObjectIdentifiers.mayo3, new MayoKeyFactorySpi.Mayo3());
            addKeyFactoryAlgorithm(provider, "MAYO_5", PREFIX + "MayoKeyFactorySpi$Mayo5", BCObjectIdentifiers.mayo5, new MayoKeyFactorySpi.Mayo5());

            provider.addAlgorithm("KeyPairGenerator.Mayo", PREFIX + "MayoKeyPairGeneratorSpi");

            addKeyPairGeneratorAlgorithm(provider, "MAYO_1", PREFIX + "MayoKeyPairGeneratorSpi$Mayo1", BCObjectIdentifiers.mayo1);
            addKeyPairGeneratorAlgorithm(provider, "MAYO_2", PREFIX + "MayoKeyPairGeneratorSpi$Mayo2", BCObjectIdentifiers.mayo2);
            addKeyPairGeneratorAlgorithm(provider, "MAYO_3", PREFIX + "MayoKeyPairGeneratorSpi$Mayo3", BCObjectIdentifiers.mayo3);
            addKeyPairGeneratorAlgorithm(provider, "MAYO_5", PREFIX + "MayoKeyPairGeneratorSpi$Mayo5", BCObjectIdentifiers.mayo5);

            addSignatureAlgorithm(provider, "Mayo", PREFIX + "SignatureSpi$Base", BCObjectIdentifiers.mayo);

            addSignatureAlgorithm(provider, "MAYO_1", PREFIX + "SignatureSpi$Mayo1", BCObjectIdentifiers.mayo1);
            addSignatureAlgorithm(provider, "MAYO_2", PREFIX + "SignatureSpi$Mayo2", BCObjectIdentifiers.mayo2);
            addSignatureAlgorithm(provider, "MAYO_3", PREFIX + "SignatureSpi$Mayo3", BCObjectIdentifiers.mayo3);
            addSignatureAlgorithm(provider, "MAYO_5", PREFIX + "SignatureSpi$Mayo5", BCObjectIdentifiers.mayo5);
        }
    }
}

