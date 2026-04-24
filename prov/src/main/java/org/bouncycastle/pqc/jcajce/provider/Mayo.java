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

            addKeyFactoryAlgorithm(provider, "MAYO-1", PREFIX + "MayoKeyFactorySpi$Mayo1", BCObjectIdentifiers.mayo1, new MayoKeyFactorySpi.Mayo1());
            addKeyFactoryAlgorithm(provider, "MAYO-2", PREFIX + "MayoKeyFactorySpi$Mayo2", BCObjectIdentifiers.mayo2, new MayoKeyFactorySpi.Mayo2());
            addKeyFactoryAlgorithm(provider, "MAYO-3", PREFIX + "MayoKeyFactorySpi$Mayo3", BCObjectIdentifiers.mayo3, new MayoKeyFactorySpi.Mayo3());
            addKeyFactoryAlgorithm(provider, "MAYO-5", PREFIX + "MayoKeyFactorySpi$Mayo5", BCObjectIdentifiers.mayo5, new MayoKeyFactorySpi.Mayo5());
            provider.addAlgorithm("Alg.Alias.KeyFactory.MAYO_1", "MAYO-1");
            provider.addAlgorithm("Alg.Alias.KeyFactory.MAYO_2", "MAYO-2");
            provider.addAlgorithm("Alg.Alias.KeyFactory.MAYO_3", "MAYO-3");
            provider.addAlgorithm("Alg.Alias.KeyFactory.MAYO_5", "MAYO-5");

            provider.addAlgorithm("KeyPairGenerator.Mayo", PREFIX + "MayoKeyPairGeneratorSpi");

            addKeyPairGeneratorAlgorithm(provider, "MAYO-1", PREFIX + "MayoKeyPairGeneratorSpi$Mayo1", BCObjectIdentifiers.mayo1);
            addKeyPairGeneratorAlgorithm(provider, "MAYO-2", PREFIX + "MayoKeyPairGeneratorSpi$Mayo2", BCObjectIdentifiers.mayo2);
            addKeyPairGeneratorAlgorithm(provider, "MAYO-3", PREFIX + "MayoKeyPairGeneratorSpi$Mayo3", BCObjectIdentifiers.mayo3);
            addKeyPairGeneratorAlgorithm(provider, "MAYO-5", PREFIX + "MayoKeyPairGeneratorSpi$Mayo5", BCObjectIdentifiers.mayo5);
            provider.addAlgorithm("Alg.Alias.KeyPairGenerator.MAYO_1", "MAYO-1");
            provider.addAlgorithm("Alg.Alias.KeyPairGenerator.MAYO_2", "MAYO-2");
            provider.addAlgorithm("Alg.Alias.KeyPairGenerator.MAYO_3", "MAYO-3");
            provider.addAlgorithm("Alg.Alias.KeyPairGenerator.MAYO_5", "MAYO-5");

            addSignatureAlgorithm(provider, "Mayo", PREFIX + "SignatureSpi$Base", BCObjectIdentifiers.mayo);

            addSignatureAlgorithm(provider, "MAYO-1", PREFIX + "SignatureSpi$Mayo1", BCObjectIdentifiers.mayo1);
            addSignatureAlgorithm(provider, "MAYO-2", PREFIX + "SignatureSpi$Mayo2", BCObjectIdentifiers.mayo2);
            addSignatureAlgorithm(provider, "MAYO-3", PREFIX + "SignatureSpi$Mayo3", BCObjectIdentifiers.mayo3);
            addSignatureAlgorithm(provider, "MAYO-5", PREFIX + "SignatureSpi$Mayo5", BCObjectIdentifiers.mayo5);
            provider.addAlgorithm("Alg.Alias.Signature.MAYO_1", "MAYO-1");
            provider.addAlgorithm("Alg.Alias.Signature.MAYO_2", "MAYO-2");
            provider.addAlgorithm("Alg.Alias.Signature.MAYO_3", "MAYO-3");
            provider.addAlgorithm("Alg.Alias.Signature.MAYO_5", "MAYO-5");
        }
    }
}

