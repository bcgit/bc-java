package org.bouncycastle.jcajce.provider.asymmetric;

import org.bouncycastle.asn1.bc.BCObjectIdentifiers;
import org.bouncycastle.jcajce.provider.config.ConfigurableProvider;
import org.bouncycastle.jcajce.provider.util.AsymmetricAlgorithmProvider;
import org.bouncycastle.pqc.jcajce.provider.dilithium.DilithiumKeyFactorySpi;

public class Dilithium
{
    private static final String PREFIX = "org.bouncycastle.pqc.jcajce.provider" + ".dilithium.";

    public static class Mappings
        extends AsymmetricAlgorithmProvider
    {
        public Mappings()
        {
        }

        public void configure(ConfigurableProvider provider)
        {
            provider.addAlgorithm("KeyFactory.DILITHIUM", PREFIX + "DilithiumKeyFactorySpi");

            addKeyFactoryAlgorithm(provider, "DILITHIUM2", PREFIX + "DilithiumKeyFactorySpi$Base2", BCObjectIdentifiers.dilithium2, new DilithiumKeyFactorySpi.Base2());
            addKeyFactoryAlgorithm(provider, "DILITHIUM3", PREFIX + "DilithiumKeyFactorySpi$Base3", BCObjectIdentifiers.dilithium3, new DilithiumKeyFactorySpi.Base3());
            addKeyFactoryAlgorithm(provider, "DILITHIUM5", PREFIX + "DilithiumKeyFactorySpi$Base5", BCObjectIdentifiers.dilithium5, new DilithiumKeyFactorySpi.Base5());

            provider.addAlgorithm("KeyPairGenerator.DILITHIUM", PREFIX + "DilithiumKeyPairGeneratorSpi");

            addKeyPairGeneratorAlgorithm(provider, "DILITHIUM2", PREFIX + "DilithiumKeyPairGeneratorSpi$Base2", BCObjectIdentifiers.dilithium2);
            addKeyPairGeneratorAlgorithm(provider, "DILITHIUM3", PREFIX + "DilithiumKeyPairGeneratorSpi$Base3", BCObjectIdentifiers.dilithium3);
            addKeyPairGeneratorAlgorithm(provider, "DILITHIUM5", PREFIX + "DilithiumKeyPairGeneratorSpi$Base5", BCObjectIdentifiers.dilithium5);

            addSignatureAlgorithm(provider, "DILITHIUM", PREFIX + "SignatureSpi$Base", BCObjectIdentifiers.dilithium);

            addSignatureAlgorithm(provider, "DILITHIUM2", PREFIX + "SignatureSpi$Base2", BCObjectIdentifiers.dilithium2);
            addSignatureAlgorithm(provider, "DILITHIUM3", PREFIX + "SignatureSpi$Base3", BCObjectIdentifiers.dilithium3);
            addSignatureAlgorithm(provider, "DILITHIUM5", PREFIX + "SignatureSpi$Base5", BCObjectIdentifiers.dilithium5);
        }
    }
}
