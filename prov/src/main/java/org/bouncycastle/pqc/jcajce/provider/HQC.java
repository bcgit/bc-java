package org.bouncycastle.pqc.jcajce.provider;

import org.bouncycastle.asn1.bc.BCObjectIdentifiers;
import org.bouncycastle.jcajce.provider.config.ConfigurableProvider;
import org.bouncycastle.jcajce.provider.util.AsymmetricAlgorithmProvider;
import org.bouncycastle.jcajce.provider.util.AsymmetricKeyInfoConverter;
import org.bouncycastle.pqc.jcajce.provider.hqc.HQCKeyFactorySpi;

public class HQC
{
    private static final String PREFIX = "org.bouncycastle.pqc.jcajce.provider" + ".hqc.";

    public static class Mappings
        extends AsymmetricAlgorithmProvider
    {
        public Mappings()
        {
        }

        public void configure(ConfigurableProvider provider)
        {
            provider.addAlgorithm("KeyFactory.HQC", PREFIX + "HQCKeyFactorySpi");
            provider.addAlgorithm("Alg.Alias.KeyFactory.HQC", "HQC");
            addKeyFactoryAlgorithm(provider, "HQC128", PREFIX + "HQCKeyFactorySpi$HQC128", BCObjectIdentifiers.hqc128, new HQCKeyFactorySpi.HQC128());
            addKeyFactoryAlgorithm(provider, "HQC192", PREFIX + "HQCKeyFactorySpi$HQC192", BCObjectIdentifiers.hqc192, new HQCKeyFactorySpi.HQC192());
            addKeyFactoryAlgorithm(provider, "HQC256", PREFIX + "HQCKeyFactorySpi$HQC256", BCObjectIdentifiers.hqc256, new HQCKeyFactorySpi.HQC256());

            provider.addAlgorithm("KeyPairGenerator.HQC", PREFIX + "HQCKeyPairGeneratorSpi");
            provider.addAlgorithm("Alg.Alias.KeyPairGenerator.HQC", "HQC");
            addKeyPairGeneratorAlgorithm(provider, "HQC128", PREFIX + "HQCKeyPairGeneratorSpi$HQC128", BCObjectIdentifiers.hqc128);
            addKeyPairGeneratorAlgorithm(provider, "HQC192", PREFIX + "HQCKeyPairGeneratorSpi$HQC192", BCObjectIdentifiers.hqc192);
            addKeyPairGeneratorAlgorithm(provider, "HQC256", PREFIX + "HQCKeyPairGeneratorSpi$HQC256", BCObjectIdentifiers.hqc256);

            provider.addAlgorithm("KeyGenerator.HQC", PREFIX + "HQCKeyGeneratorSpi");
            addKeyGeneratorAlgorithm(provider, "HQC128", PREFIX + "HQCKeyGeneratorSpi$HQC128", BCObjectIdentifiers.hqc128);
            addKeyGeneratorAlgorithm(provider, "HQC192", PREFIX + "HQCKeyGeneratorSpi$HQC192", BCObjectIdentifiers.hqc192);
            addKeyGeneratorAlgorithm(provider, "HQC256", PREFIX + "HQCKeyGeneratorSpi$HQC256", BCObjectIdentifiers.hqc256);

            AsymmetricKeyInfoConverter keyFact = new HQCKeyFactorySpi();

            provider.addAlgorithm("Cipher.HQC", PREFIX + "HQCCipherSpi$Base");
            provider.addAlgorithm("Alg.Alias.Cipher.HQC", "HQC");
            provider.addAlgorithm("Alg.Alias.Cipher." + BCObjectIdentifiers.pqc_kem_hqc, "HQC");

            addCipherAlgorithm(provider, "HQC128", PREFIX + "HQCCipherSpi$HQC128", BCObjectIdentifiers.hqc128);
            addCipherAlgorithm(provider, "HQC192", PREFIX + "HQCCipherSpi$HQC192", BCObjectIdentifiers.hqc192);
            addCipherAlgorithm(provider, "HQC256", PREFIX + "HQCCipherSpi$HQC256", BCObjectIdentifiers.hqc256);

            registerOid(provider, BCObjectIdentifiers.pqc_kem_hqc, "HQC", keyFact);
            provider.addKeyInfoConverter(BCObjectIdentifiers.hqc128, keyFact);
            provider.addKeyInfoConverter(BCObjectIdentifiers.hqc192, keyFact);
            provider.addKeyInfoConverter(BCObjectIdentifiers.hqc256, keyFact);
        }
    }
}

