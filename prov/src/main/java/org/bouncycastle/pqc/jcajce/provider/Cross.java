package org.bouncycastle.pqc.jcajce.provider;

import org.bouncycastle.asn1.bc.BCObjectIdentifiers;
import org.bouncycastle.jcajce.provider.config.ConfigurableProvider;
import org.bouncycastle.jcajce.provider.util.AsymmetricAlgorithmProvider;
import org.bouncycastle.pqc.jcajce.provider.cross.CrossKeyFactorySpi;

public class Cross
{
    private static final String PREFIX = "org.bouncycastle.pqc.jcajce.provider.cross.";

    public static class Mappings
        extends AsymmetricAlgorithmProvider
    {
        public Mappings()
        {
        }

        public void configure(ConfigurableProvider provider)
        {
            provider.addAlgorithm("KeyFactory.Cross", PREFIX + "CrossKeyFactorySpi");

            addKeyFactoryAlgorithm(provider, "CrossRsdp1Small", PREFIX + "CrossKeyFactorySpi$CrossRsdp1Small", BCObjectIdentifiers.cross_rsdp_1_small, new CrossKeyFactorySpi.CrossRsdp1Small());
            addKeyFactoryAlgorithm(provider, "CrossRsdp1Balanced", PREFIX + "CrossKeyFactorySpi$CrossRsdp1Balanced", BCObjectIdentifiers.cross_rsdp_1_balanced, new CrossKeyFactorySpi.CrossRsdp1Balanced());
            addKeyFactoryAlgorithm(provider, "CrossRsdp1Fast", PREFIX + "CrossKeyFactorySpi$CrossRsdp1Fast", BCObjectIdentifiers.cross_rsdp_1_fast, new CrossKeyFactorySpi.CrossRsdp1Fast());

            addKeyFactoryAlgorithm(provider, "CrossRsdp3Small", PREFIX + "CrossKeyFactorySpi$CrossRsdp3Small", BCObjectIdentifiers.cross_rsdp_3_small, new CrossKeyFactorySpi.CrossRsdp3Small());
            addKeyFactoryAlgorithm(provider, "CrossRsdp3Balanced", PREFIX + "CrossKeyFactorySpi$CrossRsdp3Balanced", BCObjectIdentifiers.cross_rsdp_3_balanced, new CrossKeyFactorySpi.CrossRsdp3Balanced());
            addKeyFactoryAlgorithm(provider, "CrossRsdp3Fast", PREFIX + "CrossKeyFactorySpi$CrossRsdp3Fast", BCObjectIdentifiers.cross_rsdp_3_fast, new CrossKeyFactorySpi.CrossRsdp3Fast());

            addKeyFactoryAlgorithm(provider, "CrossRsdp5Small", PREFIX + "CrossKeyFactorySpi$CrossRsdp5Small", BCObjectIdentifiers.cross_rsdp_5_small, new CrossKeyFactorySpi.CrossRsdp5Small());
            addKeyFactoryAlgorithm(provider, "CrossRsdp5Balanced", PREFIX + "CrossKeyFactorySpi$CrossRsdp5Balanced", BCObjectIdentifiers.cross_rsdp_5_balanced, new CrossKeyFactorySpi.CrossRsdp5Balanced());
            addKeyFactoryAlgorithm(provider, "CrossRsdp5Fast", PREFIX + "CrossKeyFactorySpi$CrossRsdp5Fast", BCObjectIdentifiers.cross_rsdp_5_fast, new CrossKeyFactorySpi.CrossRsdp5Fast());

            addKeyFactoryAlgorithm(provider, "CrossRsdpg1Small", PREFIX + "CrossKeyFactorySpi$CrossRsdpg1Small", BCObjectIdentifiers.cross_rsdpg_1_small, new CrossKeyFactorySpi.CrossRsdpg1Small());
            addKeyFactoryAlgorithm(provider, "CrossRsdpg1Balanced", PREFIX + "CrossKeyFactorySpi$CrossRsdpg1Balanced", BCObjectIdentifiers.cross_rsdpg_1_balanced, new CrossKeyFactorySpi.CrossRsdpg1Balanced());
            addKeyFactoryAlgorithm(provider, "CrossRsdpg1Fast", PREFIX + "CrossKeyFactorySpi$CrossRsdpg1Fast", BCObjectIdentifiers.cross_rsdpg_1_fast, new CrossKeyFactorySpi.CrossRsdpg1Fast());

            addKeyFactoryAlgorithm(provider, "CrossRsdpg3Small", PREFIX + "CrossKeyFactorySpi$CrossRsdpg3Small", BCObjectIdentifiers.cross_rsdpg_3_small, new CrossKeyFactorySpi.CrossRsdpg3Small());
            addKeyFactoryAlgorithm(provider, "CrossRsdpg3Balanced", PREFIX + "CrossKeyFactorySpi$CrossRsdpg3Balanced", BCObjectIdentifiers.cross_rsdpg_3_balanced, new CrossKeyFactorySpi.CrossRsdpg3Balanced());
            addKeyFactoryAlgorithm(provider, "CrossRsdpg3Fast", PREFIX + "CrossKeyFactorySpi$CrossRsdpg3Fast", BCObjectIdentifiers.cross_rsdpg_3_fast, new CrossKeyFactorySpi.CrossRsdpg3Fast());

            addKeyFactoryAlgorithm(provider, "CrossRsdpg5Small", PREFIX + "CrossKeyFactorySpi$CrossRsdpg5Small", BCObjectIdentifiers.cross_rsdpg_5_small, new CrossKeyFactorySpi.CrossRsdpg5Small());
            addKeyFactoryAlgorithm(provider, "CrossRsdpg5Balanced", PREFIX + "CrossKeyFactorySpi$CrossRsdpg5Balanced", BCObjectIdentifiers.cross_rsdpg_5_balanced, new CrossKeyFactorySpi.CrossRsdpg5Balanced());
            addKeyFactoryAlgorithm(provider, "CrossRsdpg5Fast", PREFIX + "CrossKeyFactorySpi$CrossRsdpg5Fast", BCObjectIdentifiers.cross_rsdpg_5_fast, new CrossKeyFactorySpi.CrossRsdpg5Fast());


            provider.addAlgorithm("KeyPairGenerator.Cross", PREFIX + "CrossKeyPairGeneratorSpi");

            addKeyPairGeneratorAlgorithm(provider, "CrossRsdp1Small", PREFIX + "CrossKeyPairGeneratorSpi$CrossRsdp1Small", BCObjectIdentifiers.cross_rsdp_1_small);
            addKeyPairGeneratorAlgorithm(provider, "CrossRsdp1Balanced", PREFIX + "CrossKeyPairGeneratorSpi$CrossRsdp1Balanced", BCObjectIdentifiers.cross_rsdp_1_balanced);
            addKeyPairGeneratorAlgorithm(provider, "CrossRsdp1Fast", PREFIX + "CrossKeyPairGeneratorSpi$CrossRsdp1Fast", BCObjectIdentifiers.cross_rsdp_1_fast);

            addKeyPairGeneratorAlgorithm(provider, "CrossRsdp3Small", PREFIX + "CrossKeyPairGeneratorSpi$CrossRsdp3Small", BCObjectIdentifiers.cross_rsdp_3_small);
            addKeyPairGeneratorAlgorithm(provider, "CrossRsdp3Balanced", PREFIX + "CrossKeyPairGeneratorSpi$CrossRsdp3Balanced", BCObjectIdentifiers.cross_rsdp_3_balanced);
            addKeyPairGeneratorAlgorithm(provider, "CrossRsdp3Fast", PREFIX + "CrossKeyPairGeneratorSpi$CrossRsdp3Fast", BCObjectIdentifiers.cross_rsdp_3_fast);

            addKeyPairGeneratorAlgorithm(provider, "CrossRsdp5Small", PREFIX + "CrossKeyPairGeneratorSpi$CrossRsdp5Small", BCObjectIdentifiers.cross_rsdp_5_small);
            addKeyPairGeneratorAlgorithm(provider, "CrossRsdp5Balanced", PREFIX + "CrossKeyPairGeneratorSpi$CrossRsdp5Balanced", BCObjectIdentifiers.cross_rsdp_5_balanced);
            addKeyPairGeneratorAlgorithm(provider, "CrossRsdp5Fast", PREFIX + "CrossKeyPairGeneratorSpi$CrossRsdp5Fast", BCObjectIdentifiers.cross_rsdp_5_fast);

            addKeyPairGeneratorAlgorithm(provider, "CrossRsdpg1Small", PREFIX + "CrossKeyPairGeneratorSpi$CrossRsdpg1Small", BCObjectIdentifiers.cross_rsdpg_1_small);
            addKeyPairGeneratorAlgorithm(provider, "CrossRsdpg1Balanced", PREFIX + "CrossKeyPairGeneratorSpi$CrossRsdpg1Balanced", BCObjectIdentifiers.cross_rsdpg_1_balanced);
            addKeyPairGeneratorAlgorithm(provider, "CrossRsdpg1Fast", PREFIX + "CrossKeyPairGeneratorSpi$CrossRsdpg1Fast", BCObjectIdentifiers.cross_rsdpg_1_fast);

            addKeyPairGeneratorAlgorithm(provider, "CrossRsdpg3Small", PREFIX + "CrossKeyPairGeneratorSpi$CrossRsdpg3Small", BCObjectIdentifiers.cross_rsdpg_3_small);
            addKeyPairGeneratorAlgorithm(provider, "CrossRsdpg3Balanced", PREFIX + "CrossKeyPairGeneratorSpi$CrossRsdpg3Balanced", BCObjectIdentifiers.cross_rsdpg_3_balanced);
            addKeyPairGeneratorAlgorithm(provider, "CrossRsdpg3Fast", PREFIX + "CrossKeyPairGeneratorSpi$CrossRsdpg3Fast", BCObjectIdentifiers.cross_rsdpg_3_fast);

            addKeyPairGeneratorAlgorithm(provider, "CrossRsdpg5Small", PREFIX + "CrossKeyPairGeneratorSpi$CrossRsdpg5Small", BCObjectIdentifiers.cross_rsdpg_5_small);
            addKeyPairGeneratorAlgorithm(provider, "CrossRsdpg5Balanced", PREFIX + "CrossKeyPairGeneratorSpi$CrossRsdpg5Balanced", BCObjectIdentifiers.cross_rsdpg_5_balanced);
            addKeyPairGeneratorAlgorithm(provider, "CrossRsdpg5Fast", PREFIX + "CrossKeyPairGeneratorSpi$CrossRsdpg5Fast", BCObjectIdentifiers.cross_rsdpg_5_fast);

            addSignatureAlgorithm(provider, "Cross", PREFIX + "SignatureSpi$Base", BCObjectIdentifiers.cross);

            addSignatureAlgorithm(provider, "CrossRsdp1Small", PREFIX + "SignatureSpi$CrossRsdp1Small", BCObjectIdentifiers.cross_rsdp_1_small);
            addSignatureAlgorithm(provider, "CrossRsdp1Balanced", PREFIX + "SignatureSpi$CrossRsdp1Balanced", BCObjectIdentifiers.cross_rsdp_1_balanced);
            addSignatureAlgorithm(provider, "CrossRsdp1Fast", PREFIX + "SignatureSpi$CrossRsdp1Fast", BCObjectIdentifiers.cross_rsdp_1_fast);

            addSignatureAlgorithm(provider, "CrossRsdp3Small", PREFIX + "SignatureSpi$CrossRsdp3Small", BCObjectIdentifiers.cross_rsdp_3_small);
            addSignatureAlgorithm(provider, "CrossRsdp3Balanced", PREFIX + "SignatureSpi$CrossRsdp3Balanced", BCObjectIdentifiers.cross_rsdp_3_balanced);
            addSignatureAlgorithm(provider, "CrossRsdp3Fast", PREFIX + "SignatureSpi$CrossRsdp3Fast", BCObjectIdentifiers.cross_rsdp_3_fast);

            addSignatureAlgorithm(provider, "CrossRsdp5Small", PREFIX + "SignatureSpi$CrossRsdp5Small", BCObjectIdentifiers.cross_rsdp_5_small);
            addSignatureAlgorithm(provider, "CrossRsdp5Balanced", PREFIX + "SignatureSpi$CrossRsdp5Balanced", BCObjectIdentifiers.cross_rsdp_5_balanced);
            addSignatureAlgorithm(provider, "CrossRsdp5Fast", PREFIX + "SignatureSpi$CrossRsdp5Fast", BCObjectIdentifiers.cross_rsdp_5_fast);

            addSignatureAlgorithm(provider, "CrossRsdpg1Small", PREFIX + "SignatureSpi$CrossRsdpg1Small", BCObjectIdentifiers.cross_rsdpg_1_small);
            addSignatureAlgorithm(provider, "CrossRsdpg1Balanced", PREFIX + "SignatureSpi$CrossRsdpg1Balanced", BCObjectIdentifiers.cross_rsdpg_1_balanced);
            addSignatureAlgorithm(provider, "CrossRsdpg1Fast", PREFIX + "SignatureSpi$CrossRsdpg1Fast", BCObjectIdentifiers.cross_rsdpg_1_fast);

            addSignatureAlgorithm(provider, "CrossRsdpg3Small", PREFIX + "SignatureSpi$CrossRsdpg3Small", BCObjectIdentifiers.cross_rsdpg_3_small);
            addSignatureAlgorithm(provider, "CrossRsdpg3Balanced", PREFIX + "SignatureSpi$CrossRsdpg3Balanced", BCObjectIdentifiers.cross_rsdpg_3_balanced);
            addSignatureAlgorithm(provider, "CrossRsdpg3Fast", PREFIX + "SignatureSpi$CrossRsdpg3Fast", BCObjectIdentifiers.cross_rsdpg_3_fast);

            addSignatureAlgorithm(provider, "CrossRsdpg5Small", PREFIX + "SignatureSpi$CrossRsdpg5Small", BCObjectIdentifiers.cross_rsdpg_5_small);
            addSignatureAlgorithm(provider, "CrossRsdpg5Balanced", PREFIX + "SignatureSpi$CrossRsdpg5Balanced", BCObjectIdentifiers.cross_rsdpg_5_balanced);
            addSignatureAlgorithm(provider, "CrossRsdpg5Fast", PREFIX + "SignatureSpi$CrossRsdpg5Fast", BCObjectIdentifiers.cross_rsdpg_5_fast);

        }
    }
}

