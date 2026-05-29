package org.bouncycastle.pqc.jcajce.provider;

import org.bouncycastle.asn1.bc.BCObjectIdentifiers;
import org.bouncycastle.jcajce.provider.config.ConfigurableProvider;
import org.bouncycastle.jcajce.provider.util.AsymmetricAlgorithmProvider;
import org.bouncycastle.pqc.jcajce.provider.sqisign.SQIsignKeyFactorySpi;

public class SQIsign
{
    private static final String PREFIX = "org.bouncycastle.pqc.jcajce.provider.sqisign.";

    public static class Mappings
        extends AsymmetricAlgorithmProvider
    {
        public Mappings()
        {
        }

        public void configure(ConfigurableProvider provider)
        {
            provider.addAlgorithm("KeyFactory.SQIsign", PREFIX + "SQIsignKeyFactorySpi");

            addKeyFactoryAlgorithm(provider, "sqisign_lvl1", PREFIX + "SQIsignKeyFactorySpi$SQIsign_lvl1", BCObjectIdentifiers.sqisign_lvl1, new SQIsignKeyFactorySpi.SQIsign_lvl1());
            addKeyFactoryAlgorithm(provider, "sqisign_lvl3", PREFIX + "SQIsignKeyFactorySpi$SQIsign_lvl3", BCObjectIdentifiers.sqisign_lvl3, new SQIsignKeyFactorySpi.SQIsign_lvl3());
            addKeyFactoryAlgorithm(provider, "sqisign_lvl5", PREFIX + "SQIsignKeyFactorySpi$SQIsign_lvl5", BCObjectIdentifiers.sqisign_lvl5, new SQIsignKeyFactorySpi.SQIsign_lvl5());

            provider.addAlgorithm("KeyPairGenerator.SQIsign", PREFIX + "SQIsignKeyPairGeneratorSpi");

            addKeyPairGeneratorAlgorithm(provider, "sqisign_lvl1", PREFIX + "SQIsignKeyPairGeneratorSpi$SQIsign_lvl1", BCObjectIdentifiers.sqisign_lvl1);
            addKeyPairGeneratorAlgorithm(provider, "sqisign_lvl3", PREFIX + "SQIsignKeyPairGeneratorSpi$SQIsign_lvl3", BCObjectIdentifiers.sqisign_lvl3);
            addKeyPairGeneratorAlgorithm(provider, "sqisign_lvl5", PREFIX + "SQIsignKeyPairGeneratorSpi$SQIsign_lvl5", BCObjectIdentifiers.sqisign_lvl5);

            addSignatureAlgorithm(provider, "SQIsign", PREFIX + "SignatureSpi$Base", BCObjectIdentifiers.sqisign);

            addSignatureAlgorithm(provider, "sqisign_lvl1", PREFIX + "SignatureSpi$SQIsign_lvl1", BCObjectIdentifiers.sqisign_lvl1);
            addSignatureAlgorithm(provider, "sqisign_lvl3", PREFIX + "SignatureSpi$SQIsign_lvl3", BCObjectIdentifiers.sqisign_lvl3);
            addSignatureAlgorithm(provider, "sqisign_lvl5", PREFIX + "SignatureSpi$SQIsign_lvl5", BCObjectIdentifiers.sqisign_lvl5);
        }
    }
}
