package org.bouncycastle.pqc.jcajce.provider;

import org.bouncycastle.asn1.bc.BCObjectIdentifiers;
import org.bouncycastle.jcajce.provider.config.ConfigurableProvider;
import org.bouncycastle.jcajce.provider.util.AsymmetricAlgorithmProvider;
import org.bouncycastle.pqc.jcajce.provider.mirath.MirathKeyFactorySpi;

public class Mirath
{
    private static final String PREFIX = "org.bouncycastle.pqc.jcajce.provider.mirath.";

    public static class Mappings
        extends AsymmetricAlgorithmProvider
    {
        public Mappings()
        {
        }

        public void configure(ConfigurableProvider provider)
        {
            provider.addAlgorithm("KeyFactory.Mirath", PREFIX + "MirathKeyFactorySpi");

            addKeyFactoryAlgorithm(provider, "Mirath_1a_fast", PREFIX + "MirathKeyFactorySpi$Mirath_1a_fast", BCObjectIdentifiers.mirath_1a_fast, new MirathKeyFactorySpi.Mirath1aFast());
            addKeyFactoryAlgorithm(provider, "Mirath_1a_short", PREFIX + "MirathKeyFactorySpi$Mirath_1a_short", BCObjectIdentifiers.mirath_1a_short, new MirathKeyFactorySpi.Mirath1aShort());
            addKeyFactoryAlgorithm(provider, "Mirath_1b_fast", PREFIX + "MirathKeyFactorySpi$Mirath_1b_fast", BCObjectIdentifiers.mirath_1b_fast, new MirathKeyFactorySpi.Mirath1bFast());
            addKeyFactoryAlgorithm(provider, "Mirath_1b_short", PREFIX + "MirathKeyFactorySpi$Mirath_1b_short", BCObjectIdentifiers.mirath_1b_short, new MirathKeyFactorySpi.Mirath1bShort());
            addKeyFactoryAlgorithm(provider, "Mirath_3a_fast", PREFIX + "MirathKeyFactorySpi$Mirath_3a_fast", BCObjectIdentifiers.mirath_3a_fast, new MirathKeyFactorySpi.Mirath3aFast());
            addKeyFactoryAlgorithm(provider, "Mirath_3a_short", PREFIX + "MirathKeyFactorySpi$Mirath_3a_short", BCObjectIdentifiers.mirath_3a_short, new MirathKeyFactorySpi.Mirath3aShort());
            addKeyFactoryAlgorithm(provider, "Mirath_3b_fast", PREFIX + "MirathKeyFactorySpi$Mirath_3b_fast", BCObjectIdentifiers.mirath_3b_fast, new MirathKeyFactorySpi.Mirath3bFast());
            addKeyFactoryAlgorithm(provider, "Mirath_3b_short", PREFIX + "MirathKeyFactorySpi$Mirath_3b_short", BCObjectIdentifiers.mirath_3b_short, new MirathKeyFactorySpi.Mirath3bShort());
            addKeyFactoryAlgorithm(provider, "Mirath_5a_fast", PREFIX + "MirathKeyFactorySpi$Mirath_5a_fast", BCObjectIdentifiers.mirath_5a_fast, new MirathKeyFactorySpi.Mirath5aFast());
            addKeyFactoryAlgorithm(provider, "Mirath_5a_short", PREFIX + "MirathKeyFactorySpi$Mirath_5a_short", BCObjectIdentifiers.mirath_5a_short, new MirathKeyFactorySpi.Mirath5aShort());
            addKeyFactoryAlgorithm(provider, "Mirath_5b_fast", PREFIX + "MirathKeyFactorySpi$Mirath_5b_fast", BCObjectIdentifiers.mirath_5b_fast, new MirathKeyFactorySpi.Mirath5bFast());
            addKeyFactoryAlgorithm(provider, "Mirath_5b_short", PREFIX + "MirathKeyFactorySpi$Mirath_5b_short", BCObjectIdentifiers.mirath_5b_short, new MirathKeyFactorySpi.Mirath5bShort());
            provider.addAlgorithm("KeyPairGenerator.Mirath", PREFIX + "MirathKeyPairGeneratorSpi");

            addKeyPairGeneratorAlgorithm(provider, "Mirath_1a_fast", PREFIX + "MirathKeyPairGeneratorSpi$Mirath_1a_fast", BCObjectIdentifiers.mirath_1a_fast);
            addKeyPairGeneratorAlgorithm(provider, "Mirath_1a_short", PREFIX + "MirathKeyPairGeneratorSpi$Mirath_1a_short", BCObjectIdentifiers.mirath_1a_short);
            addKeyPairGeneratorAlgorithm(provider, "Mirath_1b_fast", PREFIX + "MirathKeyPairGeneratorSpi$Mirath_1b_fast", BCObjectIdentifiers.mirath_1b_fast);
            addKeyPairGeneratorAlgorithm(provider, "Mirath_1b_short", PREFIX + "MirathKeyPairGeneratorSpi$Mirath_1b_short", BCObjectIdentifiers.mirath_1b_short);
            addKeyPairGeneratorAlgorithm(provider, "Mirath_3a_fast", PREFIX + "MirathKeyPairGeneratorSpi$Mirath_3a_fast", BCObjectIdentifiers.mirath_3a_fast);
            addKeyPairGeneratorAlgorithm(provider, "Mirath_3a_short", PREFIX + "MirathKeyPairGeneratorSpi$Mirath_3a_short", BCObjectIdentifiers.mirath_3a_short);
            addKeyPairGeneratorAlgorithm(provider, "Mirath_3b_fast", PREFIX + "MirathKeyPairGeneratorSpi$Mirath_3b_fast", BCObjectIdentifiers.mirath_3b_fast);
            addKeyPairGeneratorAlgorithm(provider, "Mirath_3b_short", PREFIX + "MirathKeyPairGeneratorSpi$Mirath_3b_short", BCObjectIdentifiers.mirath_3b_short);
            addKeyPairGeneratorAlgorithm(provider, "Mirath_5a_fast", PREFIX + "MirathKeyPairGeneratorSpi$Mirath_5a_fast", BCObjectIdentifiers.mirath_5a_fast);
            addKeyPairGeneratorAlgorithm(provider, "Mirath_5a_short", PREFIX + "MirathKeyPairGeneratorSpi$Mirath_5a_short", BCObjectIdentifiers.mirath_5a_short);
            addKeyPairGeneratorAlgorithm(provider, "Mirath_5b_fast", PREFIX + "MirathKeyPairGeneratorSpi$Mirath_5b_fast", BCObjectIdentifiers.mirath_5b_fast);
            addKeyPairGeneratorAlgorithm(provider, "Mirath_5b_short", PREFIX + "MirathKeyPairGeneratorSpi$Mirath_5b_short", BCObjectIdentifiers.mirath_5b_short);
            addSignatureAlgorithm(provider, "Mirath", PREFIX + "SignatureSpi$Base", BCObjectIdentifiers.mirath);

            addSignatureAlgorithm(provider, "Mirath_1a_fast", PREFIX + "SignatureSpi$Mirath_1a_fast", BCObjectIdentifiers.mirath_1a_fast);
            addSignatureAlgorithm(provider, "Mirath_1a_short", PREFIX + "SignatureSpi$Mirath_1a_short", BCObjectIdentifiers.mirath_1a_short);
            addSignatureAlgorithm(provider, "Mirath_1b_fast", PREFIX + "SignatureSpi$Mirath_1b_fast", BCObjectIdentifiers.mirath_1b_fast);
            addSignatureAlgorithm(provider, "Mirath_1b_short", PREFIX + "SignatureSpi$Mirath_1b_short", BCObjectIdentifiers.mirath_1b_short);
            addSignatureAlgorithm(provider, "Mirath_3a_fast", PREFIX + "SignatureSpi$Mirath_3a_fast", BCObjectIdentifiers.mirath_3a_fast);
            addSignatureAlgorithm(provider, "Mirath_3a_short", PREFIX + "SignatureSpi$Mirath_3a_short", BCObjectIdentifiers.mirath_3a_short);
            addSignatureAlgorithm(provider, "Mirath_3b_fast", PREFIX + "SignatureSpi$Mirath_3b_fast", BCObjectIdentifiers.mirath_3b_fast);
            addSignatureAlgorithm(provider, "Mirath_3b_short", PREFIX + "SignatureSpi$Mirath_3b_short", BCObjectIdentifiers.mirath_3b_short);
            addSignatureAlgorithm(provider, "Mirath_5a_fast", PREFIX + "SignatureSpi$Mirath_5a_fast", BCObjectIdentifiers.mirath_5a_fast);
            addSignatureAlgorithm(provider, "Mirath_5a_short", PREFIX + "SignatureSpi$Mirath_5a_short", BCObjectIdentifiers.mirath_5a_short);
            addSignatureAlgorithm(provider, "Mirath_5b_fast", PREFIX + "SignatureSpi$Mirath_5b_fast", BCObjectIdentifiers.mirath_5b_fast);
            addSignatureAlgorithm(provider, "Mirath_5b_short", PREFIX + "SignatureSpi$Mirath_5b_short", BCObjectIdentifiers.mirath_5b_short);
        }
    }
}
