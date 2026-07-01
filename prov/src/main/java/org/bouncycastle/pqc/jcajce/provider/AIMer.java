package org.bouncycastle.pqc.jcajce.provider;

import org.bouncycastle.asn1.bc.BCObjectIdentifiers;
import org.bouncycastle.jcajce.provider.config.ConfigurableProvider;
import org.bouncycastle.jcajce.provider.util.AsymmetricAlgorithmProvider;
import org.bouncycastle.pqc.jcajce.provider.aimer.AIMerKeyFactorySpi;

public class AIMer
{
    private static final String PREFIX = "org.bouncycastle.pqc.jcajce.provider.aimer.";

    public static class Mappings
        extends AsymmetricAlgorithmProvider
    {
        public Mappings()
        {
        }

        public void configure(ConfigurableProvider provider)
        {
            provider.addAlgorithm("KeyFactory.AIMer", PREFIX + "AIMerKeyFactorySpi");

            addKeyFactoryAlgorithm(provider, "AIMer-128f", PREFIX + "AIMerKeyFactorySpi$AIMer_128f", BCObjectIdentifiers.aimer_128f, new AIMerKeyFactorySpi.AIMer_128f());
            addKeyFactoryAlgorithm(provider, "AIMer-128s", PREFIX + "AIMerKeyFactorySpi$AIMer_128s", BCObjectIdentifiers.aimer_128s, new AIMerKeyFactorySpi.AIMer_128s());
            addKeyFactoryAlgorithm(provider, "AIMer-192f", PREFIX + "AIMerKeyFactorySpi$AIMer_192f", BCObjectIdentifiers.aimer_192f, new AIMerKeyFactorySpi.AIMer_192f());
            addKeyFactoryAlgorithm(provider, "AIMer-192s", PREFIX + "AIMerKeyFactorySpi$AIMer_192s", BCObjectIdentifiers.aimer_192s, new AIMerKeyFactorySpi.AIMer_192s());
            addKeyFactoryAlgorithm(provider, "AIMer-256f", PREFIX + "AIMerKeyFactorySpi$AIMer_256f", BCObjectIdentifiers.aimer_256f, new AIMerKeyFactorySpi.AIMer_256f());
            addKeyFactoryAlgorithm(provider, "AIMer-256s", PREFIX + "AIMerKeyFactorySpi$AIMer_256s", BCObjectIdentifiers.aimer_256s, new AIMerKeyFactorySpi.AIMer_256s());

            provider.addAlgorithm("KeyPairGenerator.AIMer", PREFIX + "AIMerKeyPairGeneratorSpi");

            addKeyPairGeneratorAlgorithm(provider, "AIMer-128f", PREFIX + "AIMerKeyPairGeneratorSpi$AIMer_128f", BCObjectIdentifiers.aimer_128f);
            addKeyPairGeneratorAlgorithm(provider, "AIMer-128s", PREFIX + "AIMerKeyPairGeneratorSpi$AIMer_128s", BCObjectIdentifiers.aimer_128s);
            addKeyPairGeneratorAlgorithm(provider, "AIMer-192f", PREFIX + "AIMerKeyPairGeneratorSpi$AIMer_192f", BCObjectIdentifiers.aimer_192f);
            addKeyPairGeneratorAlgorithm(provider, "AIMer-192s", PREFIX + "AIMerKeyPairGeneratorSpi$AIMer_192s", BCObjectIdentifiers.aimer_192s);
            addKeyPairGeneratorAlgorithm(provider, "AIMer-256f", PREFIX + "AIMerKeyPairGeneratorSpi$AIMer_256f", BCObjectIdentifiers.aimer_256f);
            addKeyPairGeneratorAlgorithm(provider, "AIMer-256s", PREFIX + "AIMerKeyPairGeneratorSpi$AIMer_256s", BCObjectIdentifiers.aimer_256s);

            addSignatureAlgorithm(provider, "AIMer", PREFIX + "SignatureSpi$Base", BCObjectIdentifiers.aimer);

            addSignatureAlgorithm(provider, "AIMer-128f", PREFIX + "SignatureSpi$AIMer_128f", BCObjectIdentifiers.aimer_128f);
            addSignatureAlgorithm(provider, "AIMer-128s", PREFIX + "SignatureSpi$AIMer_128s", BCObjectIdentifiers.aimer_128s);
            addSignatureAlgorithm(provider, "AIMer-192f", PREFIX + "SignatureSpi$AIMer_192f", BCObjectIdentifiers.aimer_192f);
            addSignatureAlgorithm(provider, "AIMer-192s", PREFIX + "SignatureSpi$AIMer_192s", BCObjectIdentifiers.aimer_192s);
            addSignatureAlgorithm(provider, "AIMer-256f", PREFIX + "SignatureSpi$AIMer_256f", BCObjectIdentifiers.aimer_256f);
            addSignatureAlgorithm(provider, "AIMer-256s", PREFIX + "SignatureSpi$AIMer_256s", BCObjectIdentifiers.aimer_256s);
        }
    }
}

