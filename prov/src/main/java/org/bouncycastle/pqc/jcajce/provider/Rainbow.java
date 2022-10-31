package org.bouncycastle.pqc.jcajce.provider;

import org.bouncycastle.asn1.bc.BCObjectIdentifiers;
import org.bouncycastle.jcajce.provider.config.ConfigurableProvider;
import org.bouncycastle.jcajce.provider.util.AsymmetricAlgorithmProvider;
import org.bouncycastle.jcajce.provider.util.AsymmetricKeyInfoConverter;
import org.bouncycastle.pqc.jcajce.provider.rainbow.RainbowKeyFactorySpi;

public class Rainbow
{
    private static final String PREFIX = "org.bouncycastle.pqc.jcajce.provider" + ".rainbow.";

    public static class Mappings
        extends AsymmetricAlgorithmProvider
    {
        public Mappings()
        {
        }

        public void configure(ConfigurableProvider provider)
        {
            provider.addAlgorithm("KeyFactory.RAINBOW", PREFIX + "RainbowKeyFactorySpi");
            provider.addAlgorithm("KeyPairGenerator.RAINBOW", PREFIX + "RainbowKeyPairGeneratorSpi");

            addKeyPairGeneratorAlgorithm(provider, "RAINBOW-III-CLASSIC", PREFIX + "RainbowKeyPairGeneratorSpi$RainbowIIIclassic", BCObjectIdentifiers.rainbow_III_classic);
            addKeyPairGeneratorAlgorithm(provider, "RAINBOW-III-CIRCUMZENITHAL", PREFIX + "RainbowKeyPairGeneratorSpi$RainbowIIIcircum", BCObjectIdentifiers.rainbow_III_circumzenithal);
            addKeyPairGeneratorAlgorithm(provider, "RAINBOW-III-COMPRESSED", PREFIX + "RainbowKeyPairGeneratorSpi$RainbowIIIcomp", BCObjectIdentifiers.rainbow_III_compressed);
            addKeyPairGeneratorAlgorithm(provider, "RAINBOW-V-CLASSIC", PREFIX + "RainbowKeyPairGeneratorSpi$RainbowVclassic", BCObjectIdentifiers.rainbow_V_classic);
            addKeyPairGeneratorAlgorithm(provider, "RAINBOW-V-CIRCUMZENITHAL", PREFIX + "RainbowKeyPairGeneratorSpi$RainbowVcircum", BCObjectIdentifiers.rainbow_V_circumzenithal);
            addKeyPairGeneratorAlgorithm(provider, "RAINBOW-V-COMPRESSED", PREFIX + "RainbowKeyPairGeneratorSpi$RainbowVcomp", BCObjectIdentifiers.rainbow_V_compressed);

            addSignatureAlgorithm(provider, "RAINBOW", PREFIX + "SignatureSpi$Base", BCObjectIdentifiers.rainbow);

            addSignatureAlgorithm(provider, "RAINBOW-III-CLASSIC", PREFIX + "SignatureSpi$RainbowIIIclassic", BCObjectIdentifiers.rainbow_III_classic);
            addSignatureAlgorithm(provider, "RAINBOW-III-CIRCUMZENITHAL", PREFIX + "SignatureSpi$RainbowIIIcircum", BCObjectIdentifiers.rainbow_III_circumzenithal);
            addSignatureAlgorithm(provider, "RAINBOW-III-COMPRESSED", PREFIX + "SignatureSpi$RainbowIIIcomp", BCObjectIdentifiers.rainbow_III_compressed);
            addSignatureAlgorithm(provider, "RAINBOW-V-CLASSIC", PREFIX + "SignatureSpi$RainbowVclassic", BCObjectIdentifiers.rainbow_V_classic);
            addSignatureAlgorithm(provider, "RAINBOW-V-CIRCUMZENITHAL", PREFIX + "SignatureSpi$RainbowVcircum", BCObjectIdentifiers.rainbow_V_circumzenithal);
            addSignatureAlgorithm(provider, "RAINBOW-v-COMPRESSED", PREFIX + "SignatureSpi$RainbowVcomp", BCObjectIdentifiers.rainbow_V_compressed);

            AsymmetricKeyInfoConverter keyFact = new RainbowKeyFactorySpi();

            registerKeyFactoryOid(provider, BCObjectIdentifiers.rainbow_III_classic, "RAINBOW", keyFact);
            registerKeyFactoryOid(provider, BCObjectIdentifiers.rainbow_III_circumzenithal, "RAINBOW", keyFact);
            registerKeyFactoryOid(provider, BCObjectIdentifiers.rainbow_III_compressed, "RAINBOW", keyFact);
            registerKeyFactoryOid(provider, BCObjectIdentifiers.rainbow_V_classic, "RAINBOW", keyFact);
            registerKeyFactoryOid(provider, BCObjectIdentifiers.rainbow_V_circumzenithal, "RAINBOW", keyFact);
            registerKeyFactoryOid(provider, BCObjectIdentifiers.rainbow_V_compressed, "RAINBOW", keyFact);
        }
    }
}
