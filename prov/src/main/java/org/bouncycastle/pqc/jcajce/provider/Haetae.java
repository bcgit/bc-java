package org.bouncycastle.pqc.jcajce.provider;

import org.bouncycastle.asn1.bc.BCObjectIdentifiers;
import org.bouncycastle.jcajce.provider.config.ConfigurableProvider;
import org.bouncycastle.jcajce.provider.util.AsymmetricAlgorithmProvider;
import org.bouncycastle.pqc.jcajce.provider.haetae.HaetaeKeyFactorySpi;

/**
 * BCPQC registration for HAETAE: {@link Mappings#configure} populates the
 * provider's KeyFactory, KeyPairGenerator and Signature service tables with
 * the unparameterised {@code "Haetae"} form plus per-parameter-set aliases
 * ({@code HAETAE-2} / {@code HAETAE-3} / {@code HAETAE-5}) and their OID
 * aliases.
 */
public class Haetae
{
    private static final String PREFIX = "org.bouncycastle.pqc.jcajce.provider.haetae.";

    public static class Mappings
        extends AsymmetricAlgorithmProvider
    {
        public Mappings()
        {
        }

        public void configure(ConfigurableProvider provider)
        {
            provider.addAlgorithm("KeyFactory.Haetae", PREFIX + "HaetaeKeyFactorySpi");

            addKeyFactoryAlgorithm(provider, "HAETAE-2", PREFIX + "HaetaeKeyFactorySpi$HAETAE2", BCObjectIdentifiers.haetae2, new HaetaeKeyFactorySpi.HAETAE2());
            addKeyFactoryAlgorithm(provider, "HAETAE-3", PREFIX + "HaetaeKeyFactorySpi$HAETAE3", BCObjectIdentifiers.haetae3, new HaetaeKeyFactorySpi.HAETAE3());
            addKeyFactoryAlgorithm(provider, "HAETAE-5", PREFIX + "HaetaeKeyFactorySpi$HAETAE5", BCObjectIdentifiers.haetae5, new HaetaeKeyFactorySpi.HAETAE5());

            provider.addAlgorithm("KeyPairGenerator.Haetae", PREFIX + "HaetaeKeyPairGeneratorSpi");

            addKeyPairGeneratorAlgorithm(provider, "HAETAE-2", PREFIX + "HaetaeKeyPairGeneratorSpi$HAETAE2", BCObjectIdentifiers.haetae2);
            addKeyPairGeneratorAlgorithm(provider, "HAETAE-3", PREFIX + "HaetaeKeyPairGeneratorSpi$HAETAE3", BCObjectIdentifiers.haetae3);
            addKeyPairGeneratorAlgorithm(provider, "HAETAE-5", PREFIX + "HaetaeKeyPairGeneratorSpi$HAETAE5", BCObjectIdentifiers.haetae5);

            addSignatureAlgorithm(provider, "Haetae", PREFIX + "SignatureSpi$Base", BCObjectIdentifiers.haetae);

            addSignatureAlgorithm(provider, "HAETAE-2", PREFIX + "SignatureSpi$HAETAE2", BCObjectIdentifiers.haetae2);
            addSignatureAlgorithm(provider, "HAETAE-3", PREFIX + "SignatureSpi$HAETAE3", BCObjectIdentifiers.haetae3);
            addSignatureAlgorithm(provider, "HAETAE-5", PREFIX + "SignatureSpi$HAETAE5", BCObjectIdentifiers.haetae5);
        }
    }
}
