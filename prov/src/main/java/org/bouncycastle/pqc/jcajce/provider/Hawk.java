package org.bouncycastle.pqc.jcajce.provider;

import org.bouncycastle.asn1.bc.BCObjectIdentifiers;
import org.bouncycastle.jcajce.provider.config.ConfigurableProvider;
import org.bouncycastle.jcajce.provider.util.AsymmetricAlgorithmProvider;
import org.bouncycastle.pqc.jcajce.provider.hawk.HawkKeyFactorySpi;

/**
 * BCPQC registration for Hawk: {@link Mappings#configure} populates the
 * provider's KeyFactory, KeyPairGenerator and Signature service tables with
 * the unparameterised {@code "Hawk"} form plus per-parameter-set aliases
 * ({@code HAWK-256} / {@code HAWK-512} / {@code HAWK-1024}) and their OID
 * aliases.
 */
public class Hawk
{
    private static final String PREFIX = "org.bouncycastle.pqc.jcajce.provider.hawk.";

    public static class Mappings
        extends AsymmetricAlgorithmProvider
    {
        public Mappings()
        {
        }

        public void configure(ConfigurableProvider provider)
        {
            provider.addAlgorithm("KeyFactory.Hawk", PREFIX + "HawkKeyFactorySpi");

            addKeyFactoryAlgorithm(provider, "HAWK-256", PREFIX + "HawkKeyFactorySpi$HAWK_256", BCObjectIdentifiers.hawk256, new HawkKeyFactorySpi.HAWK_256());
            addKeyFactoryAlgorithm(provider, "HAWK-512", PREFIX + "HawkKeyFactorySpi$HAWK_512", BCObjectIdentifiers.hawk512, new HawkKeyFactorySpi.HAWK_512());
            addKeyFactoryAlgorithm(provider, "HAWK-1024", PREFIX + "HawkKeyFactorySpi$HAWK_1024", BCObjectIdentifiers.hawk1024, new HawkKeyFactorySpi.HAWK_1024());

            provider.addAlgorithm("KeyPairGenerator.Hawk", PREFIX + "HawkKeyPairGeneratorSpi");

            addKeyPairGeneratorAlgorithm(provider, "HAWK-256", PREFIX + "HawkKeyPairGeneratorSpi$HAWK_256", BCObjectIdentifiers.hawk256);
            addKeyPairGeneratorAlgorithm(provider, "HAWK-512", PREFIX + "HawkKeyPairGeneratorSpi$HAWK_512", BCObjectIdentifiers.hawk512);
            addKeyPairGeneratorAlgorithm(provider, "HAWK-1024", PREFIX + "HawkKeyPairGeneratorSpi$HAWK_1024", BCObjectIdentifiers.hawk1024);

            addSignatureAlgorithm(provider, "Hawk", PREFIX + "SignatureSpi$Base", BCObjectIdentifiers.hawk);

            addSignatureAlgorithm(provider, "HAWK-256", PREFIX + "SignatureSpi$HAWK_256", BCObjectIdentifiers.hawk256);
            addSignatureAlgorithm(provider, "HAWK-512", PREFIX + "SignatureSpi$HAWK_512", BCObjectIdentifiers.hawk512);
            addSignatureAlgorithm(provider, "HAWK-1024", PREFIX + "SignatureSpi$HAWK_1024", BCObjectIdentifiers.hawk1024);
        }
    }
}
