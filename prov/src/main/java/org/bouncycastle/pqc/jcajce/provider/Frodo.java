package org.bouncycastle.pqc.jcajce.provider;

import org.bouncycastle.asn1.bc.BCObjectIdentifiers;
import org.bouncycastle.jcajce.provider.config.ConfigurableProvider;
import org.bouncycastle.jcajce.provider.util.AsymmetricAlgorithmProvider;
import org.bouncycastle.jcajce.provider.util.AsymmetricKeyInfoConverter;
import org.bouncycastle.pqc.jcajce.provider.frodo.FrodoKeyFactorySpi;

public class Frodo
{
    private static final String PREFIX = "org.bouncycastle.pqc.jcajce.provider" + ".frodo.";

    public static class Mappings
        extends AsymmetricAlgorithmProvider
    {
        public Mappings()
        {
        }

        public void configure(ConfigurableProvider provider)
        {
            provider.addAlgorithm("KeyFactory.Frodo", PREFIX + "FrodoKeyFactorySpi");
            provider.addAlgorithm("KeyPairGenerator.Frodo", PREFIX + "FrodoKeyPairGeneratorSpi");

            provider.addAlgorithm("KeyGenerator.Frodo", PREFIX + "FrodoKeyGeneratorSpi");

            AsymmetricKeyInfoConverter keyFact = new FrodoKeyFactorySpi();

            provider.addAlgorithm("Cipher.Frodo", PREFIX + "FrodoCipherSpi$Base");
            provider.addAlgorithm("Alg.Alias.Cipher." + BCObjectIdentifiers.pqc_kem_frodo, "Frodo");

            registerOid(provider, BCObjectIdentifiers.pqc_kem_frodo, "Frodo", keyFact);
            registerOidAlgorithmParameters(provider, BCObjectIdentifiers.pqc_kem_frodo, "Frodo");
        }
    }
}
