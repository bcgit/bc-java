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
            provider.addAlgorithm("KeyPairGenerator.HQC", PREFIX + "HQCKeyPairGeneratorSpi");

            provider.addAlgorithm("KeyGenerator.HQC", PREFIX + "HQCKeyGeneratorSpi");

            AsymmetricKeyInfoConverter keyFact = new HQCKeyFactorySpi();

            provider.addAlgorithm("Cipher.HQC", PREFIX + "HQCCipherSpi$Base");
            provider.addAlgorithm("Alg.Alias.Cipher." + BCObjectIdentifiers.pqc_kem_hqc, "HQC");

            registerOid(provider, BCObjectIdentifiers.pqc_kem_hqc, "HQC", keyFact);
        }
    }
}
