package org.bouncycastle.pqc.jcajce.provider;

import org.bouncycastle.asn1.bc.BCObjectIdentifiers;
import org.bouncycastle.jcajce.provider.config.ConfigurableProvider;
import org.bouncycastle.jcajce.provider.util.AsymmetricAlgorithmProvider;
import org.bouncycastle.jcajce.provider.util.AsymmetricKeyInfoConverter;
import org.bouncycastle.pqc.jcajce.provider.sike.SIKEKeyFactorySpi;

public class SIKE
{
    private static final String PREFIX = "org.bouncycastle.pqc.jcajce.provider" + ".sike.";

    public static class Mappings
        extends AsymmetricAlgorithmProvider
    {
        public Mappings()
        {
        }

        public void configure(ConfigurableProvider provider)
        {
            provider.addAlgorithm("KeyFactory.SIKE", PREFIX + "SIKEKeyFactorySpi");
            provider.addAlgorithm("KeyPairGenerator.SIKE", PREFIX + "SIKEKeyPairGeneratorSpi");

            provider.addAlgorithm("KeyGenerator.SIKE", PREFIX + "SIKEKeyGeneratorSpi");

            AsymmetricKeyInfoConverter keyFact = new SIKEKeyFactorySpi();

            provider.addAlgorithm("Cipher.SIKE", PREFIX + "SIKECipherSpi$Base");
            provider.addAlgorithm("Alg.Alias.Cipher." + BCObjectIdentifiers.pqc_kem_sike, "SIKE");

            registerOid(provider, BCObjectIdentifiers.pqc_kem_sike, "SIKE", keyFact);
        }
    }
}
