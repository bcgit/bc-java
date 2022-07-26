package org.bouncycastle.pqc.jcajce.provider;

import org.bouncycastle.asn1.bc.BCObjectIdentifiers;
import org.bouncycastle.jcajce.provider.config.ConfigurableProvider;
import org.bouncycastle.jcajce.provider.util.AsymmetricAlgorithmProvider;
import org.bouncycastle.jcajce.provider.util.AsymmetricKeyInfoConverter;
import org.bouncycastle.pqc.jcajce.provider.kyber.KyberKeyFactorySpi;

public class Kyber
{
    private static final String PREFIX = "org.bouncycastle.pqc.jcajce.provider" + ".kyber.";

    public static class Mappings
        extends AsymmetricAlgorithmProvider
    {
        public Mappings()
        {
        }

        public void configure(ConfigurableProvider provider)
        {
            provider.addAlgorithm("KeyFactory.KYBER", PREFIX + "KyberKeyFactorySpi");
            provider.addAlgorithm("KeyPairGenerator.KYBER", PREFIX + "KyberKeyPairGeneratorSpi");

            provider.addAlgorithm("KeyGenerator.KYBER", PREFIX + "KyberKeyGeneratorSpi");

            AsymmetricKeyInfoConverter keyFact = new KyberKeyFactorySpi();

            provider.addAlgorithm("Cipher.KYBER", PREFIX + "KyberCipherSpi$Base");
            provider.addAlgorithm("Alg.Alias.Cipher." + BCObjectIdentifiers.pqc_kem_kyber, "KYBER");

            registerOid(provider, BCObjectIdentifiers.pqc_kem_kyber, "Kyber", keyFact);
        }
    }
}
