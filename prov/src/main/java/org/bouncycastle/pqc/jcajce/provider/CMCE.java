package org.bouncycastle.pqc.jcajce.provider;

import org.bouncycastle.asn1.bc.BCObjectIdentifiers;
import org.bouncycastle.jcajce.provider.config.ConfigurableProvider;
import org.bouncycastle.jcajce.provider.util.AsymmetricAlgorithmProvider;
import org.bouncycastle.jcajce.provider.util.AsymmetricKeyInfoConverter;
import org.bouncycastle.pqc.jcajce.provider.cmce.CMCEKeyFactorySpi;

public class CMCE
{
    private static final String PREFIX = "org.bouncycastle.pqc.jcajce.provider" + ".cmce.";

    public static class Mappings
        extends AsymmetricAlgorithmProvider
    {
        public Mappings()
        {
        }

        public void configure(ConfigurableProvider provider)
        {
            provider.addAlgorithm("KeyFactory.CMCE", PREFIX + "CMCEKeyFactorySpi");
            provider.addAlgorithm("KeyPairGenerator.CMCE", PREFIX + "CMCEKeyPairGeneratorSpi");

            provider.addAlgorithm("KeyGenerator.CMCE", PREFIX + "CMCEKeyGeneratorSpi");

            AsymmetricKeyInfoConverter keyFact = new CMCEKeyFactorySpi();

            provider.addAlgorithm("Cipher.CMCE", PREFIX + "CMCECipherSpi$Base");
            provider.addAlgorithm("Alg.Alias.Cipher." + BCObjectIdentifiers.pqc_kem_mceliece, "CMCE");

            registerOid(provider, BCObjectIdentifiers.pqc_kem_mceliece, "CMCE", keyFact);
            registerOidAlgorithmParameters(provider, BCObjectIdentifiers.pqc_kem_mceliece, "CMCE");
        }
    }
}
