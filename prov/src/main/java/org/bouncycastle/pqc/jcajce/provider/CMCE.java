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

            addCipherAlgorithm(provider, "mceliece348864", PREFIX + "CMCECipherSpi$MCE348864", BCObjectIdentifiers.mceliece348864_r3);
            addCipherAlgorithm(provider, "mceliece460896", PREFIX + "CMCECipherSpi$MCE460896", BCObjectIdentifiers.mceliece460896_r3);
            addCipherAlgorithm(provider, "mceliece6688128", PREFIX + "CMCECipherSpi$MCE6688128", BCObjectIdentifiers.mceliece6688128_r3);
            addCipherAlgorithm(provider, "mceliece6960119", PREFIX + "CMCECipherSpi$MCE6960119", BCObjectIdentifiers.mceliece6960119_r3);
            addCipherAlgorithm(provider, "mceliece8192128", PREFIX + "CMCECipherSpi$MCE8192128", BCObjectIdentifiers.mceliece8192128_r3);

            registerOid(provider, BCObjectIdentifiers.pqc_kem_mceliece, "CMCE", keyFact);
            registerOidAlgorithmParameters(provider, BCObjectIdentifiers.pqc_kem_mceliece, "CMCE");
        }
    }
}
