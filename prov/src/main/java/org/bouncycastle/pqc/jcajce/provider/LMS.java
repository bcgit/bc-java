package org.bouncycastle.pqc.jcajce.provider;

import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.jcajce.provider.config.ConfigurableProvider;
import org.bouncycastle.jcajce.provider.util.AsymmetricAlgorithmProvider;

public class LMS
{
    private static final String PREFIX = "org.bouncycastle.pqc.jcajce.provider" + ".lms.";

    public static class Mappings
        extends AsymmetricAlgorithmProvider
    {
        public Mappings()
        {
        }

        public void configure(ConfigurableProvider provider)
        {
            provider.addAlgorithm("KeyFactory.LMS", PREFIX + "LMSKeyFactorySpi");
            provider.addAlgorithm("Alg.Alias.KeyFactory." + PKCSObjectIdentifiers.id_alg_hss_lms_hashsig, "LMS");

            provider.addAlgorithm("KeyPairGenerator.LMS", PREFIX + "LMSKeyPairGeneratorSpi");
            provider.addAlgorithm("Alg.Alias.KeyPairGenerator." + PKCSObjectIdentifiers.id_alg_hss_lms_hashsig, "LMS");

            provider.addAlgorithm("Signature.LMS", PREFIX + "LMSSignatureSpi$generic");
            provider.addAlgorithm("Alg.Alias.Signature." + PKCSObjectIdentifiers.id_alg_hss_lms_hashsig, "LMS");
        }
    }
}
