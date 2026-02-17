package org.bouncycastle.jcajce.provider.kdf;

import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.jcajce.provider.config.ConfigurableProvider;
import org.bouncycastle.jcajce.provider.util.AlgorithmProvider;

public class HKDF
{
    private static final String PREFIX = "org.bouncycastle.jcajce.provider.kdf" + ".hkdf.";

    public static class Mappings
        extends AlgorithmProvider
    {
        public Mappings()
        {
        }

        public void configure(ConfigurableProvider provider)
        {
            /*
             * TODO Would need HKDFSpi to be public, have a constructor from KDFParameters, and have some way to
             * decide which digest to use.
             */
//            provider.addAlgorithm("KDF.HKDF", PREFIX + "HKDFSpi");

            provider.addAlgorithm("KDF.HKDF-SHA256", PREFIX + "HKDFSpi$HKDFwithSHA256");
            provider.addAlgorithm("KDF.HKDF-SHA384", PREFIX + "HKDFSpi$HKDFwithSHA384");
            provider.addAlgorithm("KDF.HKDF-SHA512", PREFIX + "HKDFSpi$HKDFwithSHA512");

            provider.addAlgorithm("Alg.Alias.KDF." + PKCSObjectIdentifiers.id_alg_hkdf_with_sha256, "HKDF-SHA256");
            provider.addAlgorithm("Alg.Alias.KDF." + PKCSObjectIdentifiers.id_alg_hkdf_with_sha384, "HKDF-SHA384");
            provider.addAlgorithm("Alg.Alias.KDF." + PKCSObjectIdentifiers.id_alg_hkdf_with_sha512, "HKDF-SHA512");
        }
    }
}
