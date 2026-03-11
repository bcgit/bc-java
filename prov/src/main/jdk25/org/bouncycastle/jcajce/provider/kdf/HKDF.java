package org.bouncycastle.jcajce.provider.kdf;

import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.jcajce.provider.config.ConfigurableProvider;

public class HKDF
{
    private static final String PREFIX = "org.bouncycastle.jcajce.provider.kdf" + ".hkdf.";

    public static class Mappings
        extends KDFAlgorithmProvider
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
//            addKDFAlgorithm(provider, "HKDF", PREFIX + "HKDFSpi");

            addKDFAlgorithm(provider, "HKDF-SHA256", PREFIX + "HKDFSpi$HKDFwithSHA256",
                PKCSObjectIdentifiers.id_alg_hkdf_with_sha256);
            addKDFAlgorithm(provider, "HKDF-SHA384", PREFIX + "HKDFSpi$HKDFwithSHA384",
                PKCSObjectIdentifiers.id_alg_hkdf_with_sha384);
            addKDFAlgorithm(provider, "HKDF-SHA512", PREFIX + "HKDFSpi$HKDFwithSHA512",
                PKCSObjectIdentifiers.id_alg_hkdf_with_sha512);
        }
    }
}
