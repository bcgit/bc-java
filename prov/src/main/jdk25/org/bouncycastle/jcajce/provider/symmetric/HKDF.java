package org.bouncycastle.jcajce.provider.symmetric;

import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.jcajce.provider.config.ConfigurableProvider;
import org.bouncycastle.jcajce.provider.util.AlgorithmProvider;

class HKDF
{
    private static final String PREFIX = "org.bouncycastle.jcajce.provider.symmetric" + ".hkdf.";

    public static class Mappings
            extends AlgorithmProvider
    {
        public Mappings()
        {
        }

        public void configure(ConfigurableProvider provider)
        {

            provider.addAlgorithm("KDF.HKDF", PREFIX + "HKDFSpi");
            provider.addAlgorithm("KDF.HKDF-SHA256", PREFIX + "HKDFSpi$HKDFwithSHA256");
            provider.addAlgorithm("KDF.HKDF-SHA384", PREFIX + "HKDFSpi$HKDFwithSHA384");
            provider.addAlgorithm("KDF.HKDF-SHA512", PREFIX + "HKDFSpi$HKDFwithSHA512");

            // Use SymmetricAlgorithmProvider?
            //TODO: add PKCSObjectIdentifiers?
            //PKCSObjectIdentifiers.id_alg_hkdf_with_sha256
            //PKCSObjectIdentifiers.id_alg_hkdf_with_sha384
            //PKCSObjectIdentifiers.id_alg_hkdf_with_sha512

        }
    }
}
