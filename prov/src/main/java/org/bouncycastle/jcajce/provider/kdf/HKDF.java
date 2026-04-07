package org.bouncycastle.jcajce.provider.kdf;

import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.jcajce.provider.config.ConfigurableProvider;
import org.bouncycastle.jcajce.provider.util.AlgorithmProvider;
import org.bouncycastle.jcajce.util.SpiUtil;

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
            if (SpiUtil.hasKDF())
            {
                provider.addAlgorithm("KDF.HKDF-SHA256", PREFIX + "HKDFSpi$HKDFwithSHA256");
                provider.addAlgorithm("KDF.HKDF-SHA384", PREFIX + "HKDFSpi$HKDFwithSHA384");
                provider.addAlgorithm("KDF.HKDF-SHA512", PREFIX + "HKDFSpi$HKDFwithSHA512");
                provider.addAlgorithm("KDF", PKCSObjectIdentifiers.id_alg_hkdf_with_sha256, PREFIX + "HKDFSpi$HKDFwithSHA256");
                provider.addAlgorithm("KDF", PKCSObjectIdentifiers.id_alg_hkdf_with_sha384, PREFIX + "HKDFSpi$HKDFwithSHA384");
                provider.addAlgorithm("KDF", PKCSObjectIdentifiers.id_alg_hkdf_with_sha512, PREFIX + "HKDFSpi$HKDFwithSHA512");
            }
        }
    }
}
