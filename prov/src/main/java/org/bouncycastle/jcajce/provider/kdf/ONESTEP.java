package org.bouncycastle.jcajce.provider.kdf;

import org.bouncycastle.jcajce.provider.config.ConfigurableProvider;
import org.bouncycastle.jcajce.util.SpiUtil;

/**
 * javax.crypto.KDF services for the NIST SP 800-56C Rev. 2 Section 4.1 one-step key derivation function,
 * with the hash, HMAC and KMAC auxiliary functions: "ONESTEP-SHA256", "ONESTEP-SHA384", "ONESTEP-SHA512",
 * "ONESTEP-HMACSHA256", "ONESTEP-HMACSHA384", "ONESTEP-HMACSHA512", "ONESTEP-KMAC128" and "ONESTEP-KMAC256",
 * taking an {@link org.bouncycastle.jcajce.spec.OneStepKDFParameterSpec}.
 */
public class ONESTEP
{
    private static final String PREFIX = "org.bouncycastle.jcajce.provider.kdf" + ".onestep.";

    public static class Mappings
        extends KDFAlgorithmProvider
    {
        public Mappings()
        {
        }

        public void configure(ConfigurableProvider provider)
        {
            if (SpiUtil.hasKDF())
            {
                addKDFAlgorithm(provider, "ONESTEP-SHA256", PREFIX + "OneStepKDFSpi$WithSHA256");
                addKDFAlgorithm(provider, "ONESTEP-SHA384", PREFIX + "OneStepKDFSpi$WithSHA384");
                addKDFAlgorithm(provider, "ONESTEP-SHA512", PREFIX + "OneStepKDFSpi$WithSHA512");
                addKDFAlgorithm(provider, "ONESTEP-HMACSHA256", PREFIX + "OneStepKDFSpi$WithHMacSHA256");
                addKDFAlgorithm(provider, "ONESTEP-HMACSHA384", PREFIX + "OneStepKDFSpi$WithHMacSHA384");
                addKDFAlgorithm(provider, "ONESTEP-HMACSHA512", PREFIX + "OneStepKDFSpi$WithHMacSHA512");
                addKDFAlgorithm(provider, "ONESTEP-KMAC128", PREFIX + "OneStepKDFSpi$WithKMAC128");
                addKDFAlgorithm(provider, "ONESTEP-KMAC256", PREFIX + "OneStepKDFSpi$WithKMAC256");
            }
        }
    }
}
