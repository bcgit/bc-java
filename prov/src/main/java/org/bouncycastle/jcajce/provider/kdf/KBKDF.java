package org.bouncycastle.jcajce.provider.kdf;

import org.bouncycastle.jcajce.provider.config.ConfigurableProvider;
import org.bouncycastle.jcajce.util.SpiUtil;

/**
 * javax.crypto.KDF services for the NIST SP 800-108 Rev. 1 key-based key derivation functions with an HMAC
 * PRF: "KBKDF-COUNTER-HMACSHA256", "KBKDF-FEEDBACK-HMACSHA256", "KBKDF-PIPELINE-HMACSHA256" (double-pipeline
 * iteration mode) and the SHA-384 and SHA-512 forms, taking a {@link org.bouncycastle.jcajce.spec.KBKDFParameterSpec}.
 */
public class KBKDF
{
    private static final String PREFIX = "org.bouncycastle.jcajce.provider.kdf" + ".kbkdf.";

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
                addKDFAlgorithm(provider, "KBKDF-COUNTER-HMACSHA256", PREFIX + "KBKDFSpi$CounterHMacSHA256");
                addKDFAlgorithm(provider, "KBKDF-COUNTER-HMACSHA384", PREFIX + "KBKDFSpi$CounterHMacSHA384");
                addKDFAlgorithm(provider, "KBKDF-COUNTER-HMACSHA512", PREFIX + "KBKDFSpi$CounterHMacSHA512");
                addKDFAlgorithm(provider, "KBKDF-FEEDBACK-HMACSHA256", PREFIX + "KBKDFSpi$FeedbackHMacSHA256");
                addKDFAlgorithm(provider, "KBKDF-FEEDBACK-HMACSHA384", PREFIX + "KBKDFSpi$FeedbackHMacSHA384");
                addKDFAlgorithm(provider, "KBKDF-FEEDBACK-HMACSHA512", PREFIX + "KBKDFSpi$FeedbackHMacSHA512");
                addKDFAlgorithm(provider, "KBKDF-PIPELINE-HMACSHA256", PREFIX + "KBKDFSpi$PipelineHMacSHA256");
                addKDFAlgorithm(provider, "KBKDF-PIPELINE-HMACSHA384", PREFIX + "KBKDFSpi$PipelineHMacSHA384");
                addKDFAlgorithm(provider, "KBKDF-PIPELINE-HMACSHA512", PREFIX + "KBKDFSpi$PipelineHMacSHA512");
            }
        }
    }
}
