package org.bouncycastle.pqc.jcajce.provider;

import org.bouncycastle.asn1.bc.BCObjectIdentifiers;
import org.bouncycastle.jcajce.provider.config.ConfigurableProvider;
import org.bouncycastle.jcajce.provider.util.AsymmetricAlgorithmProvider;

public class XMSS
{
    private static final String PREFIX = "org.bouncycastle.pqc.jcajce.provider" + ".xmss.";

    public static class Mappings
        extends AsymmetricAlgorithmProvider
    {
        public Mappings()
        {
        }

        public void configure(ConfigurableProvider provider)
        {
            //provider.addAlgorithm("KeyFactory.XMSS", PREFIX + "XMSSKeyFactorySpi");
            provider.addAlgorithm("KeyPairGenerator.XMSS", PREFIX + "XMSSKeyPairGeneratorSpi");

            addSignatureAlgorithm(provider, "SHA256", "XMSS", PREFIX + "XMSSSignatureSpi$withSha256", BCObjectIdentifiers.xmss_with_SHA256);
            addSignatureAlgorithm(provider, "SHA3-256", "XMSS", PREFIX + "XMSSSignatureSpi$withSha3_256", BCObjectIdentifiers.xmss_with_SHA3_256);
            addSignatureAlgorithm(provider, "SHA512", "XMSS", PREFIX + "XMSSSignatureSpi$withSha512", BCObjectIdentifiers.xmss_with_SHA512);
            addSignatureAlgorithm(provider, "SHA3-512", "XMSS", PREFIX + "XMSSSignatureSpi$withSha3_512", BCObjectIdentifiers.xmss_with_SHA3_512);

            //provider.addAlgorithm("KeyFactory.XMSSMT", PREFIX + "XMSSMTKeyFactorySpi");
            provider.addAlgorithm("KeyPairGenerator.XMSSMT", PREFIX + "XMSSMTKeyPairGeneratorSpi");

            addSignatureAlgorithm(provider, "SHA256", "XMSSMT", PREFIX + "XMSSMTSignatureSpi$withSha256", BCObjectIdentifiers.xmss_mt_with_SHA256);
            addSignatureAlgorithm(provider, "SHA3-256", "XMSSMT", PREFIX + "XMSSMTSignatureSpi$withSha3_256", BCObjectIdentifiers.xmss_mt_with_SHA3_256);
            addSignatureAlgorithm(provider, "SHA512", "XMSSMT", PREFIX + "XMSSMTSignatureSpi$withSha512", BCObjectIdentifiers.xmss_mt_with_SHA512);
            addSignatureAlgorithm(provider, "SHA3-512", "XMSSMT", PREFIX + "XMSSMTSignatureSpi$withSha3_512", BCObjectIdentifiers.xmss_mt_with_SHA3_512);
        }
    }
}
