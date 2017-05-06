package org.bouncycastle.jcajce.provider.asymmetric;

import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.asn1.gm.GMObjectIdentifiers;
import org.bouncycastle.jcajce.provider.config.ConfigurableProvider;
import org.bouncycastle.jcajce.provider.util.AsymmetricAlgorithmProvider;

public class GM
{
    private static final String PREFIX = "org.bouncycastle.jcajce.provider.asymmetric" + ".ec.";

    private static final Map<String, String> generalSm2Attributes = new HashMap<String, String>();

    static
    {
        generalSm2Attributes.put("SupportedKeyClasses", "java.security.interfaces.ECPublicKey|java.security.interfaces.ECPrivateKey");
        generalSm2Attributes.put("SupportedKeyFormats", "PKCS#8|X.509");
    }

    public static class Mappings
        extends AsymmetricAlgorithmProvider
    {
        public Mappings()
        {
        }

        public void configure(ConfigurableProvider provider)
        {
            provider.addAlgorithm("Signature.SM3WITHSM2", PREFIX + "GMSignatureSpi$sm3WithSM2");
            provider.addAlgorithm("Alg.Alias.Signature." + GMObjectIdentifiers.sm2sign_with_sm3, "SM3WITHSM2");
        }
    }
}
