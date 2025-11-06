package org.bouncycastle.jcajce.provider.symmetric;

import org.bouncycastle.jcajce.provider.config.ConfigurableProvider;
import org.bouncycastle.jcajce.provider.util.AlgorithmProvider;

class SCRYPT
{
    private static final String PREFIX = "org.bouncycastle.jcajce.provider.symmetric" + ".scrypt.";

    public static class Mappings
            extends AlgorithmProvider
    {
        public Mappings()
        {
        }

        public void configure(ConfigurableProvider provider)
        {
            provider.addAlgorithm("KDF.SCRYPT", PREFIX + "SCryptSpi$ScryptWithUTF8");
        }
    }
}
