package org.bouncycastle.jcajce.provider.kdf;

import org.bouncycastle.jcajce.provider.config.ConfigurableProvider;
import org.bouncycastle.jcajce.provider.util.AlgorithmProvider;

class SCRYPT
{
    private static final String PREFIX = "org.bouncycastle.jcajce.provider.kdf" + ".scrypt.";

    public static class Mappings
            extends AlgorithmProvider
    {
        public Mappings()
        {
        }

        public void configure(ConfigurableProvider provider)
        {
            provider.addAlgorithm("KDF.SCRYPT", PREFIX + "ScryptSpi$ScryptWithUTF8");
        }
    }
}
