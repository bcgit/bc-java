package org.bouncycastle.jcajce.provider.kdf;

import org.bouncycastle.jcajce.provider.config.ConfigurableProvider;
import org.bouncycastle.jcajce.util.SpiUtil;

public class SCRYPT
{
    private static final String PREFIX = "org.bouncycastle.jcajce.provider.kdf" + ".scrypt.";

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
                addKDFAlgorithm(provider, "SCRYPT", PREFIX + "ScryptSpi$ScryptWithUTF8");
            }
        }
    }
}
