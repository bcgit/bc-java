package org.bouncycastle.jcajce.provider.kdf;

import org.bouncycastle.jcajce.provider.config.ConfigurableProvider;
import org.bouncycastle.jcajce.provider.util.AlgorithmProvider;

public class PBEPBKDF2
{
    private static final String PREFIX = "org.bouncycastle.jcajce.provider.kdf" + ".pbkdf2.";

    public static class Mappings
            extends AlgorithmProvider
    {
        public Mappings()
        {
        }

        public void configure(ConfigurableProvider provider)
        {
            // place holder for Java 25.
        }
    }
}
