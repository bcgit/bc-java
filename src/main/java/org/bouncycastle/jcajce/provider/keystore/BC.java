package org.bouncycastle.jcajce.provider.keystore;

import org.bouncycastle.jcajce.provider.config.ConfigurableProvider;
import org.bouncycastle.jcajce.provider.util.AsymmetricAlgorithmProvider;

public class BC
{
    private static final String PREFIX = "org.bouncycastle.jcajce.provider.keystore" + ".bc.";

    public static class Mappings
        extends AsymmetricAlgorithmProvider
    {
        public Mappings()
        {
        }

        public void configure(ConfigurableProvider provider)
        {
            provider.addAlgorithm("KeyStore.BKS", PREFIX + "BcKeyStoreSpi$Std");
            provider.addAlgorithm("KeyStore.BKS-V1", PREFIX + "BcKeyStoreSpi$Version1");
            provider.addAlgorithm("KeyStore.BouncyCastle", PREFIX + "BcKeyStoreSpi$BouncyCastleStore");
            provider.addAlgorithm("Alg.Alias.KeyStore.UBER", "BouncyCastle");
            provider.addAlgorithm("Alg.Alias.KeyStore.BOUNCYCASTLE", "BouncyCastle");
            provider.addAlgorithm("Alg.Alias.KeyStore.bouncycastle", "BouncyCastle");
        }
    }
}
