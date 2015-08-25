package org.bouncycastle.jcajce.provider.symmetric;

import org.bouncycastle.jcajce.provider.config.ConfigurableProvider;
import org.bouncycastle.jcajce.provider.util.AlgorithmProvider;

abstract class SymmetricAlgorithmProvider
    extends AlgorithmProvider
{
    protected void addCMacAlgorithm(
        ConfigurableProvider provider,
        String algorithm,
        String algorithmClassName,
        String keyGeneratorClassName)
    {
        provider.addAlgorithm("Mac." + algorithm + "-CMAC", algorithmClassName);
        provider.addAlgorithm("Alg.Alias.Mac." + algorithm + "CMAC", algorithm + "-CMAC");

        provider.addAlgorithm("KeyGenerator." + algorithm + "-CMAC", keyGeneratorClassName);
        provider.addAlgorithm("Alg.Alias.KeyGenerator." + algorithm + "CMAC",  algorithm + "-CMAC");
    }

    protected void addGMacAlgorithm(
        ConfigurableProvider provider,
        String algorithm,
        String algorithmClassName,
        String keyGeneratorClassName)
    {
        provider.addAlgorithm("Mac." + algorithm + "-GMAC", algorithmClassName);
        provider.addAlgorithm("Alg.Alias.Mac." + algorithm + "GMAC", algorithm + "-GMAC");

        provider.addAlgorithm("KeyGenerator." + algorithm + "-GMAC", keyGeneratorClassName);
        provider.addAlgorithm("Alg.Alias.KeyGenerator." + algorithm + "GMAC",  algorithm + "-GMAC");
    }

    protected void addPoly1305Algorithm(ConfigurableProvider provider,
                                        String algorithm,
                                        String algorithmClassName,
                                        String keyGeneratorClassName)
    {
        provider.addAlgorithm("Mac.POLY1305-" + algorithm, algorithmClassName);
        provider.addAlgorithm("Alg.Alias.Mac.POLY1305" + algorithm, "POLY1305-" + algorithm);

        provider.addAlgorithm("KeyGenerator.POLY1305-" + algorithm, keyGeneratorClassName);
        provider.addAlgorithm("Alg.Alias.KeyGenerator.POLY1305" + algorithm, "POLY1305-" + algorithm);
    }

}
