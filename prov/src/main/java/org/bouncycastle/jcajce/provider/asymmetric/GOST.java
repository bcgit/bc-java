package org.bouncycastle.jcajce.provider.asymmetric;

import org.bouncycastle.asn1.cryptopro.CryptoProObjectIdentifiers;
import org.bouncycastle.jcajce.provider.asymmetric.gost.KeyFactorySpi;
import org.bouncycastle.jcajce.provider.config.ConfigurableProvider;
import org.bouncycastle.jcajce.provider.util.AsymmetricAlgorithmProvider;

public class GOST
{
    private static final String PREFIX = "org.bouncycastle.jcajce.provider.asymmetric" + ".gost.";

    public static class Mappings
        extends AsymmetricAlgorithmProvider
    {
        public Mappings()
        {
        }
        
        public void configure(ConfigurableProvider provider)
        {
            provider.addAlgorithm("KeyPairGenerator.GOST3410", PREFIX + "KeyPairGeneratorSpi");
            provider.addAlgorithm("Alg.Alias.KeyPairGenerator.GOST-3410", "GOST3410");
            provider.addAlgorithm("Alg.Alias.KeyPairGenerator.GOST-3410-94", "GOST3410");

            provider.addAlgorithm("KeyFactory.GOST3410", PREFIX + "KeyFactorySpi");
            provider.addAlgorithm("Alg.Alias.KeyFactory.GOST-3410", "GOST3410");
            provider.addAlgorithm("Alg.Alias.KeyFactory.GOST-3410-94", "GOST3410");


            provider.addAlgorithm("AlgorithmParameters.GOST3410", PREFIX + "AlgorithmParametersSpi");
            provider.addAlgorithm("AlgorithmParameterGenerator.GOST3410", PREFIX + "AlgorithmParameterGeneratorSpi");

            registerOid(provider, CryptoProObjectIdentifiers.gostR3410_94, "GOST3410", new KeyFactorySpi());
            registerOidAlgorithmParameterGenerator(provider, CryptoProObjectIdentifiers.gostR3410_94, "GOST3410");

            provider.addAlgorithm("Signature.GOST3410", PREFIX + "SignatureSpi");
            provider.addAlgorithm("Alg.Alias.Signature.GOST-3410", "GOST3410");
            provider.addAlgorithm("Alg.Alias.Signature.GOST-3410-94", "GOST3410");
            provider.addAlgorithm("Alg.Alias.Signature.GOST3411withGOST3410", "GOST3410");
            provider.addAlgorithm("Alg.Alias.Signature.GOST3411WITHGOST3410", "GOST3410");
            provider.addAlgorithm("Alg.Alias.Signature.GOST3411WithGOST3410", "GOST3410");
            provider.addAlgorithm("Alg.Alias.Signature." + CryptoProObjectIdentifiers.gostR3411_94_with_gostR3410_94, "GOST3410");


            provider.addAlgorithm("Alg.Alias.AlgorithmParameterGenerator.GOST-3410", "GOST3410");
            provider.addAlgorithm("Alg.Alias.AlgorithmParameters.GOST-3410", "GOST3410");
        }
    }
}
