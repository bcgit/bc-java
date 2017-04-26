package org.bouncycastle.jcajce.provider.asymmetric;

import org.bouncycastle.asn1.cryptopro.CryptoProObjectIdentifiers;
import org.bouncycastle.asn1.rosstandart.RosstandartObjectIdentifiers;
import org.bouncycastle.jcajce.provider.asymmetric.ecgost.KeyFactorySpi;
import org.bouncycastle.jcajce.provider.config.ConfigurableProvider;
import org.bouncycastle.jcajce.provider.util.AsymmetricAlgorithmProvider;

public class ECGOST
{
    private static final String PREFIX = "org.bouncycastle.jcajce.provider.asymmetric" + ".ecgost.";

    public static class Mappings
        extends AsymmetricAlgorithmProvider
    {
        public Mappings()
        {
        }
        
        public void configure(ConfigurableProvider provider)
        {
            provider.addAlgorithm("KeyFactory.ECGOST3410", PREFIX + "KeyFactorySpi");
            provider.addAlgorithm("Alg.Alias.KeyFactory.GOST-3410-2001", "ECGOST3410");
            provider.addAlgorithm("Alg.Alias.KeyFactory.ECGOST-3410", "ECGOST3410");

            registerOid(provider, CryptoProObjectIdentifiers.gostR3410_2001, "ECGOST3410", new KeyFactorySpi());
            registerOidAlgorithmParameters(provider, CryptoProObjectIdentifiers.gostR3410_2001, "ECGOST3410");

            provider.addAlgorithm("KeyPairGenerator.ECGOST3410", PREFIX + "KeyPairGeneratorSpi");
            provider.addAlgorithm("Alg.Alias.KeyPairGenerator.ECGOST-3410", "ECGOST3410");
            provider.addAlgorithm("Alg.Alias.KeyPairGenerator.GOST-3410-2001", "ECGOST3410");

            provider.addAlgorithm("Signature.ECGOST3410", PREFIX + "SignatureSpi");
            provider.addAlgorithm("Alg.Alias.Signature.ECGOST-3410", "ECGOST3410");
            provider.addAlgorithm("Alg.Alias.Signature.GOST-3410-2001", "ECGOST3410");

            addSignatureAlgorithm(provider, "GOST3411", "ECGOST3410", PREFIX + "SignatureSpi", CryptoProObjectIdentifiers.gostR3411_94_with_gostR3410_2001);

            // ========= GOST34.10 2012

            provider.addAlgorithm("KeyFactory.ECGOST3410-2012", PREFIX + "KeyFactorySpi");
            provider.addAlgorithm("Alg.Alias.KeyFactory.GOST-3410-2012", "ECGOST3410-2012");
            provider.addAlgorithm("Alg.Alias.KeyFactory.ECGOST-3410-2012", "ECGOST3410-2012");

            registerOid(provider, RosstandartObjectIdentifiers.id_tc26_constants,
                    "ECGOST3410-2012",
                    new KeyFactorySpi());
            registerOidAlgorithmParameters(provider,
                    RosstandartObjectIdentifiers.id_tc26_constants, "ECGOST3410-2012");

            provider.addAlgorithm("KeyPairGenerator.ECGOST3410-2012", PREFIX + "KeyPairGeneratorSpi");
            provider.addAlgorithm("Alg.Alias.KeyPairGenerator.ECGOST3410-2012", "ECGOST3410-2012");
            provider.addAlgorithm("Alg.Alias.KeyPairGenerator.GOST-3410-2012", "ECGOST3410-2012");

            provider.addAlgorithm("Signature.ECGOST3410-2012-256", PREFIX + "ECGOST2012SignatureSpi256");
            provider.addAlgorithm("Alg.Alias.Signature.ECGOST3410-2012-256", "ECGOST3410-2012-256");
            provider.addAlgorithm("Alg.Alias.Signature.GOST-3410-2012-256", "ECGOST3410-2012-256");

            provider.addAlgorithm("Signature.ECGOST3410-2012-512", PREFIX + "ECGOST2012SignatureSpi512");
            provider.addAlgorithm("Alg.Alias.Signature.ECGOST3410-2012-512", "ECGOST3410-2012-512");
            provider.addAlgorithm("Alg.Alias.Signature.GOST-3410-2012-512", "ECGOST3410-2012-512");

            addSignatureAlgorithm(provider, "GOST3411-2012-256", "ECGOST3410-2012",
                    PREFIX + "ECGOST2012SignatureSpi256",
                    RosstandartObjectIdentifiers.id_tc26_gost_3411_12_256);

            addSignatureAlgorithm(provider, "GOST3411-2012-512", "ECGOST3410-2012",
                    PREFIX + "ECGOST2012SignatureSpi512",
                    RosstandartObjectIdentifiers.id_tc26_gost_3411_12_512);



        }
    }
}
