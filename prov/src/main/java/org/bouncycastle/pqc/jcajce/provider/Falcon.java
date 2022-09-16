package org.bouncycastle.pqc.jcajce.provider;

import org.bouncycastle.asn1.bc.BCObjectIdentifiers;
import org.bouncycastle.jcajce.provider.config.ConfigurableProvider;
import org.bouncycastle.jcajce.provider.util.AsymmetricAlgorithmProvider;
import org.bouncycastle.jcajce.provider.util.AsymmetricKeyInfoConverter;
import org.bouncycastle.pqc.jcajce.provider.falcon.FalconKeyFactorySpi;

public class Falcon
{
    private static final String PREFIX = "org.bouncycastle.pqc.jcajce.provider" + ".falcon.";

    public static class Mappings
        extends AsymmetricAlgorithmProvider
    {
        public Mappings()
        {
        }

        public void configure(ConfigurableProvider provider)
        {
            provider.addAlgorithm("KeyFactory.FALCON", PREFIX + "FalconKeyFactorySpi");
            provider.addAlgorithm("KeyPairGenerator.FALCON", PREFIX + "FalconKeyPairGeneratorSpi");

            provider.addAlgorithm("KeyGenerator.FALCON", PREFIX + "FalconKeyGeneratorSpi");

            addSignatureAlgorithm(provider, "FALCON", PREFIX + "SignatureSpi$Base", BCObjectIdentifiers.falcon);

            addSignatureAlias(provider, "FALCON", BCObjectIdentifiers.falcon_512);
            addSignatureAlias(provider, "FALCON", BCObjectIdentifiers.falcon_1024);

            AsymmetricKeyInfoConverter keyFact = new FalconKeyFactorySpi();

            registerOid(provider, BCObjectIdentifiers.falcon_512, "FALCON", keyFact);
            registerOid(provider, BCObjectIdentifiers.falcon_1024, "FALCON", keyFact);
        }
    }
}
