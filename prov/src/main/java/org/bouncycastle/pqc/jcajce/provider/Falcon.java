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

            addKeyFactoryAlgorithm(provider, "FALCON-512", PREFIX + "FalconKeyFactorySpi$Falcon512", BCObjectIdentifiers.falcon_512, new FalconKeyFactorySpi.Falcon512());
            addKeyFactoryAlgorithm(provider, "FALCON-1024", PREFIX + "FalconKeyFactorySpi$Falcon1024", BCObjectIdentifiers.falcon_1024,  new FalconKeyFactorySpi.Falcon1024());

            provider.addAlgorithm("KeyPairGenerator.FALCON", PREFIX + "FalconKeyPairGeneratorSpi");

            addKeyPairGeneratorAlgorithm(provider, "FALCON-512", PREFIX + "FalconKeyPairGeneratorSpi$Falcon512", BCObjectIdentifiers.falcon_512);
            addKeyPairGeneratorAlgorithm(provider, "FALCON-1024", PREFIX + "FalconKeyPairGeneratorSpi$Falcon1024", BCObjectIdentifiers.falcon_1024);

            addSignatureAlgorithm(provider, "FALCON", PREFIX + "SignatureSpi$Base", BCObjectIdentifiers.falcon);

            addSignatureAlgorithm(provider, "FALCON-512", PREFIX + "SignatureSpi$Falcon512", BCObjectIdentifiers.falcon_512);
            addSignatureAlgorithm(provider, "FALCON-1024", PREFIX + "SignatureSpi$Falcon1024", BCObjectIdentifiers.falcon_1024);
        }
    }
}
