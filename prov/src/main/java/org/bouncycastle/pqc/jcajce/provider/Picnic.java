package org.bouncycastle.pqc.jcajce.provider;

import org.bouncycastle.asn1.bc.BCObjectIdentifiers;
import org.bouncycastle.jcajce.provider.config.ConfigurableProvider;
import org.bouncycastle.jcajce.provider.util.AsymmetricAlgorithmProvider;
import org.bouncycastle.jcajce.provider.util.AsymmetricKeyInfoConverter;
import org.bouncycastle.pqc.jcajce.provider.picnic.PicnicKeyFactorySpi;

public class Picnic
{
    private static final String PREFIX = "org.bouncycastle.pqc.jcajce.provider" + ".picnic.";

    public static class Mappings
            extends AsymmetricAlgorithmProvider
    {
        public Mappings()
        {
        }

        public void configure(ConfigurableProvider provider)
        {
            provider.addAlgorithm("KeyFactory.PICNIC", PREFIX + "PicnicKeyFactorySpi");
            provider.addAlgorithm("KeyPairGenerator.PICNIC", PREFIX + "PicnicKeyPairGeneratorSpi");

            addSignatureAlgorithm(provider, "PICNIC", PREFIX + "SignatureSpi$Base", BCObjectIdentifiers.picnic);

            provider.addAlgorithm("KeyGenerator.PICNIC", PREFIX + "PicnicKeyGeneratorSpi");

            AsymmetricKeyInfoConverter keyFact = new PicnicKeyFactorySpi();

            registerOid(provider, BCObjectIdentifiers.picnic, "Picnic", keyFact);
        }
    }
}
