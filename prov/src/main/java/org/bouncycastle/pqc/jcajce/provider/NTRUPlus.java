package org.bouncycastle.pqc.jcajce.provider;

import org.bouncycastle.asn1.bc.BCObjectIdentifiers;
import org.bouncycastle.jcajce.provider.config.ConfigurableProvider;
import org.bouncycastle.jcajce.provider.util.AsymmetricAlgorithmProvider;
import org.bouncycastle.pqc.jcajce.provider.ntruplus.NTRUPlusKeyFactorySpi;

public class NTRUPlus
{
    private static final String PREFIX = "org.bouncycastle.pqc.jcajce.provider" + ".ntruplus.";

    public static class Mappings
        extends AsymmetricAlgorithmProvider
    {
        public Mappings()
        {
        }

        public void configure(ConfigurableProvider provider)
        {
            provider.addAlgorithm("KeyFactory.NTRUPLUS", PREFIX + "NTRUPlusKeyFactorySpi");

            addKeyFactoryAlgorithm(provider, "NTRUPLUS-768", PREFIX + "NTRUPlusKeyFactorySpi$NTRUPlus768", BCObjectIdentifiers.ntruPlus768, new NTRUPlusKeyFactorySpi.NTRUPlus768());
            addKeyFactoryAlgorithm(provider, "NTRUPLUS-864", PREFIX + "NTRUPlusKeyFactorySpi$NTRUPlus864", BCObjectIdentifiers.ntruPlus864,  new NTRUPlusKeyFactorySpi.NTRUPlus864());
            addKeyFactoryAlgorithm(provider, "NTRUPLUS-1152", PREFIX + "NTRUPlusKeyFactorySpi$NTRUPlus1152", BCObjectIdentifiers.ntruPlus1152,  new NTRUPlusKeyFactorySpi.NTRUPlus864());

            provider.addAlgorithm("KeyPairGenerator.NTRUPLUS", PREFIX + "NTRUPlusKeyPairGeneratorSpi");

            addKeyPairGeneratorAlgorithm(provider, "NTRUPLUS-768", PREFIX + "NTRUPlusKeyPairGeneratorSpi$NTRUPlus768", BCObjectIdentifiers.ntruPlus768);
            addKeyPairGeneratorAlgorithm(provider, "NTRUPLUS-864", PREFIX + "NTRUPlusKeyPairGeneratorSpi$NTRUPlus864", BCObjectIdentifiers.ntruPlus864);
            addKeyPairGeneratorAlgorithm(provider, "NTRUPLUS-1152", PREFIX + "NTRUPlusKeyPairGeneratorSpi$NTRUPlus1152", BCObjectIdentifiers.ntruPlus1152);

            addSignatureAlgorithm(provider, "NTRUPLUS", PREFIX + "SignatureSpi$Base", BCObjectIdentifiers.ntruPlus);

            addSignatureAlgorithm(provider, "NTRUPLUS-768", PREFIX + "SignatureSpi$NTRUPlus768", BCObjectIdentifiers.ntruPlus768);
            addSignatureAlgorithm(provider, "NTRUPLUS-864", PREFIX + "SignatureSpi$NTRUPlus864", BCObjectIdentifiers.ntruPlus864);
            addSignatureAlgorithm(provider, "NTRUPLUS-1152", PREFIX + "SignatureSpi$NTRUPlus1152", BCObjectIdentifiers.ntruPlus1152);
        }
    }
}
