package org.bouncycastle.pqc.jcajce.provider;

import org.bouncycastle.asn1.bc.BCObjectIdentifiers;
import org.bouncycastle.jcajce.provider.config.ConfigurableProvider;
import org.bouncycastle.jcajce.provider.util.AsymmetricAlgorithmProvider;
import org.bouncycastle.pqc.jcajce.provider.faest.FaestKeyFactorySpi;

public class Faest
{
    private static final String PREFIX = "org.bouncycastle.pqc.jcajce.provider.faest.";

    public static class Mappings
        extends AsymmetricAlgorithmProvider
    {
        public Mappings()
        {
        }

        public void configure(ConfigurableProvider provider)
        {
            provider.addAlgorithm("KeyFactory.Faest", PREFIX + "FaestKeyFactorySpi");

            addKeyFactoryAlgorithm(provider, "FAEST_128S", PREFIX + "FaestKeyFactorySpi$FAEST_128S", BCObjectIdentifiers.faest_128s, new FaestKeyFactorySpi.FAEST_128S());
            addKeyFactoryAlgorithm(provider, "FAEST_128F", PREFIX + "FaestKeyFactorySpi$FAEST_128F", BCObjectIdentifiers.faest_128f, new FaestKeyFactorySpi.FAEST_128F());
            addKeyFactoryAlgorithm(provider, "FAEST_192S", PREFIX + "FaestKeyFactorySpi$FAEST_192S", BCObjectIdentifiers.faest_192s, new FaestKeyFactorySpi.FAEST_192S());
            addKeyFactoryAlgorithm(provider, "FAEST_192F", PREFIX + "FaestKeyFactorySpi$FAEST_192F", BCObjectIdentifiers.faest_192f, new FaestKeyFactorySpi.FAEST_192F());
            addKeyFactoryAlgorithm(provider, "FAEST_256S", PREFIX + "FaestKeyFactorySpi$FAEST_256S", BCObjectIdentifiers.faest_256s, new FaestKeyFactorySpi.FAEST_256S());
            addKeyFactoryAlgorithm(provider, "FAEST_256F", PREFIX + "FaestKeyFactorySpi$FAEST_256F", BCObjectIdentifiers.faest_256f, new FaestKeyFactorySpi.FAEST_256F());
            addKeyFactoryAlgorithm(provider, "FAEST_EM_128S", PREFIX + "FaestKeyFactorySpi$FAEST_EM_128S", BCObjectIdentifiers.faest_em_128s, new FaestKeyFactorySpi.FAEST_EM_128S());
            addKeyFactoryAlgorithm(provider, "FAEST_EM_128F", PREFIX + "FaestKeyFactorySpi$FAEST_EM_128F", BCObjectIdentifiers.faest_em_128f, new FaestKeyFactorySpi.FAEST_EM_128F());
            addKeyFactoryAlgorithm(provider, "FAEST_EM_192S", PREFIX + "FaestKeyFactorySpi$FAEST_EM_192S", BCObjectIdentifiers.faest_em_192s, new FaestKeyFactorySpi.FAEST_EM_192S());
            addKeyFactoryAlgorithm(provider, "FAEST_EM_192F", PREFIX + "FaestKeyFactorySpi$FAEST_EM_192F", BCObjectIdentifiers.faest_em_192f, new FaestKeyFactorySpi.FAEST_EM_192F());
            addKeyFactoryAlgorithm(provider, "FAEST_EM_256S", PREFIX + "FaestKeyFactorySpi$FAEST_EM_256S", BCObjectIdentifiers.faest_em_256s, new FaestKeyFactorySpi.FAEST_EM_256S());
            addKeyFactoryAlgorithm(provider, "FAEST_EM_256F", PREFIX + "FaestKeyFactorySpi$FAEST_EM_256F", BCObjectIdentifiers.faest_em_256f, new FaestKeyFactorySpi.FAEST_EM_256F());

            provider.addAlgorithm("KeyPairGenerator.Faest", PREFIX + "FaestKeyPairGeneratorSpi");

            addKeyPairGeneratorAlgorithm(provider, "FAEST_128S", PREFIX + "FaestKeyPairGeneratorSpi$FAEST_128S", BCObjectIdentifiers.faest_128s);
            addKeyPairGeneratorAlgorithm(provider, "FAEST_128F", PREFIX + "FaestKeyPairGeneratorSpi$FAEST_128F", BCObjectIdentifiers.faest_128f);
            addKeyPairGeneratorAlgorithm(provider, "FAEST_192S", PREFIX + "FaestKeyPairGeneratorSpi$FAEST_192S", BCObjectIdentifiers.faest_192s);
            addKeyPairGeneratorAlgorithm(provider, "FAEST_192F", PREFIX + "FaestKeyPairGeneratorSpi$FAEST_192F", BCObjectIdentifiers.faest_192f);
            addKeyPairGeneratorAlgorithm(provider, "FAEST_256S", PREFIX + "FaestKeyPairGeneratorSpi$FAEST_256S", BCObjectIdentifiers.faest_256s);
            addKeyPairGeneratorAlgorithm(provider, "FAEST_256F", PREFIX + "FaestKeyPairGeneratorSpi$FAEST_256F", BCObjectIdentifiers.faest_256f);
            addKeyPairGeneratorAlgorithm(provider, "FAEST_EM_128S", PREFIX + "FaestKeyPairGeneratorSpi$FAEST_EM_128S", BCObjectIdentifiers.faest_em_128s);
            addKeyPairGeneratorAlgorithm(provider, "FAEST_EM_128F", PREFIX + "FaestKeyPairGeneratorSpi$FAEST_EM_128F", BCObjectIdentifiers.faest_em_128f);
            addKeyPairGeneratorAlgorithm(provider, "FAEST_EM_192S", PREFIX + "FaestKeyPairGeneratorSpi$FAEST_EM_192S", BCObjectIdentifiers.faest_em_192s);
            addKeyPairGeneratorAlgorithm(provider, "FAEST_EM_192F", PREFIX + "FaestKeyPairGeneratorSpi$FAEST_EM_192F", BCObjectIdentifiers.faest_em_192f);
            addKeyPairGeneratorAlgorithm(provider, "FAEST_EM_256S", PREFIX + "FaestKeyPairGeneratorSpi$FAEST_EM_256S", BCObjectIdentifiers.faest_em_256s);
            addKeyPairGeneratorAlgorithm(provider, "FAEST_EM_256F", PREFIX + "FaestKeyPairGeneratorSpi$FAEST_EM_256F", BCObjectIdentifiers.faest_em_256f);

            addSignatureAlgorithm(provider, "Faest", PREFIX + "SignatureSpi$Base", BCObjectIdentifiers.faest);

            addSignatureAlgorithm(provider, "FAEST_128S", PREFIX + "SignatureSpi$FAEST_128S", BCObjectIdentifiers.faest_128s);
            addSignatureAlgorithm(provider, "FAEST_128F", PREFIX + "SignatureSpi$FAEST_128F", BCObjectIdentifiers.faest_128f);
            addSignatureAlgorithm(provider, "FAEST_192S", PREFIX + "SignatureSpi$FAEST_192S", BCObjectIdentifiers.faest_192s);
            addSignatureAlgorithm(provider, "FAEST_192F", PREFIX + "SignatureSpi$FAEST_192F", BCObjectIdentifiers.faest_192f);
            addSignatureAlgorithm(provider, "FAEST_256S", PREFIX + "SignatureSpi$FAEST_256S", BCObjectIdentifiers.faest_256s);
            addSignatureAlgorithm(provider, "FAEST_256F", PREFIX + "SignatureSpi$FAEST_256F", BCObjectIdentifiers.faest_256f);
            addSignatureAlgorithm(provider, "FAEST_EM_128S", PREFIX + "SignatureSpi$FAEST_EM_128S", BCObjectIdentifiers.faest_em_128s);
            addSignatureAlgorithm(provider, "FAEST_EM_128F", PREFIX + "SignatureSpi$FAEST_EM_128F", BCObjectIdentifiers.faest_em_128f);
            addSignatureAlgorithm(provider, "FAEST_EM_192S", PREFIX + "SignatureSpi$FAEST_EM_192S", BCObjectIdentifiers.faest_em_192s);
            addSignatureAlgorithm(provider, "FAEST_EM_192F", PREFIX + "SignatureSpi$FAEST_EM_192F", BCObjectIdentifiers.faest_em_192f);
            addSignatureAlgorithm(provider, "FAEST_EM_256S", PREFIX + "SignatureSpi$FAEST_EM_256S", BCObjectIdentifiers.faest_em_256s);
            addSignatureAlgorithm(provider, "FAEST_EM_256F", PREFIX + "SignatureSpi$FAEST_EM_256F", BCObjectIdentifiers.faest_em_256f);
        }
    }
}
