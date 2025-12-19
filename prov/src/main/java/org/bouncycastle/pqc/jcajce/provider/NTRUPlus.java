package org.bouncycastle.pqc.jcajce.provider;

import org.bouncycastle.asn1.bc.BCObjectIdentifiers;
import org.bouncycastle.jcajce.provider.config.ConfigurableProvider;
import org.bouncycastle.jcajce.provider.util.AsymmetricAlgorithmProvider;
import org.bouncycastle.jcajce.provider.util.AsymmetricKeyInfoConverter;
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
            provider.addAlgorithm("Alg.Alias.KeyFactory.NTRUPLUS", "NTRUPLUS");
            addKeyFactoryAlgorithm(provider, "NTRU+KEM-768", PREFIX + "NTRUPlusKeyFactorySpi$NTRUPlus768", BCObjectIdentifiers.ntruPlus768, new NTRUPlusKeyFactorySpi.NTRUPlus768());
            addKeyFactoryAlgorithm(provider, "NTRU+KEM-864", PREFIX + "NTRUPlusKeyFactorySpi$NTRUPlus864", BCObjectIdentifiers.ntruPlus864,  new NTRUPlusKeyFactorySpi.NTRUPlus864());
            addKeyFactoryAlgorithm(provider, "NTRU+KEM-1152", PREFIX + "NTRUPlusKeyFactorySpi$NTRUPlus1152", BCObjectIdentifiers.ntruPlus1152,  new NTRUPlusKeyFactorySpi.NTRUPlus1152());

            provider.addAlgorithm("KeyPairGenerator.NTRUPLUS", PREFIX + "NTRUPlusKeyPairGeneratorSpi");
            provider.addAlgorithm("Alg.Alias.KeyPairGenerator.NTRUPLUS", "NTRUPLUS");
            addKeyPairGeneratorAlgorithm(provider, "NTRU+KEM-768", PREFIX + "NTRUPlusKeyPairGeneratorSpi$NTRUPlus768", BCObjectIdentifiers.ntruPlus768);
            addKeyPairGeneratorAlgorithm(provider, "NTRU+KEM-864", PREFIX + "NTRUPlusKeyPairGeneratorSpi$NTRUPlus864", BCObjectIdentifiers.ntruPlus864);
            addKeyPairGeneratorAlgorithm(provider, "NTRU+KEM-1152", PREFIX + "NTRUPlusKeyPairGeneratorSpi$NTRUPlus1152", BCObjectIdentifiers.ntruPlus1152);

            provider.addAlgorithm("KeyGenerator.NTRUPLUS", PREFIX + "NTRUPlusKeyGeneratorSpi");
            addKeyGeneratorAlgorithm(provider, "NTRU+KEM-768", PREFIX + "NTRUPLUSKeyGeneratorSpi$NTRUPLUS768", BCObjectIdentifiers.ntruPlus768);
            addKeyGeneratorAlgorithm(provider, "NTRU+KEM-864", PREFIX + "NTRUPLUSKeyGeneratorSpi$NTRUPLUS864", BCObjectIdentifiers.ntruPlus864);
            addKeyGeneratorAlgorithm(provider, "NTRU+KEM-1152", PREFIX + "NTRUPLUSKeyGeneratorSpi$NTRUPLUS1152", BCObjectIdentifiers.ntruPlus1152);

            AsymmetricKeyInfoConverter keyFact = new NTRUPlusKeyFactorySpi();

            provider.addAlgorithm("Cipher.NTRUPLUS", PREFIX + "NTRUPlusCipherSpi$Base");
            provider.addAlgorithm("Alg.Alias.Cipher.NTRUPLUS", "NTRUPLUS");
            provider.addAlgorithm("Alg.Alias.Cipher." + BCObjectIdentifiers.ntruPlus, "NTRUPLUS");

            addCipherAlgorithm(provider, "NTRU+KEM-768", PREFIX + "NTRUPLUSCipherSpi$NTRUPLUS768", BCObjectIdentifiers.ntruPlus768);
            addCipherAlgorithm(provider, "NTRU+KEM-864", PREFIX + "NTRUPLUSCipherSpi$NTRUPLUS864", BCObjectIdentifiers.ntruPlus864);
            addCipherAlgorithm(provider, "NTRU+KEM-1152", PREFIX + "NTRUPLUSCipherSpi$NTRUPLUS1152", BCObjectIdentifiers.ntruPlus1152);

            registerOid(provider, BCObjectIdentifiers.ntruPlus, "NTRUPLUS", keyFact);
            provider.addKeyInfoConverter(BCObjectIdentifiers.ntruPlus768, keyFact);
            provider.addKeyInfoConverter(BCObjectIdentifiers.ntruPlus864, keyFact);
            provider.addKeyInfoConverter(BCObjectIdentifiers.ntruPlus1152, keyFact);
        }
    }
}
