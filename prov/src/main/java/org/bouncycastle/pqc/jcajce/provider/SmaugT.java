package org.bouncycastle.pqc.jcajce.provider;

import org.bouncycastle.asn1.bc.BCObjectIdentifiers;
import org.bouncycastle.jcajce.provider.config.ConfigurableProvider;
import org.bouncycastle.jcajce.provider.util.AsymmetricAlgorithmProvider;
import org.bouncycastle.jcajce.provider.util.AsymmetricKeyInfoConverter;
import org.bouncycastle.pqc.jcajce.provider.smaugt.SmaugTKeyFactorySpi;

public class SmaugT
{
    private static final String PREFIX = "org.bouncycastle.pqc.jcajce.provider" + ".smaugt.";

    public static class Mappings
        extends AsymmetricAlgorithmProvider
    {
        public Mappings()
        {
        }

        public void configure(ConfigurableProvider provider)
        {
            provider.addAlgorithm("KeyFactory.SMAUGT", PREFIX + "SmaugTKeyFactorySpi");
            provider.addAlgorithm("Alg.Alias.KeyFactory.SMAUG-T", "SMAUGT");
            addKeyFactoryAlgorithm(provider, "SMAUGT-MODE1", PREFIX + "SmaugTKeyFactorySpi$Mode1", BCObjectIdentifiers.smaugt_mode1, new SmaugTKeyFactorySpi.Mode1());
            addKeyFactoryAlgorithm(provider, "SMAUGT-MODE3", PREFIX + "SmaugTKeyFactorySpi$Mode3", BCObjectIdentifiers.smaugt_mode3, new SmaugTKeyFactorySpi.Mode3());
            addKeyFactoryAlgorithm(provider, "SMAUGT-MODE5", PREFIX + "SmaugTKeyFactorySpi$Mode5", BCObjectIdentifiers.smaugt_mode5, new SmaugTKeyFactorySpi.Mode5());
            addKeyFactoryAlgorithm(provider, "SMAUGT-MODET", PREFIX + "SmaugTKeyFactorySpi$ModeT", BCObjectIdentifiers.smaugt_modet, new SmaugTKeyFactorySpi.ModeT());

            provider.addAlgorithm("KeyPairGenerator.SMAUGT", PREFIX + "SmaugTKeyPairGeneratorSpi");
            provider.addAlgorithm("Alg.Alias.KeyPairGenerator.SMAUG-T", "SMAUGT");
            addKeyPairGeneratorAlgorithm(provider, "SMAUGT-MODE1", PREFIX + "SmaugTKeyPairGeneratorSpi$Mode1", BCObjectIdentifiers.smaugt_mode1);
            addKeyPairGeneratorAlgorithm(provider, "SMAUGT-MODE3", PREFIX + "SmaugTKeyPairGeneratorSpi$Mode3", BCObjectIdentifiers.smaugt_mode3);
            addKeyPairGeneratorAlgorithm(provider, "SMAUGT-MODE5", PREFIX + "SmaugTKeyPairGeneratorSpi$Mode5", BCObjectIdentifiers.smaugt_mode5);
            addKeyPairGeneratorAlgorithm(provider, "SMAUGT-MODET", PREFIX + "SmaugTKeyPairGeneratorSpi$ModeT", BCObjectIdentifiers.smaugt_modet);

            provider.addAlgorithm("KeyGenerator.SMAUGT", PREFIX + "SmaugTKeyGeneratorSpi");
            addKeyGeneratorAlgorithm(provider, "SMAUGT-MODE1", PREFIX + "SmaugTKeyGeneratorSpi$Mode1", BCObjectIdentifiers.smaugt_mode1);
            addKeyGeneratorAlgorithm(provider, "SMAUGT-MODE3", PREFIX + "SmaugTKeyGeneratorSpi$Mode3", BCObjectIdentifiers.smaugt_mode3);
            addKeyGeneratorAlgorithm(provider, "SMAUGT-MODE5", PREFIX + "SmaugTKeyGeneratorSpi$Mode5", BCObjectIdentifiers.smaugt_mode5);
            addKeyGeneratorAlgorithm(provider, "SMAUGT-MODET", PREFIX + "SmaugTKeyGeneratorSpi$ModeT", BCObjectIdentifiers.smaugt_modet);

            AsymmetricKeyInfoConverter keyFact = new SmaugTKeyFactorySpi();

            provider.addAlgorithm("Cipher.SMAUGT", PREFIX + "SmaugTCipherSpi$Base");
            provider.addAlgorithm("Alg.Alias.Cipher.SMAUG-T", "SMAUGT");
            provider.addAlgorithm("Alg.Alias.Cipher." + BCObjectIdentifiers.pqc_kem_smaugt, "SMAUGT");

            addCipherAlgorithm(provider, "SMAUGT-MODE1", PREFIX + "SmaugTCipherSpi$Mode1", BCObjectIdentifiers.smaugt_mode1);
            addCipherAlgorithm(provider, "SMAUGT-MODE3", PREFIX + "SmaugTCipherSpi$Mode3", BCObjectIdentifiers.smaugt_mode3);
            addCipherAlgorithm(provider, "SMAUGT-MODE5", PREFIX + "SmaugTCipherSpi$Mode5", BCObjectIdentifiers.smaugt_mode5);
            addCipherAlgorithm(provider, "SMAUGT-MODET", PREFIX + "SmaugTCipherSpi$ModeT", BCObjectIdentifiers.smaugt_modet);

            registerOid(provider, BCObjectIdentifiers.pqc_kem_smaugt, "SMAUGT", keyFact);
            provider.addKeyInfoConverter(BCObjectIdentifiers.smaugt_mode1, keyFact);
            provider.addKeyInfoConverter(BCObjectIdentifiers.smaugt_mode3, keyFact);
            provider.addKeyInfoConverter(BCObjectIdentifiers.smaugt_mode5, keyFact);
            provider.addKeyInfoConverter(BCObjectIdentifiers.smaugt_modet, keyFact);
        }
    }
}
