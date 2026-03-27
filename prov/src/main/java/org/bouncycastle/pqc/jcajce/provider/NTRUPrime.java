package org.bouncycastle.pqc.jcajce.provider;

import org.bouncycastle.asn1.bc.BCObjectIdentifiers;
import org.bouncycastle.jcajce.provider.config.ConfigurableProvider;
import org.bouncycastle.jcajce.provider.util.AsymmetricAlgorithmProvider;
import org.bouncycastle.jcajce.provider.util.AsymmetricKeyInfoConverter;
import org.bouncycastle.jcajce.util.SpiUtil;
import org.bouncycastle.pqc.jcajce.provider.ntruprime.NTRULPRimeKeyFactorySpi;
import org.bouncycastle.pqc.jcajce.provider.ntruprime.SNTRUPrimeKeyFactorySpi;

public class NTRUPrime
{
    private static final String PREFIX = "org.bouncycastle.pqc.jcajce.provider" + ".ntruprime.";

    public static class Mappings
        extends AsymmetricAlgorithmProvider
    {
        public Mappings()
        {
        }

        public void configure(ConfigurableProvider provider)
        {
            provider.addAlgorithm("KeyFactory.NTRULPRIME", PREFIX + "NTRULPRimeKeyFactorySpi");
            provider.addAlgorithm("KeyPairGenerator.NTRULPRIME", PREFIX + "NTRULPRimeKeyPairGeneratorSpi");

            provider.addAlgorithm("KeyGenerator.NTRULPRIME", PREFIX + "NTRULPRimeKeyGeneratorSpi");

            AsymmetricKeyInfoConverter keyFact = new NTRULPRimeKeyFactorySpi();

            addCipherAlgorithm(provider, "NTRULPRIME", PREFIX + "NTRULPRimeCipherSpi$Base", BCObjectIdentifiers.pqc_kem_ntrulprime);

            registerOid(provider, BCObjectIdentifiers.ntrulpr653, "NTRULPRIME", keyFact);
            registerOid(provider, BCObjectIdentifiers.ntrulpr761, "NTRULPRIME", keyFact);
            registerOid(provider, BCObjectIdentifiers.ntrulpr857, "NTRULPRIME", keyFact);
            registerOid(provider, BCObjectIdentifiers.ntrulpr953, "NTRULPRIME", keyFact);
            registerOid(provider, BCObjectIdentifiers.ntrulpr1013, "NTRULPRIME", keyFact);
            registerOid(provider, BCObjectIdentifiers.ntrulpr1277, "NTRULPRIME", keyFact);

            provider.addAlgorithm("KeyFactory.SNTRUPRIME", PREFIX + "SNTRUPrimeKeyFactorySpi");
            provider.addAlgorithm("KeyPairGenerator.SNTRUPRIME", PREFIX + "SNTRUPrimeKeyPairGeneratorSpi");

            provider.addAlgorithm("KeyGenerator.SNTRUPRIME", PREFIX + "SNTRUPrimeKeyGeneratorSpi");

            keyFact = new SNTRUPrimeKeyFactorySpi();

            addCipherAlgorithm(provider, "SNTRUPRIME", PREFIX + "SNTRUPrimeCipherSpi$Base", BCObjectIdentifiers.pqc_kem_sntruprime);

            registerOid(provider, BCObjectIdentifiers.sntrup653, "SNTRUPRIME", keyFact);
            registerOid(provider, BCObjectIdentifiers.sntrup761, "SNTRUPRIME", keyFact);
            registerOid(provider, BCObjectIdentifiers.sntrup857, "SNTRUPRIME", keyFact);
            registerOid(provider, BCObjectIdentifiers.sntrup953, "SNTRUPRIME", keyFact);
            registerOid(provider, BCObjectIdentifiers.sntrup1013, "SNTRUPRIME", keyFact);
            registerOid(provider, BCObjectIdentifiers.sntrup1277, "SNTRUPRIME", keyFact);

            if (SpiUtil.hasKEM())
            {
                // TODO Per-parameter-set SPI classes?
                addKEMAlgorithm(provider, "SNTRUPRIME", PREFIX + "SNTRUPrimeKEMSpi$SNTRUPrime", BCObjectIdentifiers.pqc_kem_sntruprime);
            }
        }
    }
}
