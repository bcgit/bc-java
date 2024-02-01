package org.bouncycastle.pqc.jcajce.provider;

import org.bouncycastle.asn1.bc.BCObjectIdentifiers;
import org.bouncycastle.jcajce.provider.config.ConfigurableProvider;
import org.bouncycastle.jcajce.provider.util.AsymmetricAlgorithmProvider;
import org.bouncycastle.jcajce.provider.util.AsymmetricKeyInfoConverter;
import org.bouncycastle.pqc.jcajce.provider.ntruprime.SNTRUPrimeKeyFactorySpi;

public class SNTRUPrime
{
    private static final String PREFIX = "org.bouncycastle.pqc.jcajce.provider" + ".sntru.";

    public static class Mappings
            extends AsymmetricAlgorithmProvider
    {
        public Mappings()
        {
        }

        public void configure(ConfigurableProvider provider)
        {
            provider.addAlgorithm("KeyFactory.SNTRUPRIME", PREFIX + "SNTRUPrimeKeyFactorySpi");
            provider.addAlgorithm("KeyPairGenerator.SNTRUPRIME", PREFIX + "SNTRUPrimeKeyPairGeneratorSpi");

            provider.addAlgorithm("KeyGenerator.SNTRUPRIME", PREFIX + "SNTRUPrimeKeyGeneratorSpi");
            provider.addAlgorithm("Alg.Alias.KeyGenerator." + BCObjectIdentifiers.pqc_kem_sntruprime, "SNTRUPRIME");
            provider.addAlgorithm("Alg.Alias.KeyGenerator." + BCObjectIdentifiers.sntrup653, "SNTRUPRIME");
            provider.addAlgorithm("Alg.Alias.KeyGenerator." + BCObjectIdentifiers.sntrup761, "SNTRUPRIME");
            provider.addAlgorithm("Alg.Alias.KeyGenerator." + BCObjectIdentifiers.sntrup857, "SNTRUPRIME");
            provider.addAlgorithm("Alg.Alias.KeyGenerator." + BCObjectIdentifiers.sntrup953, "SNTRUPRIME");
            provider.addAlgorithm("Alg.Alias.KeyGenerator." + BCObjectIdentifiers.sntrup1013, "SNTRUPRIME");
            provider.addAlgorithm("Alg.Alias.KeyGenerator." + BCObjectIdentifiers.sntrup1277, "SNTRUPRIME");

            AsymmetricKeyInfoConverter keyFact = new SNTRUPrimeKeyFactorySpi();

            provider.addAlgorithm("Kem.SNTRUPRIME", PREFIX + "NTRUCipherSpi$Base");
            provider.addAlgorithm("Alg.Alias.Kem." + BCObjectIdentifiers.pqc_kem_sntruprime, "SNTRUPRIME");

            //These two not needed? KEMSpi returns a Decapsulator/Encapsulator
            provider.addAlgorithm("Decapsulator.SNTRUPRIME", PREFIX + "NTRUCipherSpi$Base");
            provider.addAlgorithm("Alg.Alias.Decapsulator." + BCObjectIdentifiers.pqc_kem_sntruprime, "SNTRUPRIME");

            provider.addAlgorithm("Encapsulator.SNTRUPRIME", PREFIX + "NTRUCipherSpi$Base");
            provider.addAlgorithm("Alg.Alias.Encapsulator." + BCObjectIdentifiers.pqc_kem_sntruprime, "SNTRUPRIME");

            registerOid(provider, BCObjectIdentifiers.pqc_kem_sntruprime, "SNTRUPRIME", keyFact);
            registerOid(provider, BCObjectIdentifiers.sntrup653, "SNTRUPRIME", keyFact);
            registerOid(provider, BCObjectIdentifiers.sntrup761, "SNTRUPRIME", keyFact);
            registerOid(provider, BCObjectIdentifiers.sntrup857, "SNTRUPRIME", keyFact);
            registerOid(provider, BCObjectIdentifiers.sntrup953, "SNTRUPRIME", keyFact);
            registerOid(provider, BCObjectIdentifiers.sntrup1013, "SNTRUPRIME", keyFact);
            registerOid(provider, BCObjectIdentifiers.sntrup1277, "SNTRUPRIME", keyFact);
        }
    }
}
