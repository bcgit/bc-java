package org.bouncycastle.pqc.jcajce.provider;

import org.bouncycastle.asn1.bc.BCObjectIdentifiers;
import org.bouncycastle.jcajce.provider.config.ConfigurableProvider;
import org.bouncycastle.jcajce.provider.util.AsymmetricAlgorithmProvider;
import org.bouncycastle.jcajce.provider.util.AsymmetricKeyInfoConverter;
import org.bouncycastle.pqc.jcajce.provider.ntru.NTRUKeyFactorySpi;

public class NTRU
{
    private static final String PREFIX = "org.bouncycastle.pqc.jcajce.provider" + ".ntru.";

    public static class Mappings
        extends AsymmetricAlgorithmProvider
    {
        public Mappings()
        {
        }

        public void configure(ConfigurableProvider provider)
        {
            provider.addAlgorithm("KeyFactory.NTRU", PREFIX + "NTRUKeyFactorySpi");
            provider.addAlgorithm("KeyPairGenerator.NTRU", PREFIX + "NTRUKeyPairGeneratorSpi");

            provider.addAlgorithm("KeyGenerator.NTRU", PREFIX + "NTRUKeyGeneratorSpi");
            provider.addAlgorithm("Alg.Alias.KeyGenerator." + BCObjectIdentifiers.pqc_kem_ntru, "NTRU");
            provider.addAlgorithm("Alg.Alias.KeyGenerator." + BCObjectIdentifiers.ntruhps2048509, "NTRU");
            provider.addAlgorithm("Alg.Alias.KeyGenerator." + BCObjectIdentifiers.ntruhps2048677, "NTRU");
            provider.addAlgorithm("Alg.Alias.KeyGenerator." + BCObjectIdentifiers.ntruhps4096821, "NTRU");
            provider.addAlgorithm("Alg.Alias.KeyGenerator." + BCObjectIdentifiers.ntruhrss701, "NTRU");

            AsymmetricKeyInfoConverter keyFact = new NTRUKeyFactorySpi();

            provider.addAlgorithm("Cipher.NTRU", PREFIX + "NTRUCipherSpi$Base");
            provider.addAlgorithm("Alg.Alias.Cipher." + BCObjectIdentifiers.pqc_kem_ntru, "NTRU");
            provider.addAlgorithm("Alg.Alias.Cipher." + BCObjectIdentifiers.ntruhps2048509, "NTRU");
            provider.addAlgorithm("Alg.Alias.Cipher." + BCObjectIdentifiers.ntruhps2048677, "NTRU");
            provider.addAlgorithm("Alg.Alias.Cipher." + BCObjectIdentifiers.ntruhps4096821, "NTRU");
            provider.addAlgorithm("Alg.Alias.Cipher." + BCObjectIdentifiers.ntruhrss701, "NTRU");

            registerOid(provider, BCObjectIdentifiers.pqc_kem_ntru, "NTRU", keyFact);
            registerOid(provider, BCObjectIdentifiers.ntruhps2048509, "NTRU", keyFact);
            registerOid(provider, BCObjectIdentifiers.ntruhps2048677, "NTRU", keyFact);
            registerOid(provider, BCObjectIdentifiers.ntruhps4096821, "NTRU", keyFact);
            registerOid(provider, BCObjectIdentifiers.ntruhrss701, "NTRU", keyFact);
        }
    }
}
