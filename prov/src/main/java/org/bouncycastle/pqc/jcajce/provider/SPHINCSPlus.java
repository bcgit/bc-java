package org.bouncycastle.pqc.jcajce.provider;

import org.bouncycastle.asn1.bc.BCObjectIdentifiers;
import org.bouncycastle.jcajce.provider.config.ConfigurableProvider;
import org.bouncycastle.jcajce.provider.util.AsymmetricAlgorithmProvider;
import org.bouncycastle.jcajce.provider.util.AsymmetricKeyInfoConverter;
import org.bouncycastle.pqc.jcajce.provider.sphincsplus.SPHINCSPlusKeyFactorySpi;

public class SPHINCSPlus
{
    private static final String PREFIX = "org.bouncycastle.pqc.jcajce.provider" + ".sphincsplus.";

    public static class Mappings
        extends AsymmetricAlgorithmProvider
    {
        public Mappings()
        {
        }

        public void configure(ConfigurableProvider provider)
        {
            provider.addAlgorithm("KeyFactory.SPHINCSPLUS", PREFIX + "SPHINCSPlusKeyFactorySpi");
            provider.addAlgorithm("KeyPairGenerator.SPHINCSPLUS", PREFIX + "SPHINCSPlusKeyPairGeneratorSpi");
            provider.addAlgorithm("Alg.Alias.KeyFactory.SPHINCS+", "SPHINCSPLUS");
            provider.addAlgorithm("Alg.Alias.KeyPairGenerator.SPHINCS+", "SPHINCSPLUS");

            addKeyPairGeneratorAlgorithm(provider, "SPHINCS+-SHA2-128S", PREFIX + "SPHINCSPlusKeyPairGeneratorSpi$Sha2_128s", BCObjectIdentifiers.sphincsPlus_sha2_128s);
            addKeyPairGeneratorAlgorithm(provider, "SPHINCS+-SHA2-128F", PREFIX + "SPHINCSPlusKeyPairGeneratorSpi$Sha2_128f", BCObjectIdentifiers.sphincsPlus_sha2_128f);
            addKeyPairGeneratorAlgorithm(provider, "SPHINCS+-SHA2-192S", PREFIX + "SPHINCSPlusKeyPairGeneratorSpi$Sha2_192s", BCObjectIdentifiers.sphincsPlus_sha2_192s);
            addKeyPairGeneratorAlgorithm(provider, "SPHINCS+-SHA2-192F", PREFIX + "SPHINCSPlusKeyPairGeneratorSpi$Sha2_192f", BCObjectIdentifiers.sphincsPlus_sha2_192f);
            addKeyPairGeneratorAlgorithm(provider, "SPHINCS+-SHA2-256S", PREFIX + "SPHINCSPlusKeyPairGeneratorSpi$Sha2_256s", BCObjectIdentifiers.sphincsPlus_sha2_256s);
            addKeyPairGeneratorAlgorithm(provider, "SPHINCS+-SHA2-256F", PREFIX + "SPHINCSPlusKeyPairGeneratorSpi$Sha2_256f", BCObjectIdentifiers.sphincsPlus_sha2_256f);
                
            addKeyPairGeneratorAlgorithm(provider, "SPHINCS+-SHAKE-128S", PREFIX + "SPHINCSPlusKeyPairGeneratorSpi$Shake_128s", BCObjectIdentifiers.sphincsPlus_shake_128s);
            addKeyPairGeneratorAlgorithm(provider, "SPHINCS+-SHAKE-128F", PREFIX + "SPHINCSPlusKeyPairGeneratorSpi$Shake_128f", BCObjectIdentifiers.sphincsPlus_shake_128f);
            addKeyPairGeneratorAlgorithm(provider, "SPHINCS+-SHAKE-192S", PREFIX + "SPHINCSPlusKeyPairGeneratorSpi$Shake_192s", BCObjectIdentifiers.sphincsPlus_shake_192s);
            addKeyPairGeneratorAlgorithm(provider, "SPHINCS+-SHAKE-192F", PREFIX + "SPHINCSPlusKeyPairGeneratorSpi$Shake_192f", BCObjectIdentifiers.sphincsPlus_shake_192f);
            addKeyPairGeneratorAlgorithm(provider, "SPHINCS+-SHAKE-256S", PREFIX + "SPHINCSPlusKeyPairGeneratorSpi$Shake_256s", BCObjectIdentifiers.sphincsPlus_shake_256s);
            addKeyPairGeneratorAlgorithm(provider, "SPHINCS+-SHAKE-256F", PREFIX + "SPHINCSPlusKeyPairGeneratorSpi$Shake_256f", BCObjectIdentifiers.sphincsPlus_shake_256f);
            
            addSignatureAlgorithm(provider, "SPHINCSPLUS", PREFIX + "SignatureSpi$Direct", BCObjectIdentifiers.sphincsPlus);

            addSignatureAlias(provider, "SPHINCSPLUS", BCObjectIdentifiers.sphincsPlus_sha2_128s_r3);
            addSignatureAlias(provider, "SPHINCSPLUS", BCObjectIdentifiers.sphincsPlus_sha2_128f_r3);
            addSignatureAlias(provider, "SPHINCSPLUS", BCObjectIdentifiers.sphincsPlus_shake_128s_r3);
            addSignatureAlias(provider, "SPHINCSPLUS", BCObjectIdentifiers.sphincsPlus_shake_128f_r3);
            addSignatureAlias(provider, "SPHINCSPLUS", BCObjectIdentifiers.sphincsPlus_haraka_128s_r3);
            addSignatureAlias(provider, "SPHINCSPLUS", BCObjectIdentifiers.sphincsPlus_haraka_128f_r3);
            addSignatureAlias(provider, "SPHINCSPLUS", BCObjectIdentifiers.sphincsPlus_sha2_192s_r3);
            addSignatureAlias(provider, "SPHINCSPLUS", BCObjectIdentifiers.sphincsPlus_sha2_192f_r3);
            addSignatureAlias(provider, "SPHINCSPLUS", BCObjectIdentifiers.sphincsPlus_shake_192s_r3);
            addSignatureAlias(provider, "SPHINCSPLUS", BCObjectIdentifiers.sphincsPlus_shake_192f_r3);
            addSignatureAlias(provider, "SPHINCSPLUS", BCObjectIdentifiers.sphincsPlus_haraka_192s_r3);
            addSignatureAlias(provider, "SPHINCSPLUS", BCObjectIdentifiers.sphincsPlus_haraka_192f_r3);
            addSignatureAlias(provider, "SPHINCSPLUS", BCObjectIdentifiers.sphincsPlus_sha2_256s_r3);
            addSignatureAlias(provider, "SPHINCSPLUS", BCObjectIdentifiers.sphincsPlus_sha2_256f_r3);
            addSignatureAlias(provider, "SPHINCSPLUS", BCObjectIdentifiers.sphincsPlus_shake_256s_r3);
            addSignatureAlias(provider, "SPHINCSPLUS", BCObjectIdentifiers.sphincsPlus_shake_256f_r3);
            addSignatureAlias(provider, "SPHINCSPLUS", BCObjectIdentifiers.sphincsPlus_haraka_256s_r3);
            addSignatureAlias(provider, "SPHINCSPLUS", BCObjectIdentifiers.sphincsPlus_haraka_256f_r3);
            addSignatureAlias(provider, "SPHINCSPLUS", BCObjectIdentifiers.sphincsPlus_sha2_128s_r3_simple);
            addSignatureAlias(provider, "SPHINCSPLUS", BCObjectIdentifiers.sphincsPlus_sha2_128f_r3_simple);
            addSignatureAlias(provider, "SPHINCSPLUS", BCObjectIdentifiers.sphincsPlus_shake_128s_r3_simple);
            addSignatureAlias(provider, "SPHINCSPLUS", BCObjectIdentifiers.sphincsPlus_shake_128f_r3_simple);
            addSignatureAlias(provider, "SPHINCSPLUS", BCObjectIdentifiers.sphincsPlus_haraka_128s_r3_simple);
            addSignatureAlias(provider, "SPHINCSPLUS", BCObjectIdentifiers.sphincsPlus_haraka_128f_r3_simple);
            addSignatureAlias(provider, "SPHINCSPLUS", BCObjectIdentifiers.sphincsPlus_sha2_192s_r3_simple);
            addSignatureAlias(provider, "SPHINCSPLUS", BCObjectIdentifiers.sphincsPlus_sha2_192f_r3_simple);
            addSignatureAlias(provider, "SPHINCSPLUS", BCObjectIdentifiers.sphincsPlus_shake_192s_r3_simple);
            addSignatureAlias(provider, "SPHINCSPLUS", BCObjectIdentifiers.sphincsPlus_shake_192f_r3_simple);
            addSignatureAlias(provider, "SPHINCSPLUS", BCObjectIdentifiers.sphincsPlus_haraka_192s_r3_simple);
            addSignatureAlias(provider, "SPHINCSPLUS", BCObjectIdentifiers.sphincsPlus_haraka_192f_r3_simple);
            addSignatureAlias(provider, "SPHINCSPLUS", BCObjectIdentifiers.sphincsPlus_sha2_256s_r3_simple);
            addSignatureAlias(provider, "SPHINCSPLUS", BCObjectIdentifiers.sphincsPlus_sha2_256f_r3_simple);
            addSignatureAlias(provider, "SPHINCSPLUS", BCObjectIdentifiers.sphincsPlus_shake_256s_r3_simple);
            addSignatureAlias(provider, "SPHINCSPLUS", BCObjectIdentifiers.sphincsPlus_shake_256f_r3_simple);
            addSignatureAlias(provider, "SPHINCSPLUS", BCObjectIdentifiers.sphincsPlus_haraka_256s_r3_simple);
            addSignatureAlias(provider, "SPHINCSPLUS", BCObjectIdentifiers.sphincsPlus_haraka_256f_r3_simple);

            provider.addAlgorithm("Alg.Alias.Signature.SPHINCS+", "SPHINCSPLUS");

            AsymmetricKeyInfoConverter keyFact = new SPHINCSPlusKeyFactorySpi();

            registerKeyFactoryOid(provider, BCObjectIdentifiers.sphincsPlus, "SPHINCSPLUS", keyFact);
            registerKeyFactoryOid(provider, BCObjectIdentifiers.sphincsPlus_sha2_128s_r3, "SPHINCSPLUS", keyFact);
            registerKeyFactoryOid(provider, BCObjectIdentifiers.sphincsPlus_sha2_128f_r3, "SPHINCSPLUS", keyFact);
            registerKeyFactoryOid(provider, BCObjectIdentifiers.sphincsPlus_shake_128s_r3, "SPHINCSPLUS", keyFact);
            registerKeyFactoryOid(provider, BCObjectIdentifiers.sphincsPlus_shake_128f_r3, "SPHINCSPLUS", keyFact);
            registerKeyFactoryOid(provider, BCObjectIdentifiers.sphincsPlus_haraka_128s_r3, "SPHINCSPLUS", keyFact);
            registerKeyFactoryOid(provider, BCObjectIdentifiers.sphincsPlus_haraka_128f_r3, "SPHINCSPLUS", keyFact);
            registerKeyFactoryOid(provider, BCObjectIdentifiers.sphincsPlus_sha2_192s_r3, "SPHINCSPLUS", keyFact);
            registerKeyFactoryOid(provider, BCObjectIdentifiers.sphincsPlus_sha2_192f_r3, "SPHINCSPLUS", keyFact);
            registerKeyFactoryOid(provider, BCObjectIdentifiers.sphincsPlus_shake_192s_r3, "SPHINCSPLUS", keyFact);
            registerKeyFactoryOid(provider, BCObjectIdentifiers.sphincsPlus_shake_192f_r3, "SPHINCSPLUS", keyFact);
            registerKeyFactoryOid(provider, BCObjectIdentifiers.sphincsPlus_haraka_192s_r3, "SPHINCSPLUS", keyFact);
            registerKeyFactoryOid(provider, BCObjectIdentifiers.sphincsPlus_haraka_192f_r3, "SPHINCSPLUS", keyFact);
            registerKeyFactoryOid(provider, BCObjectIdentifiers.sphincsPlus_sha2_256s_r3, "SPHINCSPLUS", keyFact);
            registerKeyFactoryOid(provider, BCObjectIdentifiers.sphincsPlus_sha2_256f_r3, "SPHINCSPLUS", keyFact);
            registerKeyFactoryOid(provider, BCObjectIdentifiers.sphincsPlus_shake_256s_r3, "SPHINCSPLUS", keyFact);
            registerKeyFactoryOid(provider, BCObjectIdentifiers.sphincsPlus_shake_256f_r3, "SPHINCSPLUS", keyFact);
            registerKeyFactoryOid(provider, BCObjectIdentifiers.sphincsPlus_haraka_256s_r3, "SPHINCSPLUS", keyFact);
            registerKeyFactoryOid(provider, BCObjectIdentifiers.sphincsPlus_haraka_256f_r3, "SPHINCSPLUS", keyFact);
            registerKeyFactoryOid(provider, BCObjectIdentifiers.sphincsPlus_sha2_128s_r3_simple, "SPHINCSPLUS", keyFact);
            registerKeyFactoryOid(provider, BCObjectIdentifiers.sphincsPlus_sha2_128f_r3_simple, "SPHINCSPLUS", keyFact);
            registerKeyFactoryOid(provider, BCObjectIdentifiers.sphincsPlus_shake_128s_r3_simple, "SPHINCSPLUS", keyFact);
            registerKeyFactoryOid(provider, BCObjectIdentifiers.sphincsPlus_shake_128f_r3_simple, "SPHINCSPLUS", keyFact);
            registerKeyFactoryOid(provider, BCObjectIdentifiers.sphincsPlus_haraka_128s_r3_simple, "SPHINCSPLUS", keyFact);
            registerKeyFactoryOid(provider, BCObjectIdentifiers.sphincsPlus_haraka_128f_r3_simple, "SPHINCSPLUS", keyFact);
            registerKeyFactoryOid(provider, BCObjectIdentifiers.sphincsPlus_sha2_192s_r3_simple, "SPHINCSPLUS", keyFact);
            registerKeyFactoryOid(provider, BCObjectIdentifiers.sphincsPlus_sha2_192f_r3_simple, "SPHINCSPLUS", keyFact);
            registerKeyFactoryOid(provider, BCObjectIdentifiers.sphincsPlus_shake_192s_r3_simple, "SPHINCSPLUS", keyFact);
            registerKeyFactoryOid(provider, BCObjectIdentifiers.sphincsPlus_shake_192f_r3_simple, "SPHINCSPLUS", keyFact);
            registerKeyFactoryOid(provider, BCObjectIdentifiers.sphincsPlus_haraka_192s_r3_simple, "SPHINCSPLUS", keyFact);
            registerKeyFactoryOid(provider, BCObjectIdentifiers.sphincsPlus_haraka_192f_r3_simple, "SPHINCSPLUS", keyFact);
            registerKeyFactoryOid(provider, BCObjectIdentifiers.sphincsPlus_sha2_256s_r3_simple, "SPHINCSPLUS", keyFact);
            registerKeyFactoryOid(provider, BCObjectIdentifiers.sphincsPlus_sha2_256f_r3_simple, "SPHINCSPLUS", keyFact);
            registerKeyFactoryOid(provider, BCObjectIdentifiers.sphincsPlus_shake_256s_r3_simple, "SPHINCSPLUS", keyFact);
            registerKeyFactoryOid(provider, BCObjectIdentifiers.sphincsPlus_shake_256f_r3_simple, "SPHINCSPLUS", keyFact);
            registerKeyFactoryOid(provider, BCObjectIdentifiers.sphincsPlus_haraka_256s_r3_simple, "SPHINCSPLUS", keyFact);
            registerKeyFactoryOid(provider, BCObjectIdentifiers.sphincsPlus_haraka_256f_r3_simple, "SPHINCSPLUS", keyFact);
        }
    }
}
