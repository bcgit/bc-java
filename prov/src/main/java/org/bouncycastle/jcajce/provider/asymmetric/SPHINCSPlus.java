package org.bouncycastle.jcajce.provider.asymmetric;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
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

            addSignatureAlgorithm(provider, "SPHINCSPLUS", PREFIX + "SignatureSpi$Direct", BCObjectIdentifiers.sphincsPlus);

//            provider.addAlgorithm("Alg.Alias.Signature." + BCObjectIdentifiers.sphincsPlus.getId(), "SPHINCSPLUS");
//            provider.addAlgorithm("Alg.Alias.Signature.OID." + BCObjectIdentifiers.sphincsPlus.getId(), "SPHINCSPLUS");
            // add the full oid set, all 36.
            for (int i = 1; i <= 36; i++)
            {
                provider.addAlgorithm("Alg.Alias.Signature." + BCObjectIdentifiers.sphincsPlus + "." + i, "SPHINCSPLUS");
                provider.addAlgorithm("Alg.Alias.Signature.OID." + BCObjectIdentifiers.sphincsPlus + "." + i, "SPHINCSPLUS");
            }

            ASN1ObjectIdentifier[] libOQSOids = new ASN1ObjectIdentifier[]
            {
                BCObjectIdentifiers.sphincsPlus_sha2_128s,
                BCObjectIdentifiers.sphincsPlus_sha2_128f,
                BCObjectIdentifiers.sphincsPlus_shake_128s,
                BCObjectIdentifiers.sphincsPlus_shake_128f,
                BCObjectIdentifiers.sphincsPlus_sha2_192s,
                BCObjectIdentifiers.sphincsPlus_sha2_192f,
                BCObjectIdentifiers.sphincsPlus_shake_192s,
                BCObjectIdentifiers.sphincsPlus_shake_192f,
                BCObjectIdentifiers.sphincsPlus_sha2_256s,
                BCObjectIdentifiers.sphincsPlus_sha2_256f,
                BCObjectIdentifiers.sphincsPlus_shake_256s,
                BCObjectIdentifiers.sphincsPlus_shake_256f
            };
            
            for (int i = 0; i != libOQSOids.length; i++)
            {
                provider.addAlgorithm("Alg.Alias.Signature." + libOQSOids[i], "SPHINCSPLUS");
                provider.addAlgorithm("Alg.Alias.Signature.OID." + libOQSOids[i], "SPHINCSPLUS");
            }

            provider.addAlgorithm("Alg.Alias.Signature.SPHINCS+", "SPHINCSPLUS");

            AsymmetricKeyInfoConverter keyFact = new SPHINCSPlusKeyFactorySpi();

//            registerOid(provider, BCObjectIdentifiers.sphincsPlus, "SPHINCSPLUS", keyFact);
            registerOid(provider, BCObjectIdentifiers.sphincsPlus_sha2_128s_r3, "SPHINCSPLUS", keyFact);
            registerOid(provider, BCObjectIdentifiers.sphincsPlus_sha2_128f_r3, "SPHINCSPLUS", keyFact);
            registerOid(provider, BCObjectIdentifiers.sphincsPlus_shake_128s_r3, "SPHINCSPLUS", keyFact);
            registerOid(provider, BCObjectIdentifiers.sphincsPlus_shake_128f_r3, "SPHINCSPLUS", keyFact);
            registerOid(provider, BCObjectIdentifiers.sphincsPlus_haraka_128s_r3, "SPHINCSPLUS", keyFact);
            registerOid(provider, BCObjectIdentifiers.sphincsPlus_haraka_128f_r3, "SPHINCSPLUS", keyFact);
            registerOid(provider, BCObjectIdentifiers.sphincsPlus_sha2_192s_r3, "SPHINCSPLUS", keyFact);
            registerOid(provider, BCObjectIdentifiers.sphincsPlus_sha2_192f_r3, "SPHINCSPLUS", keyFact);
            registerOid(provider, BCObjectIdentifiers.sphincsPlus_shake_192s_r3, "SPHINCSPLUS", keyFact);
            registerOid(provider, BCObjectIdentifiers.sphincsPlus_shake_192f_r3, "SPHINCSPLUS", keyFact);
            registerOid(provider, BCObjectIdentifiers.sphincsPlus_haraka_192s_r3, "SPHINCSPLUS", keyFact);
            registerOid(provider, BCObjectIdentifiers.sphincsPlus_haraka_192f_r3, "SPHINCSPLUS", keyFact);
            registerOid(provider, BCObjectIdentifiers.sphincsPlus_sha2_256s_r3, "SPHINCSPLUS", keyFact);
            registerOid(provider, BCObjectIdentifiers.sphincsPlus_sha2_256f_r3, "SPHINCSPLUS", keyFact);
            registerOid(provider, BCObjectIdentifiers.sphincsPlus_shake_256s_r3, "SPHINCSPLUS", keyFact);
            registerOid(provider, BCObjectIdentifiers.sphincsPlus_shake_256f_r3, "SPHINCSPLUS", keyFact);
            registerOid(provider, BCObjectIdentifiers.sphincsPlus_haraka_256s_r3, "SPHINCSPLUS", keyFact);
            registerOid(provider, BCObjectIdentifiers.sphincsPlus_haraka_256f_r3, "SPHINCSPLUS", keyFact);
            registerOid(provider, BCObjectIdentifiers.sphincsPlus_sha2_128s_r3_simple, "SPHINCSPLUS", keyFact);
            registerOid(provider, BCObjectIdentifiers.sphincsPlus_sha2_128f_r3_simple, "SPHINCSPLUS", keyFact);
            registerOid(provider, BCObjectIdentifiers.sphincsPlus_shake_128s_r3_simple, "SPHINCSPLUS", keyFact);
            registerOid(provider, BCObjectIdentifiers.sphincsPlus_shake_128f_r3_simple, "SPHINCSPLUS", keyFact);
            registerOid(provider, BCObjectIdentifiers.sphincsPlus_haraka_128s_r3_simple, "SPHINCSPLUS", keyFact);
            registerOid(provider, BCObjectIdentifiers.sphincsPlus_haraka_128f_r3_simple, "SPHINCSPLUS", keyFact);
            registerOid(provider, BCObjectIdentifiers.sphincsPlus_sha2_192s_r3_simple, "SPHINCSPLUS", keyFact);
            registerOid(provider, BCObjectIdentifiers.sphincsPlus_sha2_192f_r3_simple, "SPHINCSPLUS", keyFact);
            registerOid(provider, BCObjectIdentifiers.sphincsPlus_shake_192s_r3_simple, "SPHINCSPLUS", keyFact);
            registerOid(provider, BCObjectIdentifiers.sphincsPlus_shake_192f_r3_simple, "SPHINCSPLUS", keyFact);
            registerOid(provider, BCObjectIdentifiers.sphincsPlus_haraka_192s_r3_simple, "SPHINCSPLUS", keyFact);
            registerOid(provider, BCObjectIdentifiers.sphincsPlus_haraka_192f_r3_simple, "SPHINCSPLUS", keyFact);
            registerOid(provider, BCObjectIdentifiers.sphincsPlus_sha2_256s_r3_simple, "SPHINCSPLUS", keyFact);
            registerOid(provider, BCObjectIdentifiers.sphincsPlus_sha2_256f_r3_simple, "SPHINCSPLUS", keyFact);
            registerOid(provider, BCObjectIdentifiers.sphincsPlus_shake_256s_r3_simple, "SPHINCSPLUS", keyFact);
            registerOid(provider, BCObjectIdentifiers.sphincsPlus_shake_256f_r3_simple, "SPHINCSPLUS", keyFact);
            registerOid(provider, BCObjectIdentifiers.sphincsPlus_haraka_256s_r3_simple, "SPHINCSPLUS", keyFact);
            registerOid(provider, BCObjectIdentifiers.sphincsPlus_haraka_256f_r3_simple, "SPHINCSPLUS", keyFact);

            for (int i = 0; i != libOQSOids.length; i++)
            {
                registerOid(provider, libOQSOids[i], "SPHINCSPLUS", keyFact);
            }
            
            registerOidAlgorithmParameters(provider, BCObjectIdentifiers.sphincsPlus, "SPHINCSPLUS");
        }
    }
}
