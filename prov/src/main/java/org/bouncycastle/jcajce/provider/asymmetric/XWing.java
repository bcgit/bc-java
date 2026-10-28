package org.bouncycastle.jcajce.provider.asymmetric;

import org.bouncycastle.asn1.bc.BCObjectIdentifiers;
import org.bouncycastle.jcajce.provider.asymmetric.xwing.XWingKeyFactorySpi;
import org.bouncycastle.jcajce.provider.config.ConfigurableProvider;
import org.bouncycastle.jcajce.provider.util.AsymmetricAlgorithmProvider;
import org.bouncycastle.jcajce.provider.util.AsymmetricKeyInfoConverter;
import org.bouncycastle.jcajce.util.SpiUtil;

/**
 * Registration of X-Wing (draft-connolly-cfrg-xwing-kem), the X25519 and ML-KEM-768 hybrid KEM, under the
 * name "X-WING" (alias "XWING") and the draft's id-XWing OID: KeyFactory, KeyPairGenerator, the KEM
 * KeyGenerator and KTS Cipher services, and on Java 21 and later javax.crypto.KEM.
 */
public class XWing
{
    private static final String PREFIX = "org.bouncycastle.jcajce.provider.asymmetric" + ".xwing.";

    public static class Mappings
        extends AsymmetricAlgorithmProvider
    {
        public Mappings()
        {
        }

        public void configure(ConfigurableProvider provider)
        {
            AsymmetricKeyInfoConverter keyFact = new XWingKeyFactorySpi();

            addKeyFactoryAlgorithm(provider, "X-WING", PREFIX + "XWingKeyFactorySpi", BCObjectIdentifiers.xwing, keyFact);
            provider.addAlgorithm("Alg.Alias.KeyFactory.XWING", "X-WING");

            addKeyPairGeneratorAlgorithm(provider, "X-WING", PREFIX + "XWingKeyPairGeneratorSpi", BCObjectIdentifiers.xwing);
            provider.addAlgorithm("Alg.Alias.KeyPairGenerator.XWING", "X-WING");

            addKeyGeneratorAlgorithm(provider, "X-WING", PREFIX + "XWingKeyGeneratorSpi", BCObjectIdentifiers.xwing);
            provider.addAlgorithm("Alg.Alias.KeyGenerator.XWING", "X-WING");

            addCipherAlgorithm(provider, "X-WING", PREFIX + "XWingCipherSpi", BCObjectIdentifiers.xwing);
            provider.addAlgorithm("Alg.Alias.Cipher.XWING", "X-WING");

            if (SpiUtil.hasKEM())
            {
                addKEMAlgorithm(provider, "X-WING", PREFIX + "XWingSpi", BCObjectIdentifiers.xwing);
                provider.addAlgorithm("Alg.Alias.KEM.XWING", "X-WING");
            }
        }
    }
}
