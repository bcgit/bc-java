package org.bouncycastle.pqc.jcajce.provider;

import org.bouncycastle.asn1.bc.BCObjectIdentifiers;
import org.bouncycastle.jcajce.provider.config.ConfigurableProvider;
import org.bouncycastle.jcajce.provider.util.AsymmetricAlgorithmProvider;
import org.bouncycastle.jcajce.provider.util.AsymmetricKeyInfoConverter;
import org.bouncycastle.pqc.jcajce.provider.frodo.FrodoKeyFactorySpi;

/**
 * @deprecated the standardised FrodoKEM (ISO/IEC 18033-2:2006/Amd 2:2026) is now provided under org.bouncycastle.crypto and org.bouncycastle.jcajce (see FrodoKEMParameters / FrodoKEMParameterSpec). This is the legacy NIST round 3 (unsalted, eFrodoKEM) implementation, retained for backwards compatibility.
 */
@Deprecated
public class Frodo
{
    private static final String PREFIX = "org.bouncycastle.pqc.jcajce.provider" + ".frodo.";

    public static class Mappings
        extends AsymmetricAlgorithmProvider
    {
        public Mappings()
        {
        }

        public void configure(ConfigurableProvider provider)
        {
            provider.addAlgorithm("KeyFactory.FRODO", PREFIX + "FrodoKeyFactorySpi");
            provider.addAlgorithm("KeyPairGenerator.FRODO", PREFIX + "FrodoKeyPairGeneratorSpi");

            provider.addAlgorithm("KeyGenerator.FRODO", PREFIX + "FrodoKeyGeneratorSpi");

            AsymmetricKeyInfoConverter keyFact = new FrodoKeyFactorySpi();

            provider.addAlgorithm("Cipher.FRODO", PREFIX + "FrodoCipherSpi$Base");
            provider.addAlgorithm("Alg.Alias.Cipher." + BCObjectIdentifiers.pqc_kem_frodo, "FRODO");

            registerOid(provider, BCObjectIdentifiers.pqc_kem_frodo, "Frodo", keyFact);
        }
    }
}
