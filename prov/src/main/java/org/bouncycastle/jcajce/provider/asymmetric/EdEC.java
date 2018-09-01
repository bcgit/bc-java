package org.bouncycastle.jcajce.provider.asymmetric;

import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.asn1.edec.EdECObjectIdentifiers;
import org.bouncycastle.jcajce.provider.asymmetric.edec.KeyFactorySpi;
import org.bouncycastle.jcajce.provider.config.ConfigurableProvider;
import org.bouncycastle.jcajce.provider.util.AsymmetricAlgorithmProvider;

public class EdEC
{
    private static final String PREFIX = "org.bouncycastle.jcajce.provider.asymmetric" + ".edec.";

    private static final Map<String, String> edxAttributes = new HashMap<String, String>();

    static
    {
        edxAttributes.put("SupportedKeyClasses", "java.security.interfaces.ECPublicKey|java.security.interfaces.ECPrivateKey");
        edxAttributes.put("SupportedKeyFormats", "PKCS#8|X.509");
    }

    public static class Mappings
        extends AsymmetricAlgorithmProvider
    {
        public Mappings()
        {
        }

        public void configure(ConfigurableProvider provider)
        {
            provider.addAlgorithm("KeyFactory.XDH", PREFIX + "KeyFactorySpi$XDH");
            provider.addAlgorithm("KeyFactory.EDDSA", PREFIX + "KeyFactorySpi$EDDSA");

            provider.addAlgorithm("Signature.EDDSA", PREFIX + "SignatureSpi$EdDSA");
            provider.addAlgorithm("Signature.ED448", PREFIX + "SignatureSpi$Ed448");
            provider.addAlgorithm("Signature.ED25519", PREFIX + "SignatureSpi$Ed25519");
            provider.addAlgorithm("Signature", EdECObjectIdentifiers.id_Ed448, PREFIX + "SignatureSpi$Ed448");
            provider.addAlgorithm("Signature", EdECObjectIdentifiers.id_Ed25519, PREFIX + "SignatureSpi$Ed25519");

            registerOid(provider, EdECObjectIdentifiers.id_X448, "XDH", new KeyFactorySpi("XDH"));
            registerOid(provider, EdECObjectIdentifiers.id_X25519, "XDH", new KeyFactorySpi("XDH"));
            registerOid(provider, EdECObjectIdentifiers.id_Ed448, "EDDSA", new KeyFactorySpi("EdDSA"));
            registerOid(provider, EdECObjectIdentifiers.id_Ed25519, "EDDSA", new KeyFactorySpi("EdDSA"));
        }
    }
}
