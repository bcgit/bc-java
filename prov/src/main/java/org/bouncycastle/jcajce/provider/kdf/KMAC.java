package org.bouncycastle.jcajce.provider.kdf;

import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.jcajce.provider.config.ConfigurableProvider;
import org.bouncycastle.jcajce.util.SpiUtil;

/**
 * javax.crypto.KDF services for the KMAC-based KDF of RFC 9629 / RFC 9935 (KMAC(secret, context, L,
 * customization)): "KMAC128-KDF" and "KMAC256-KDF", also reachable by the id-Kmac128 and id-Kmac256 OIDs,
 * taking a {@link org.bouncycastle.jcajce.spec.KMACKDFParameterSpec}.
 */
public class KMAC
{
    private static final String PREFIX = "org.bouncycastle.jcajce.provider.kdf" + ".kmac.";

    public static class Mappings
        extends KDFAlgorithmProvider
    {
        public Mappings()
        {
        }

        public void configure(ConfigurableProvider provider)
        {
            if (SpiUtil.hasKDF())
            {
                addKDFAlgorithm(provider, "KMAC128-KDF", PREFIX + "KMACKDFSpi$KMAC128", NISTObjectIdentifiers.id_Kmac128);
                addKDFAlgorithm(provider, "KMAC256-KDF", PREFIX + "KMACKDFSpi$KMAC256", NISTObjectIdentifiers.id_Kmac256);
            }
        }
    }
}
