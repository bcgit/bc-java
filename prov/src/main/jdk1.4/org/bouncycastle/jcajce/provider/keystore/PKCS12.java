package org.bouncycastle.jcajce.provider.keystore;

import org.bouncycastle.jcajce.provider.config.ConfigurableProvider;
import org.bouncycastle.jcajce.provider.util.AsymmetricAlgorithmProvider;
import org.bouncycastle.util.Properties;
import org.bouncycastle.util.Strings;

/**
 * NOTE: this overlay exists because the jdk1.4 (and, by layering, jdk1.3) PKCS12KeyStoreSpi
 * overlays do not implement the AES256 store variants, so the PKCS12-AES256-AES128(-GCM) and
 * PKCS12-DEF-AES256-AES128(-GCM) registrations of the base class are left out here - they would
 * name classes that do not exist. The legacy stores can still read PBES2/AES protected files.
 * Keep everything else in step with the base PKCS12.java.
 */
public class PKCS12
{
    private static final String PREFIX = "org.bouncycastle.jcajce.provider.keystore" + ".pkcs12.";

    public static class Mappings
        extends AsymmetricAlgorithmProvider
    {
        public Mappings()
        {
        }

        public void configure(ConfigurableProvider provider)
        {
            provider.addAlgorithm("KeyStore.PKCS12-3DES-40RC2", PREFIX + "PKCS12KeyStoreSpi$BCPKCS12KeyStore");
            provider.addAlgorithm("KeyStore.PKCS12-3DES-3DES", PREFIX + "PKCS12KeyStoreSpi$BCPKCS12KeyStore3DES");

            provider.addAlgorithm("KeyStore.PKCS12-DEF-3DES-40RC2", PREFIX + "PKCS12KeyStoreSpi$DefPKCS12KeyStore");
            provider.addAlgorithm("KeyStore.PKCS12-DEF-3DES-3DES", PREFIX + "PKCS12KeyStoreSpi$DefPKCS12KeyStore3DES");

            provider.addAlgorithm("KeyStore.PKCS12-PBMAC1", PREFIX + "PKCS12PBMAC1KeyStoreSpi$BCPKCS12KeyStore");

            configureDefaults(provider);
        }

        /**
         * Register PKCS12, BCPKCS12 and PKCS12-DEF, as aliases for the store named by
         * org.bouncycastle.pkcs12.default when it names one registered above, and PKCS12-DEF for its
         * PKCS12-DEF-* counterpart where there is one. A value naming no registered store is ignored.
         */
        private static void configureDefaults(ConfigurableProvider provider)
        {
            String defType = Properties.getPropertyValue("org.bouncycastle.pkcs12.default");
            if (defType != null)
            {
                defType = Strings.toUpperCase(defType.trim());
            }

            if (defType != null && defType.startsWith("PKCS12-") && provider.hasAlgorithm("KeyStore", defType))
            {
                provider.addAlgorithm("Alg.Alias.KeyStore.PKCS12", defType);
                provider.addAlgorithm("Alg.Alias.KeyStore.BCPKCS12", defType);

                String defDefType = "PKCS12-DEF" + defType.substring("PKCS12".length());
                if (provider.hasAlgorithm("KeyStore", defDefType))
                {
                    provider.addAlgorithm("Alg.Alias.KeyStore.PKCS12-DEF", defDefType);
                }
                else
                {
                    provider.addAlgorithm("KeyStore.PKCS12-DEF", PREFIX + "PKCS12KeyStoreSpi$DefPKCS12KeyStore");
                }
            }
            else
            {
                provider.addAlgorithm("KeyStore.PKCS12", PREFIX + "PKCS12KeyStoreSpi$BCPKCS12KeyStore");
                provider.addAlgorithm("KeyStore.BCPKCS12", PREFIX + "PKCS12KeyStoreSpi$BCPKCS12KeyStore");
                provider.addAlgorithm("KeyStore.PKCS12-DEF", PREFIX + "PKCS12KeyStoreSpi$DefPKCS12KeyStore");
            }
        }
    }
}
