package org.bouncycastle.jcajce.provider.kdf;

import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.jcajce.provider.config.ConfigurableProvider;
import org.bouncycastle.jcajce.provider.util.AlgorithmProvider;

class PBEPBKDF2
{
    private static final String PREFIX = "org.bouncycastle.jcajce.provider.kdf" + ".pbepbkdf2.";

    public static class Mappings
            extends AlgorithmProvider
    {
        public Mappings()
        {
        }

        public void configure(ConfigurableProvider provider)
        {
//            provider.addAlgorithm("AlgorithmParameters.PBKDF2", PREFIX + "PBEPBKDF2Spi$AlgParams");
//            provider.addAlgorithm("Alg.Alias.AlgorithmParameters." + PKCSObjectIdentifiers.id_PBKDF2, "PBKDF2");
            provider.addAlgorithm("KDF.PBKDF2", PREFIX + "PBEPBKDF2Spi$PBKDF2withUTF8");
            provider.addAlgorithm("Alg.Alias.KDF.PBKDF2WITHHMACSHA1", "PBKDF2");
            provider.addAlgorithm("Alg.Alias.KDF.PBKDF2WITHHMACSHA1ANDUTF8", "PBKDF2");
            provider.addAlgorithm("Alg.Alias.KDF." + PKCSObjectIdentifiers.id_PBKDF2, "PBKDF2");
            provider.addAlgorithm("KDF.PBKDF2WITHASCII", PREFIX + "PBEPBKDF2Spi$PBKDF2with8BIT");
            provider.addAlgorithm("Alg.Alias.KDF.PBKDF2WITH8BIT", "PBKDF2WITHASCII");
            provider.addAlgorithm("Alg.Alias.KDF.PBKDF2WITHHMACSHA1AND8BIT", "PBKDF2WITHASCII");
            provider.addAlgorithm("KDF.PBKDF2WITHHMACSHA224", PREFIX + "PBEPBKDF2Spi$PBKDF2withSHA224");
            provider.addAlgorithm("KDF.PBKDF2WITHHMACSHA256", PREFIX + "PBEPBKDF2Spi$PBKDF2withSHA256");
            provider.addAlgorithm("KDF.PBKDF2WITHHMACSHA384", PREFIX + "PBEPBKDF2Spi$PBKDF2withSHA384");
            provider.addAlgorithm("KDF.PBKDF2WITHHMACSHA512", PREFIX + "PBEPBKDF2Spi$PBKDF2withSHA512");
            provider.addAlgorithm("KDF.PBKDF2WITHHMACSHA512-224", PREFIX + "PBEPBKDF2Spi$PBKDF2withSHA512_224");
            provider.addAlgorithm("KDF.PBKDF2WITHHMACSHA512-256", PREFIX + "PBEPBKDF2Spi$PBKDF2withSHA512_256");
            provider.addAlgorithm("KDF.PBKDF2WITHHMACSHA3-224", PREFIX + "PBEPBKDF2Spi$PBKDF2withSHA3_224");
            provider.addAlgorithm("KDF.PBKDF2WITHHMACSHA3-256", PREFIX + "PBEPBKDF2Spi$PBKDF2withSHA3_256");
            provider.addAlgorithm("KDF.PBKDF2WITHHMACSHA3-384", PREFIX + "PBEPBKDF2Spi$PBKDF2withSHA3_384");
            provider.addAlgorithm("KDF.PBKDF2WITHHMACSHA3-512", PREFIX + "PBEPBKDF2Spi$PBKDF2withSHA3_512");
            provider.addAlgorithm("KDF.PBKDF2WITHHMACGOST3411", PREFIX + "PBEPBKDF2Spi$PBKDF2withGOST3411");
            provider.addAlgorithm("KDF.PBKDF2WITHHMACSM3", PREFIX + "PBEPBKDF2Spi$PBKDF2withSM3");


        }
    }
}
