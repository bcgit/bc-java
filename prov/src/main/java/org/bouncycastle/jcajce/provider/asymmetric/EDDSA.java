package org.bouncycastle.jcajce.provider.asymmetric;


import org.bouncycastle.jcajce.provider.asymmetric.eddsa.EdDSAKey;
import org.bouncycastle.jcajce.provider.config.ConfigurableProvider;
import org.bouncycastle.jcajce.provider.util.AsymmetricAlgorithmProvider;


public class EDDSA {
    private static final String PREFIX = "org.bouncycastle.jcajce.provider.asymmetric." + "eddsa.";

    public static class Mappings
            extends AsymmetricAlgorithmProvider {
        public Mappings() {
        }

        public void configure(ConfigurableProvider provider)
        {
            provider.addAlgorithm("KeyPairGenerator." + EdDSAKey.KEY_ALGORITHM, PREFIX + "KeyPairGenerator");
            provider.addAlgorithm("KeyFactory." + EdDSAKey.KEY_ALGORITHM, PREFIX + "KeyFactory");

            if (provider.hasAlgorithm("MessageDigest", "MD2"))
            {
                addDigestSignature(provider, "MD2", PREFIX + "DigestSignatureSpi$MD2");
            }

            if (provider.hasAlgorithm("MessageDigest", "MD4"))
            {
                addDigestSignature(provider, "MD4", PREFIX + "DigestSignatureSpi$MD4");
            }

            if (provider.hasAlgorithm("MessageDigest", "MD5"))
            {
                addDigestSignature(provider, "MD5", PREFIX + "DigestSignatureSpi$MD5");
            }

            if (provider.hasAlgorithm("MessageDigest", "SHA1"))
            {
                addDigestSignature(provider, "SHA1", PREFIX + "DigestSignatureSpi$SHA1");
            }

            addDigestSignature(provider, "SHA224", PREFIX + "DigestSignatureSpi$SHA224");
            addDigestSignature(provider, "SHA256", PREFIX + "DigestSignatureSpi$SHA256");
            addDigestSignature(provider, "SHA384", PREFIX + "DigestSignatureSpi$SHA384");
            addDigestSignature(provider, "SHA512", PREFIX + "DigestSignatureSpi$SHA512");
            addDigestSignature(provider, "SHA512(224)", PREFIX + "DigestSignatureSpi$SHA512_224");
            addDigestSignature(provider, "SHA512(256)", PREFIX + "DigestSignatureSpi$SHA512_256");

            if (provider.hasAlgorithm("MessageDigest", "RIPEMD128"))
            {
                addDigestSignature(provider, "RIPEMD128", PREFIX + "DigestSignatureSpi$RIPEMD128");
                addDigestSignature(provider, "RMD128", PREFIX + "DigestSignatureSpi$RIPEMD128");
            }

            if (provider.hasAlgorithm("MessageDigest", "RIPEMD160"))
            {
                addDigestSignature(provider, "RIPEMD160", PREFIX + "DigestSignatureSpi$RIPEMD160");
                addDigestSignature(provider, "RMD160", PREFIX + "DigestSignatureSpi$RIPEMD160");
            }

            if (provider.hasAlgorithm("MessageDigest", "RIPEMD256"))
            {
                addDigestSignature(provider, "RIPEMD256", PREFIX + "DigestSignatureSpi$RIPEMD256");
                addDigestSignature(provider, "RMD256", PREFIX + "DigestSignatureSpi$RIPEMD256");
            }
        }

        private void addDigestSignature(
                ConfigurableProvider provider,
                String digest,
                String className)
        {
            String mainName = digest + "WITHEd25519";
            String jdk11Variation1 = digest + "withEd25519";
            String jdk11Variation2 = digest + "WithEd25519";
            String alias = digest + "/" + "Ed25519";

            provider.addAlgorithm("Signature." + mainName, className);
            provider.addAlgorithm("Alg.Alias.Signature." + jdk11Variation1, mainName);
            provider.addAlgorithm("Alg.Alias.Signature." + jdk11Variation2, mainName);
            provider.addAlgorithm("Alg.Alias.Signature." + alias, mainName);
        }

    }
}
