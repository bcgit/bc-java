package org.bouncycastle.jcajce.provider.asymmetric;


import org.bouncycastle.asn1.rfc7748.RFC7748ObjectIdentifiers;
import org.bouncycastle.jcajce.provider.asymmetric.rfc7748.KeyFactorySpi;
import org.bouncycastle.jcajce.provider.config.ConfigurableProvider;
import org.bouncycastle.jcajce.provider.util.AsymmetricAlgorithmProvider;


public class RFC7748 {
    private static final String PREFIX = "org.bouncycastle.jcajce.provider.asymmetric" + ".rfc7748.";

    public static class Mappings
            extends AsymmetricAlgorithmProvider {
        public Mappings() {
        }

        public void configure(ConfigurableProvider provider)
        {
            // provider.addAlgorithm("KeyPairGenerator.X25519", PREFIX + "KeyPairGeneratorSpi$X25519");
            // provider.addAlgorithm("KeyPairGenerator.X448", PREFIX + "KeyPairGeneratorSpi$X448");
            provider.addAlgorithm("KeyPairGenerator.Ed25519", PREFIX + "KeyPairGeneratorSpi$Ed25519");
            // provider.addAlgorithm("KeyPairGenerator.Ed448", PREFIX + "KeyPairGeneratorSpi$Ed448");

            // provider.addAlgorithm("KeyFactory.X25519", PREFIX + "KeyFactorySpi$X25519");
            // provider.addAlgorithm("KeyFactory.X448", PREFIX + "KeyFactorySpi$X448");
            provider.addAlgorithm("KeyFactory.Ed25519", PREFIX + "KeyFactorySpi$Ed25519");
            // provider.addAlgorithm("KeyFactory.Ed448", PREFIX + "KeyFactorySpi$Ed448");

            addSignatureAlgorithm(provider, "NONE", "Ed25519", PREFIX + "DigestSignatureSpi$NONE", RFC7748ObjectIdentifiers.id_Ed25519);

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
            
            // registerOid(provider, RFC7748ObjectIdentifiers.id_X25519, "X25519", new KeyFactorySpi.X25519());
            // registerOid(provider, RFC7748ObjectIdentifiers.id_X448, "X448", new KeyFactorySpi.X448());
            registerOid(provider, RFC7748ObjectIdentifiers.id_Ed25519, "Ed25519", new KeyFactorySpi.Ed25519());
            // registerOid(provider, RFC7748ObjectIdentifiers.id_Ed448, "Ed448", new KeyFactorySpi.Ed448());
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
