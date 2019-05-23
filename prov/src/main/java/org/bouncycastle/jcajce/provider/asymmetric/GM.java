package org.bouncycastle.jcajce.provider.asymmetric;

import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.asn1.gm.GMObjectIdentifiers;
import org.bouncycastle.jcajce.provider.config.ConfigurableProvider;
import org.bouncycastle.jcajce.provider.util.AsymmetricAlgorithmProvider;

public class GM
{
    private static final String PREFIX = "org.bouncycastle.jcajce.provider.asymmetric" + ".ec.";

    private static final Map<String, String> generalSm2Attributes = new HashMap<String, String>();

    static
    {
        generalSm2Attributes.put("SupportedKeyClasses", "java.security.interfaces.ECPublicKey|java.security.interfaces.ECPrivateKey");
        generalSm2Attributes.put("SupportedKeyFormats", "PKCS#8|X.509");
    }

    public static class Mappings
        extends AsymmetricAlgorithmProvider
    {
        public Mappings()
        {
        }

        public void configure(ConfigurableProvider provider)
        {
//            provider.addAlgorithm("Signature.BLAKE2BWITHSM2", PREFIX + "GMSignatureSpi$blake2b512WithSM2");
//            provider.addAlgorithm("Alg.Alias.Signature." + GMObjectIdentifiers.sm2sign_with_blake2b512, "BLAKE2BWITHSM2");
//            provider.addAlgorithm("Signature.BLAKE2SWITHSM2", PREFIX + "GMSignatureSpi$blake2s256WithSM2");
//            provider.addAlgorithm("Alg.Alias.Signature." + GMObjectIdentifiers.sm2sign_with_blake2s256, "BLAKE2SWITHSM2");
//            provider.addAlgorithm("Signature.RIPEMD160WITHSM2", PREFIX + "GMSignatureSpi$ripemd160WithSM2");
//            provider.addAlgorithm("Alg.Alias.Signature." + GMObjectIdentifiers.sm2sign_with_rmd160, "RIPEMD160WITHSM2");
//            provider.addAlgorithm("Signature.SHA1WITHSM2", PREFIX + "GMSignatureSpi$sha1WithSM2");
//            provider.addAlgorithm("Alg.Alias.Signature." + GMObjectIdentifiers.sm2sign_with_sha1, "SHA1WITHSM2");
//            provider.addAlgorithm("Signature.SHA224WITHSM2", PREFIX + "GMSignatureSpi$sha224WithSM2");
//            provider.addAlgorithm("Alg.Alias.Signature." + GMObjectIdentifiers.sm2sign_with_sha224, "SHA224WITHSM2");
            provider.addAlgorithm("Signature.SHA256WITHSM2", PREFIX + "GMSignatureSpi$sha256WithSM2");
            provider.addAlgorithm("Alg.Alias.Signature." + GMObjectIdentifiers.sm2sign_with_sha256, "SHA256WITHSM2");
//            provider.addAlgorithm("Signature.SHA384WITHSM2", PREFIX + "GMSignatureSpi$sha384WithSM2");
//            provider.addAlgorithm("Alg.Alias.Signature." + GMObjectIdentifiers.sm2sign_with_sha384, "SHA384WITHSM2");
//            provider.addAlgorithm("Signature.SHA512WITHSM2", PREFIX + "GMSignatureSpi$sha512WithSM2");
//            provider.addAlgorithm("Alg.Alias.Signature." + GMObjectIdentifiers.sm2sign_with_sha512, "SHA512WITHSM2");
            provider.addAlgorithm("Signature.SM3WITHSM2", PREFIX + "GMSignatureSpi$sm3WithSM2");
            provider.addAlgorithm("Alg.Alias.Signature." + GMObjectIdentifiers.sm2sign_with_sm3, "SM3WITHSM2");
//            provider.addAlgorithm("Signature.WHIRLPOOLWITHSM2", PREFIX + "GMSignatureSpi$whirlpoolWithSM2");
//            provider.addAlgorithm("Alg.Alias.Signature." + GMObjectIdentifiers.sm2sign_with_whirlpool, "WHIRLPOOLWITHSM2");

            provider.addAlgorithm("Cipher.SM2", PREFIX + "GMCipherSpi$SM2");
            provider.addAlgorithm("Alg.Alias.Cipher.SM2WITHSM3", "SM2");
            provider.addAlgorithm("Alg.Alias.Cipher." + GMObjectIdentifiers.sm2encrypt_with_sm3, "SM2");
            provider.addAlgorithm("Cipher.SM2WITHBLAKE2B", PREFIX + "GMCipherSpi$SM2withBlake2b");
            provider.addAlgorithm("Alg.Alias.Cipher." + GMObjectIdentifiers.sm2encrypt_with_blake2b512, "SM2WITHBLAKE2B");
            provider.addAlgorithm("Cipher.SM2WITHBLAKE2S", PREFIX + "GMCipherSpi$SM2withBlake2s");
            provider.addAlgorithm("Alg.Alias.Cipher." + GMObjectIdentifiers.sm2encrypt_with_blake2s256, "SM2WITHBLAKE2S");
            provider.addAlgorithm("Cipher.SM2WITHWHIRLPOOL", PREFIX + "GMCipherSpi$SM2withWhirlpool");
            provider.addAlgorithm("Alg.Alias.Cipher." + GMObjectIdentifiers.sm2encrypt_with_whirlpool, "SM2WITHWHIRLPOOL");
            provider.addAlgorithm("Cipher.SM2WITHMD5", PREFIX + "GMCipherSpi$SM2withMD5");
            provider.addAlgorithm("Alg.Alias.Cipher." + GMObjectIdentifiers.sm2encrypt_with_md5, "SM2WITHMD5");
            provider.addAlgorithm("Cipher.SM2WITHRIPEMD160", PREFIX + "GMCipherSpi$SM2withRMD");
            provider.addAlgorithm("Alg.Alias.Cipher." + GMObjectIdentifiers.sm2encrypt_with_rmd160, "SM2WITHRIPEMD160");
            provider.addAlgorithm("Cipher.SM2WITHSHA1", PREFIX + "GMCipherSpi$SM2withSha1");
            provider.addAlgorithm("Alg.Alias.Cipher." + GMObjectIdentifiers.sm2encrypt_with_sha1, "SM2WITHSHA1");
            provider.addAlgorithm("Cipher.SM2WITHSHA224", PREFIX + "GMCipherSpi$SM2withSha224");
            provider.addAlgorithm("Alg.Alias.Cipher." + GMObjectIdentifiers.sm2encrypt_with_sha224, "SM2WITHSHA224");
            provider.addAlgorithm("Cipher.SM2WITHSHA256", PREFIX + "GMCipherSpi$SM2withSha256");
            provider.addAlgorithm("Alg.Alias.Cipher." + GMObjectIdentifiers.sm2encrypt_with_sha256, "SM2WITHSHA256");
            provider.addAlgorithm("Cipher.SM2WITHSHA384", PREFIX + "GMCipherSpi$SM2withSha384");
            provider.addAlgorithm("Alg.Alias.Cipher." + GMObjectIdentifiers.sm2encrypt_with_sha384, "SM2WITHSHA384");
            provider.addAlgorithm("Cipher.SM2WITHSHA512", PREFIX + "GMCipherSpi$SM2withSha512");
            provider.addAlgorithm("Alg.Alias.Cipher." + GMObjectIdentifiers.sm2encrypt_with_sha512, "SM2WITHSHA512");
        }
    }
}
