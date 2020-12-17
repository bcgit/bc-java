package org.bouncycastle.jcajce.provider.asymmetric;

import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.teletrust.TeleTrusTObjectIdentifiers;
import org.bouncycastle.asn1.x509.X509ObjectIdentifiers;
import org.bouncycastle.jcajce.provider.asymmetric.rsa.KeyFactorySpi;
import org.bouncycastle.jcajce.provider.config.ConfigurableProvider;
import org.bouncycastle.jcajce.provider.util.AsymmetricAlgorithmProvider;
import org.bouncycastle.jcajce.provider.util.AsymmetricKeyInfoConverter;

public class RSA
{
    private static final String PREFIX = "org.bouncycastle.jcajce.provider.asymmetric" + ".rsa.";

    private static final Map<String, String> generalRsaAttributes = new HashMap<String, String>();

    static
    {
        generalRsaAttributes.put("SupportedKeyClasses", "javax.crypto.interfaces.RSAPublicKey|javax.crypto.interfaces.RSAPrivateKey");
        generalRsaAttributes.put("SupportedKeyFormats", "PKCS#8|X.509");
    }

    public static class Mappings
        extends AsymmetricAlgorithmProvider
    {
        public Mappings()
        {
        }

        public void configure(ConfigurableProvider provider)
        {
            provider.addAlgorithm("AlgorithmParameters.OAEP", PREFIX + "AlgorithmParametersSpi$OAEP");
            provider.addAlgorithm("AlgorithmParameters.PSS", PREFIX + "AlgorithmParametersSpi$PSS");

            provider.addAlgorithm("Alg.Alias.AlgorithmParameters.RSAPSS", "PSS");
            provider.addAlgorithm("Alg.Alias.AlgorithmParameters.RSASSA-PSS", "PSS");

            provider.addAlgorithm("Alg.Alias.AlgorithmParameters.SHA224withRSA/PSS", "PSS");
            provider.addAlgorithm("Alg.Alias.AlgorithmParameters.SHA256withRSA/PSS", "PSS");
            provider.addAlgorithm("Alg.Alias.AlgorithmParameters.SHA384withRSA/PSS", "PSS");
            provider.addAlgorithm("Alg.Alias.AlgorithmParameters.SHA512withRSA/PSS", "PSS");

            provider.addAlgorithm("Alg.Alias.AlgorithmParameters.SHA224WITHRSAANDMGF1", "PSS");
            provider.addAlgorithm("Alg.Alias.AlgorithmParameters.SHA256WITHRSAANDMGF1", "PSS");
            provider.addAlgorithm("Alg.Alias.AlgorithmParameters.SHA384WITHRSAANDMGF1", "PSS");
            provider.addAlgorithm("Alg.Alias.AlgorithmParameters.SHA512WITHRSAANDMGF1", "PSS");
            provider.addAlgorithm("Alg.Alias.AlgorithmParameters.SHA3-224WITHRSAANDMGF1", "PSS");
            provider.addAlgorithm("Alg.Alias.AlgorithmParameters.SHA3-256WITHRSAANDMGF1", "PSS");
            provider.addAlgorithm("Alg.Alias.AlgorithmParameters.SHA3-384WITHRSAANDMGF1", "PSS");
            provider.addAlgorithm("Alg.Alias.AlgorithmParameters.SHA3-512WITHRSAANDMGF1", "PSS");

            provider.addAlgorithm("Alg.Alias.AlgorithmParameters.RAWRSAPSS", "PSS");
            provider.addAlgorithm("Alg.Alias.AlgorithmParameters.NONEWITHRSAPSS", "PSS");
            provider.addAlgorithm("Alg.Alias.AlgorithmParameters.NONEWITHRSASSA-PSS", "PSS");
            provider.addAlgorithm("Alg.Alias.AlgorithmParameters.NONEWITHRSAANDMGF1", "PSS");

            provider.addAttributes("Cipher.RSA", generalRsaAttributes);
            provider.addAlgorithm("Cipher.RSA", PREFIX + "CipherSpi$NoPadding");
            provider.addAlgorithm("Cipher.RSA/RAW", PREFIX + "CipherSpi$NoPadding");
            provider.addAlgorithm("Cipher.RSA/PKCS1", PREFIX + "CipherSpi$PKCS1v1_5Padding");
            provider.addAlgorithm("Cipher", PKCSObjectIdentifiers.rsaEncryption, PREFIX + "CipherSpi$PKCS1v1_5Padding");
            provider.addAlgorithm("Cipher", X509ObjectIdentifiers.id_ea_rsa, PREFIX + "CipherSpi$PKCS1v1_5Padding");
            provider.addAlgorithm("Cipher.RSA/1", PREFIX + "CipherSpi$PKCS1v1_5Padding_PrivateOnly");
            provider.addAlgorithm("Cipher.RSA/2", PREFIX + "CipherSpi$PKCS1v1_5Padding_PublicOnly");
            provider.addAlgorithm("Cipher.RSA/OAEP", PREFIX + "CipherSpi$OAEPPadding");
            provider.addAlgorithm("Cipher", PKCSObjectIdentifiers.id_RSAES_OAEP, PREFIX + "CipherSpi$OAEPPadding");
            provider.addAlgorithm("Cipher.RSA/ISO9796-1", PREFIX + "CipherSpi$ISO9796d1Padding");

            provider.addAlgorithm("Alg.Alias.Cipher.RSA//RAW", "RSA");
            provider.addAlgorithm("Alg.Alias.Cipher.RSA//NOPADDING", "RSA");
            provider.addAlgorithm("Alg.Alias.Cipher.RSA//PKCS1PADDING", "RSA/PKCS1");
            provider.addAlgorithm("Alg.Alias.Cipher.RSA//OAEPPADDING", "RSA/OAEP");
            provider.addAlgorithm("Alg.Alias.Cipher.RSA//ISO9796-1PADDING", "RSA/ISO9796-1");

            provider.addAlgorithm("KeyFactory.RSA", PREFIX + "KeyFactorySpi");
            provider.addAlgorithm("KeyPairGenerator.RSA", PREFIX + "KeyPairGeneratorSpi");

            provider.addAlgorithm("KeyFactory.RSASSA-PSS", PREFIX + "KeyFactorySpi");
            provider.addAlgorithm("KeyPairGenerator.RSASSA-PSS", PREFIX + "KeyPairGeneratorSpi$PSS");

            AsymmetricKeyInfoConverter keyFact = new KeyFactorySpi();

            registerOid(provider, PKCSObjectIdentifiers.rsaEncryption, "RSA", keyFact);
            registerOid(provider, X509ObjectIdentifiers.id_ea_rsa, "RSA", keyFact);
            registerOid(provider, PKCSObjectIdentifiers.id_RSAES_OAEP, "RSA", keyFact);
            registerOid(provider, PKCSObjectIdentifiers.id_RSASSA_PSS, "RSA", keyFact);

            registerOidAlgorithmParameters(provider, PKCSObjectIdentifiers.rsaEncryption, "RSA");
            registerOidAlgorithmParameters(provider, X509ObjectIdentifiers.id_ea_rsa, "RSA");
            registerOidAlgorithmParameters(provider, PKCSObjectIdentifiers.id_RSAES_OAEP, "OAEP");
            registerOidAlgorithmParameters(provider, PKCSObjectIdentifiers.id_RSASSA_PSS, "PSS");

            provider.addAlgorithm("Signature.RSASSA-PSS", PREFIX + "PSSSignatureSpi$PSSwithRSA");
            provider.addAlgorithm("Signature." + PKCSObjectIdentifiers.id_RSASSA_PSS, PREFIX + "PSSSignatureSpi$PSSwithRSA");
            provider.addAlgorithm("Signature.OID." + PKCSObjectIdentifiers.id_RSASSA_PSS, PREFIX + "PSSSignatureSpi$PSSwithRSA");

            provider.addAlgorithm("Signature.RSA", PREFIX + "DigestSignatureSpi$noneRSA");
            provider.addAlgorithm("Signature.RAWRSASSA-PSS", PREFIX + "PSSSignatureSpi$nonePSS");

            provider.addAlgorithm("Alg.Alias.Signature.RAWRSA", "RSA");
            provider.addAlgorithm("Alg.Alias.Signature.NONEWITHRSA", "RSA");
            provider.addAlgorithm("Alg.Alias.Signature.RAWRSAPSS", "RAWRSASSA-PSS");
            provider.addAlgorithm("Alg.Alias.Signature.NONEWITHRSAPSS", "RAWRSASSA-PSS");
            provider.addAlgorithm("Alg.Alias.Signature.NONEWITHRSASSA-PSS", "RAWRSASSA-PSS");
            provider.addAlgorithm("Alg.Alias.Signature.NONEWITHRSAANDMGF1", "RAWRSASSA-PSS");
            provider.addAlgorithm("Alg.Alias.Signature.RSAPSS", "RSASSA-PSS");

            addPSSSignature(provider, "SHA224", PREFIX + "PSSSignatureSpi$SHA224withRSA");
            addPSSSignature(provider, "SHA256", PREFIX + "PSSSignatureSpi$SHA256withRSA");
            addPSSSignature(provider, "SHA384", PREFIX + "PSSSignatureSpi$SHA384withRSA");
            addPSSSignature(provider, "SHA512", PREFIX + "PSSSignatureSpi$SHA512withRSA");
            addPSSSignature(provider, "SHA512(224)", PREFIX + "PSSSignatureSpi$SHA512_224withRSA");
            addPSSSignature(provider, "SHA512(256)", PREFIX + "PSSSignatureSpi$SHA512_256withRSA");

            addPSSSignature(provider, "SHA3-224", PREFIX + "PSSSignatureSpi$SHA3_224withRSA");
            addPSSSignature(provider, "SHA3-256", PREFIX + "PSSSignatureSpi$SHA3_256withRSA");
            addPSSSignature(provider, "SHA3-384", PREFIX + "PSSSignatureSpi$SHA3_384withRSA");
            addPSSSignature(provider, "SHA3-512", PREFIX + "PSSSignatureSpi$SHA3_512withRSA");

            if (provider.hasAlgorithm("MessageDigest", "MD2"))
            {
                addDigestSignature(provider, "MD2", PREFIX + "DigestSignatureSpi$MD2", PKCSObjectIdentifiers.md2WithRSAEncryption);
            }

            if (provider.hasAlgorithm("MessageDigest", "MD4"))
            {
                addDigestSignature(provider, "MD4", PREFIX + "DigestSignatureSpi$MD4", PKCSObjectIdentifiers.md4WithRSAEncryption);
            }

            if (provider.hasAlgorithm("MessageDigest", "MD5"))
            {
                addDigestSignature(provider, "MD5", PREFIX + "DigestSignatureSpi$MD5", PKCSObjectIdentifiers.md5WithRSAEncryption);
                addISO9796Signature(provider, "MD5", PREFIX + "ISOSignatureSpi$MD5WithRSAEncryption");
            }

            if (provider.hasAlgorithm("MessageDigest", "SHA1"))
            {
                provider.addAlgorithm("Alg.Alias.AlgorithmParameters.SHA1withRSA/PSS", "PSS");
                provider.addAlgorithm("Alg.Alias.AlgorithmParameters.SHA1WITHRSAANDMGF1", "PSS");

                addPSSSignature(provider, "SHA1", PREFIX + "PSSSignatureSpi$SHA1withRSA");
                addDigestSignature(provider, "SHA1", PREFIX + "DigestSignatureSpi$SHA1", PKCSObjectIdentifiers.sha1WithRSAEncryption);
                addISO9796Signature(provider, "SHA1", PREFIX + "ISOSignatureSpi$SHA1WithRSAEncryption");

                provider.addAlgorithm("Alg.Alias.Signature." + OIWObjectIdentifiers.sha1WithRSA, "SHA1WITHRSA");
                provider.addAlgorithm("Alg.Alias.Signature.OID." + OIWObjectIdentifiers.sha1WithRSA, "SHA1WITHRSA");

                addX931Signature(provider, "SHA1", PREFIX + "X931SignatureSpi$SHA1WithRSAEncryption");
            }

            addDigestSignature(provider, "SHA224", PREFIX + "DigestSignatureSpi$SHA224", PKCSObjectIdentifiers.sha224WithRSAEncryption);
            addDigestSignature(provider, "SHA256", PREFIX + "DigestSignatureSpi$SHA256", PKCSObjectIdentifiers.sha256WithRSAEncryption);
            addDigestSignature(provider, "SHA384", PREFIX + "DigestSignatureSpi$SHA384", PKCSObjectIdentifiers.sha384WithRSAEncryption);
            addDigestSignature(provider, "SHA512", PREFIX + "DigestSignatureSpi$SHA512", PKCSObjectIdentifiers.sha512WithRSAEncryption);
            addDigestSignature(provider, "SHA512(224)", PREFIX + "DigestSignatureSpi$SHA512_224", PKCSObjectIdentifiers.sha512_224WithRSAEncryption);
            addDigestSignature(provider, "SHA512(256)", PREFIX + "DigestSignatureSpi$SHA512_256", PKCSObjectIdentifiers.sha512_256WithRSAEncryption);

            addDigestSignature(provider, "SHA3-224", PREFIX + "DigestSignatureSpi$SHA3_224", NISTObjectIdentifiers.id_rsassa_pkcs1_v1_5_with_sha3_224);
            addDigestSignature(provider, "SHA3-256", PREFIX + "DigestSignatureSpi$SHA3_256", NISTObjectIdentifiers.id_rsassa_pkcs1_v1_5_with_sha3_256);
            addDigestSignature(provider, "SHA3-384", PREFIX + "DigestSignatureSpi$SHA3_384", NISTObjectIdentifiers.id_rsassa_pkcs1_v1_5_with_sha3_384);
            addDigestSignature(provider, "SHA3-512", PREFIX + "DigestSignatureSpi$SHA3_512", NISTObjectIdentifiers.id_rsassa_pkcs1_v1_5_with_sha3_512);

            addISO9796Signature(provider, "SHA224", PREFIX + "ISOSignatureSpi$SHA224WithRSAEncryption");
            addISO9796Signature(provider, "SHA256", PREFIX + "ISOSignatureSpi$SHA256WithRSAEncryption");
            addISO9796Signature(provider, "SHA384", PREFIX + "ISOSignatureSpi$SHA384WithRSAEncryption");
            addISO9796Signature(provider, "SHA512", PREFIX + "ISOSignatureSpi$SHA512WithRSAEncryption");
            addISO9796Signature(provider, "SHA512(224)", PREFIX + "ISOSignatureSpi$SHA512_224WithRSAEncryption");
            addISO9796Signature(provider, "SHA512(256)", PREFIX + "ISOSignatureSpi$SHA512_256WithRSAEncryption");

            addX931Signature(provider, "SHA224", PREFIX + "X931SignatureSpi$SHA224WithRSAEncryption");
            addX931Signature(provider, "SHA256", PREFIX + "X931SignatureSpi$SHA256WithRSAEncryption");
            addX931Signature(provider, "SHA384", PREFIX + "X931SignatureSpi$SHA384WithRSAEncryption");
            addX931Signature(provider, "SHA512", PREFIX + "X931SignatureSpi$SHA512WithRSAEncryption");
            addX931Signature(provider, "SHA512(224)", PREFIX + "X931SignatureSpi$SHA512_224WithRSAEncryption");
            addX931Signature(provider, "SHA512(256)", PREFIX + "X931SignatureSpi$SHA512_256WithRSAEncryption");

            if (provider.hasAlgorithm("MessageDigest", "RIPEMD128"))
            {
                addDigestSignature(provider, "RIPEMD128", PREFIX + "DigestSignatureSpi$RIPEMD128", TeleTrusTObjectIdentifiers.rsaSignatureWithripemd128);
                addDigestSignature(provider, "RMD128", PREFIX + "DigestSignatureSpi$RIPEMD128", null);

                addX931Signature(provider, "RMD128", PREFIX + "X931SignatureSpi$RIPEMD128WithRSAEncryption");
                addX931Signature(provider, "RIPEMD128", PREFIX + "X931SignatureSpi$RIPEMD128WithRSAEncryption");
            }

            if (provider.hasAlgorithm("MessageDigest", "RIPEMD160"))
            {
                addDigestSignature(provider, "RIPEMD160", PREFIX + "DigestSignatureSpi$RIPEMD160", TeleTrusTObjectIdentifiers.rsaSignatureWithripemd160);
                addDigestSignature(provider, "RMD160", PREFIX + "DigestSignatureSpi$RIPEMD160", null);
                provider.addAlgorithm("Alg.Alias.Signature.RIPEMD160WithRSA/ISO9796-2", "RIPEMD160withRSA/ISO9796-2");
                provider.addAlgorithm("Signature.RIPEMD160withRSA/ISO9796-2", PREFIX + "ISOSignatureSpi$RIPEMD160WithRSAEncryption");

                addX931Signature(provider, "RMD160", PREFIX + "X931SignatureSpi$RIPEMD160WithRSAEncryption");
                addX931Signature(provider, "RIPEMD160", PREFIX + "X931SignatureSpi$RIPEMD160WithRSAEncryption");
            }

            if (provider.hasAlgorithm("MessageDigest", "RIPEMD256"))
            {
                addDigestSignature(provider, "RIPEMD256", PREFIX + "DigestSignatureSpi$RIPEMD256", TeleTrusTObjectIdentifiers.rsaSignatureWithripemd256);
                addDigestSignature(provider, "RMD256", PREFIX + "DigestSignatureSpi$RIPEMD256", null);
            }

            if (provider.hasAlgorithm("MessageDigest", "WHIRLPOOL"))
            {
                addISO9796Signature(provider, "Whirlpool", PREFIX + "ISOSignatureSpi$WhirlpoolWithRSAEncryption");
                addISO9796Signature(provider, "WHIRLPOOL", PREFIX + "ISOSignatureSpi$WhirlpoolWithRSAEncryption");
                addX931Signature(provider, "Whirlpool", PREFIX + "X931SignatureSpi$WhirlpoolWithRSAEncryption");
                addX931Signature(provider, "WHIRLPOOL", PREFIX + "X931SignatureSpi$WhirlpoolWithRSAEncryption");
            }
        }

        private void addDigestSignature(
            ConfigurableProvider provider,
            String digest,
            String className,
            ASN1ObjectIdentifier oid)
        {
            String mainName = digest + "WITHRSA";
            String jdk11Variation1 = digest + "withRSA";
            String jdk11Variation2 = digest + "WithRSA";
            String alias = digest + "/" + "RSA";
            String longName = digest + "WITHRSAENCRYPTION";
            String longJdk11Variation1 = digest + "withRSAEncryption";
            String longJdk11Variation2 = digest + "WithRSAEncryption";

            provider.addAlgorithm("Signature." + mainName, className);
            provider.addAlgorithm("Alg.Alias.Signature." + jdk11Variation1, mainName);
            provider.addAlgorithm("Alg.Alias.Signature." + jdk11Variation2, mainName);
            provider.addAlgorithm("Alg.Alias.Signature." + longName, mainName);
            provider.addAlgorithm("Alg.Alias.Signature." + longJdk11Variation1, mainName);
            provider.addAlgorithm("Alg.Alias.Signature." + longJdk11Variation2, mainName);
            provider.addAlgorithm("Alg.Alias.Signature." + alias, mainName);

            if (oid != null)
            {
                provider.addAlgorithm("Alg.Alias.Signature." + oid, mainName);
                provider.addAlgorithm("Alg.Alias.Signature.OID." + oid, mainName);
            }
        }

        private void addISO9796Signature(
            ConfigurableProvider provider,
            String digest,
            String className)
        {
            provider.addAlgorithm("Alg.Alias.Signature." + digest + "withRSA/ISO9796-2", digest + "WITHRSA/ISO9796-2");
            provider.addAlgorithm("Alg.Alias.Signature." + digest + "WithRSA/ISO9796-2", digest + "WITHRSA/ISO9796-2");
            provider.addAlgorithm("Signature." + digest + "WITHRSA/ISO9796-2", className);
        }

        private void addPSSSignature(
            ConfigurableProvider provider,
            String digest,
            String className)
        {
            provider.addAlgorithm("Alg.Alias.Signature." + digest + "withRSA/PSS", digest + "WITHRSAANDMGF1");
            provider.addAlgorithm("Alg.Alias.Signature." + digest + "WithRSA/PSS", digest + "WITHRSAANDMGF1");
            provider.addAlgorithm("Alg.Alias.Signature." + digest + "withRSAandMGF1", digest + "WITHRSAANDMGF1");
            provider.addAlgorithm("Alg.Alias.Signature." + digest + "WithRSAAndMGF1", digest + "WITHRSAANDMGF1");
            provider.addAlgorithm("Alg.Alias.Signature." + digest + "withRSASSA-PSS", digest + "WITHRSAANDMGF1");
            provider.addAlgorithm("Alg.Alias.Signature." + digest + "WithRSASSA-PSS", digest + "WITHRSAANDMGF1");
            provider.addAlgorithm("Alg.Alias.Signature." + digest + "WITHRSASSA-PSS", digest + "WITHRSAANDMGF1");
            provider.addAlgorithm("Signature." + digest + "WITHRSAANDMGF1", className);
        }

        private void addX931Signature(
            ConfigurableProvider provider,
            String digest,
            String className)
        {
            provider.addAlgorithm("Alg.Alias.Signature." + digest + "withRSA/X9.31", digest + "WITHRSA/X9.31");
            provider.addAlgorithm("Alg.Alias.Signature." + digest + "WithRSA/X9.31", digest + "WITHRSA/X9.31");
            provider.addAlgorithm("Signature." + digest + "WITHRSA/X9.31", className);
        }
    }
}
