package org.bouncycastle.jcajce.provider.asymmetric;

import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.asn1.bsi.BSIObjectIdentifiers;
import org.bouncycastle.asn1.eac.EACObjectIdentifiers;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.sec.SECObjectIdentifiers;
import org.bouncycastle.asn1.teletrust.TeleTrusTObjectIdentifiers;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.jcajce.provider.asymmetric.ec.KeyFactorySpi;
import org.bouncycastle.jcajce.provider.config.ConfigurableProvider;
import org.bouncycastle.jcajce.provider.util.AsymmetricAlgorithmProvider;
import org.bouncycastle.util.Properties;

public class EC
{
    private static final String PREFIX = "org.bouncycastle.jcajce.provider.asymmetric" + ".ec.";

    private static final Map<String, String> generalEcAttributes = new HashMap<String, String>();

    static
    {
        generalEcAttributes.put("SupportedKeyClasses", "java.security.interfaces.ECPublicKey|java.security.interfaces.ECPrivateKey");
        generalEcAttributes.put("SupportedKeyFormats", "PKCS#8|X.509");
    }

    public static class Mappings
        extends AsymmetricAlgorithmProvider
    {
        public Mappings()
        {
        }

        public void configure(ConfigurableProvider provider)
        {
            provider.addAlgorithm("AlgorithmParameters.EC", PREFIX + "AlgorithmParametersSpi");

            provider.addAttributes("KeyAgreement.ECDH", generalEcAttributes);
            provider.addAlgorithm("KeyAgreement.ECDH", PREFIX + "KeyAgreementSpi$DH");
            provider.addAttributes("KeyAgreement.ECDHC", generalEcAttributes);
            provider.addAlgorithm("KeyAgreement.ECDHC", PREFIX + "KeyAgreementSpi$DHC");
            provider.addAttributes("KeyAgreement.ECCDH", generalEcAttributes);
            provider.addAlgorithm("KeyAgreement.ECCDH", PREFIX + "KeyAgreementSpi$DHC");

            provider.addAttributes("KeyAgreement.ECCDHU", generalEcAttributes);
            provider.addAlgorithm("KeyAgreement.ECCDHU", PREFIX + "KeyAgreementSpi$DHUC");

            provider.addAlgorithm("KeyAgreement.ECDHWITHSHA1KDF", PREFIX + "KeyAgreementSpi$DHwithSHA1KDFAndSharedInfo");
            provider.addAlgorithm("KeyAgreement.ECCDHWITHSHA1KDF", PREFIX + "KeyAgreementSpi$CDHwithSHA1KDFAndSharedInfo");

            provider.addAlgorithm("KeyAgreement.ECDHWITHSHA224KDF", PREFIX + "KeyAgreementSpi$DHwithSHA224KDFAndSharedInfo");
            provider.addAlgorithm("KeyAgreement.ECCDHWITHSHA224KDF", PREFIX + "KeyAgreementSpi$CDHwithSHA224KDFAndSharedInfo");

            provider.addAlgorithm("KeyAgreement.ECDHWITHSHA256KDF", PREFIX + "KeyAgreementSpi$DHwithSHA256KDFAndSharedInfo");
            provider.addAlgorithm("KeyAgreement.ECCDHWITHSHA256KDF", PREFIX + "KeyAgreementSpi$CDHwithSHA256KDFAndSharedInfo");

            provider.addAlgorithm("KeyAgreement.ECDHWITHSHA384KDF", PREFIX + "KeyAgreementSpi$DHwithSHA384KDFAndSharedInfo");
            provider.addAlgorithm("KeyAgreement.ECCDHWITHSHA384KDF", PREFIX + "KeyAgreementSpi$CDHwithSHA384KDFAndSharedInfo");

            provider.addAlgorithm("KeyAgreement.ECDHWITHSHA512KDF", PREFIX + "KeyAgreementSpi$DHwithSHA512KDFAndSharedInfo");
            provider.addAlgorithm("KeyAgreement.ECCDHWITHSHA512KDF", PREFIX + "KeyAgreementSpi$CDHwithSHA512KDFAndSharedInfo");

            provider.addAlgorithm("KeyAgreement", X9ObjectIdentifiers.dhSinglePass_stdDH_sha1kdf_scheme, PREFIX + "KeyAgreementSpi$DHwithSHA1KDFAndSharedInfo");
            provider.addAlgorithm("KeyAgreement", X9ObjectIdentifiers.dhSinglePass_cofactorDH_sha1kdf_scheme, PREFIX + "KeyAgreementSpi$CDHwithSHA1KDFAndSharedInfo");

            provider.addAlgorithm("KeyAgreement", SECObjectIdentifiers.dhSinglePass_stdDH_sha224kdf_scheme, PREFIX + "KeyAgreementSpi$DHwithSHA224KDFAndSharedInfo");
            provider.addAlgorithm("KeyAgreement", SECObjectIdentifiers.dhSinglePass_cofactorDH_sha224kdf_scheme, PREFIX + "KeyAgreementSpi$CDHwithSHA224KDFAndSharedInfo");

            provider.addAlgorithm("KeyAgreement", SECObjectIdentifiers.dhSinglePass_stdDH_sha256kdf_scheme, PREFIX + "KeyAgreementSpi$DHwithSHA256KDFAndSharedInfo");
            provider.addAlgorithm("KeyAgreement", SECObjectIdentifiers.dhSinglePass_cofactorDH_sha256kdf_scheme, PREFIX + "KeyAgreementSpi$CDHwithSHA256KDFAndSharedInfo");

            provider.addAlgorithm("KeyAgreement", SECObjectIdentifiers.dhSinglePass_stdDH_sha384kdf_scheme, PREFIX + "KeyAgreementSpi$DHwithSHA384KDFAndSharedInfo");
            provider.addAlgorithm("KeyAgreement", SECObjectIdentifiers.dhSinglePass_cofactorDH_sha384kdf_scheme, PREFIX + "KeyAgreementSpi$CDHwithSHA384KDFAndSharedInfo");

            provider.addAlgorithm("KeyAgreement", SECObjectIdentifiers.dhSinglePass_stdDH_sha512kdf_scheme, PREFIX + "KeyAgreementSpi$DHwithSHA512KDFAndSharedInfo");
            provider.addAlgorithm("KeyAgreement", SECObjectIdentifiers.dhSinglePass_cofactorDH_sha512kdf_scheme, PREFIX + "KeyAgreementSpi$CDHwithSHA512KDFAndSharedInfo");

            provider.addAlgorithm("KeyAgreement.ECCDHWITHSHA1CKDF", PREFIX + "KeyAgreementSpi$DHwithSHA1CKDF");
            provider.addAlgorithm("KeyAgreement.ECCDHWITHSHA256CKDF", PREFIX + "KeyAgreementSpi$DHwithSHA256CKDF");
            provider.addAlgorithm("KeyAgreement.ECCDHWITHSHA384CKDF", PREFIX + "KeyAgreementSpi$DHwithSHA384CKDF");
            provider.addAlgorithm("KeyAgreement.ECCDHWITHSHA512CKDF", PREFIX + "KeyAgreementSpi$DHwithSHA512CKDF");

            provider.addAlgorithm("KeyAgreement.ECCDHUWITHSHA1CKDF", PREFIX + "KeyAgreementSpi$DHUwithSHA1CKDF");
            provider.addAlgorithm("KeyAgreement.ECCDHUWITHSHA224CKDF", PREFIX + "KeyAgreementSpi$DHUwithSHA224CKDF");
            provider.addAlgorithm("KeyAgreement.ECCDHUWITHSHA256CKDF", PREFIX + "KeyAgreementSpi$DHUwithSHA256CKDF");
            provider.addAlgorithm("KeyAgreement.ECCDHUWITHSHA384CKDF", PREFIX + "KeyAgreementSpi$DHUwithSHA384CKDF");
            provider.addAlgorithm("KeyAgreement.ECCDHUWITHSHA512CKDF", PREFIX + "KeyAgreementSpi$DHUwithSHA512CKDF");

            provider.addAlgorithm("KeyAgreement.ECCDHUWITHSHA1KDF", PREFIX + "KeyAgreementSpi$DHUwithSHA1KDF");
            provider.addAlgorithm("KeyAgreement.ECCDHUWITHSHA224KDF", PREFIX + "KeyAgreementSpi$DHUwithSHA224KDF");
            provider.addAlgorithm("KeyAgreement.ECCDHUWITHSHA256KDF", PREFIX + "KeyAgreementSpi$DHUwithSHA256KDF");
            provider.addAlgorithm("KeyAgreement.ECCDHUWITHSHA384KDF", PREFIX + "KeyAgreementSpi$DHUwithSHA384KDF");
            provider.addAlgorithm("KeyAgreement.ECCDHUWITHSHA512KDF", PREFIX + "KeyAgreementSpi$DHUwithSHA512KDF");

            provider.addAlgorithm("KeyAgreement.ECKAEGWITHSHA1KDF", PREFIX + "KeyAgreementSpi$ECKAEGwithSHA1KDF");
            provider.addAlgorithm("KeyAgreement.ECKAEGWITHSHA224KDF", PREFIX + "KeyAgreementSpi$ECKAEGwithSHA224KDF");
            provider.addAlgorithm("KeyAgreement.ECKAEGWITHSHA256KDF", PREFIX + "KeyAgreementSpi$ECKAEGwithSHA256KDF");
            provider.addAlgorithm("KeyAgreement.ECKAEGWITHSHA384KDF", PREFIX + "KeyAgreementSpi$ECKAEGwithSHA384KDF");
            provider.addAlgorithm("KeyAgreement.ECKAEGWITHSHA512KDF", PREFIX + "KeyAgreementSpi$ECKAEGwithSHA512KDF");

            provider.addAlgorithm("KeyAgreement", BSIObjectIdentifiers.ecka_eg_X963kdf_SHA1, PREFIX + "KeyAgreementSpi$ECKAEGwithSHA1KDF");
            provider.addAlgorithm("KeyAgreement", BSIObjectIdentifiers.ecka_eg_X963kdf_SHA224, PREFIX + "KeyAgreementSpi$ECKAEGwithSHA224KDF");
            provider.addAlgorithm("KeyAgreement", BSIObjectIdentifiers.ecka_eg_X963kdf_SHA256, PREFIX + "KeyAgreementSpi$ECKAEGwithSHA256KDF");
            provider.addAlgorithm("KeyAgreement", BSIObjectIdentifiers.ecka_eg_X963kdf_SHA384, PREFIX + "KeyAgreementSpi$ECKAEGwithSHA384KDF");
            provider.addAlgorithm("KeyAgreement", BSIObjectIdentifiers.ecka_eg_X963kdf_SHA512, PREFIX + "KeyAgreementSpi$ECKAEGwithSHA512KDF");

            provider.addAlgorithm("KeyAgreement", BSIObjectIdentifiers.ecka_eg_X963kdf_RIPEMD160, PREFIX + "KeyAgreementSpi$ECKAEGwithRIPEMD160KDF");
            provider.addAlgorithm("KeyAgreement.ECKAEGWITHRIPEMD160KDF", PREFIX + "KeyAgreementSpi$ECKAEGwithRIPEMD160KDF");

            registerOid(provider, X9ObjectIdentifiers.id_ecPublicKey, "EC", new KeyFactorySpi.EC());

            registerOid(provider, X9ObjectIdentifiers.dhSinglePass_cofactorDH_sha1kdf_scheme, "EC", new KeyFactorySpi.EC());
            registerOid(provider, X9ObjectIdentifiers.mqvSinglePass_sha1kdf_scheme, "ECMQV", new KeyFactorySpi.ECMQV());

            registerOid(provider, SECObjectIdentifiers.dhSinglePass_stdDH_sha224kdf_scheme, "EC", new KeyFactorySpi.EC());
            registerOid(provider, SECObjectIdentifiers.dhSinglePass_cofactorDH_sha224kdf_scheme, "EC", new KeyFactorySpi.EC());

            registerOid(provider, SECObjectIdentifiers.dhSinglePass_stdDH_sha256kdf_scheme, "EC", new KeyFactorySpi.EC());
            registerOid(provider, SECObjectIdentifiers.dhSinglePass_cofactorDH_sha256kdf_scheme, "EC", new KeyFactorySpi.EC());

            registerOid(provider, SECObjectIdentifiers.dhSinglePass_stdDH_sha384kdf_scheme, "EC", new KeyFactorySpi.EC());
            registerOid(provider, SECObjectIdentifiers.dhSinglePass_cofactorDH_sha384kdf_scheme, "EC", new KeyFactorySpi.EC());

            registerOid(provider, SECObjectIdentifiers.dhSinglePass_stdDH_sha512kdf_scheme, "EC", new KeyFactorySpi.EC());
            registerOid(provider, SECObjectIdentifiers.dhSinglePass_cofactorDH_sha512kdf_scheme, "EC", new KeyFactorySpi.EC());

            registerOidAlgorithmParameters(provider, X9ObjectIdentifiers.id_ecPublicKey, "EC");

            registerOidAlgorithmParameters(provider, X9ObjectIdentifiers.dhSinglePass_stdDH_sha1kdf_scheme, "EC");
            registerOidAlgorithmParameters(provider, X9ObjectIdentifiers.dhSinglePass_cofactorDH_sha1kdf_scheme, "EC");

            registerOidAlgorithmParameters(provider, SECObjectIdentifiers.dhSinglePass_stdDH_sha224kdf_scheme, "EC");
            registerOidAlgorithmParameters(provider, SECObjectIdentifiers.dhSinglePass_cofactorDH_sha224kdf_scheme, "EC");

            registerOidAlgorithmParameters(provider, SECObjectIdentifiers.dhSinglePass_stdDH_sha256kdf_scheme, "EC");
            registerOidAlgorithmParameters(provider, SECObjectIdentifiers.dhSinglePass_cofactorDH_sha256kdf_scheme, "EC");

            registerOidAlgorithmParameters(provider, SECObjectIdentifiers.dhSinglePass_stdDH_sha384kdf_scheme, "EC");
            registerOidAlgorithmParameters(provider, SECObjectIdentifiers.dhSinglePass_cofactorDH_sha384kdf_scheme, "EC");

            registerOidAlgorithmParameters(provider, SECObjectIdentifiers.dhSinglePass_stdDH_sha512kdf_scheme, "EC");
            registerOidAlgorithmParameters(provider, SECObjectIdentifiers.dhSinglePass_cofactorDH_sha512kdf_scheme, "EC");

            if (!Properties.isOverrideSet("org.bouncycastle.ec.disable_mqv"))
            {
                provider.addAlgorithm("KeyAgreement.ECMQV", PREFIX + "KeyAgreementSpi$MQV");

                provider.addAlgorithm("KeyAgreement.ECMQVWITHSHA1CKDF", PREFIX + "KeyAgreementSpi$MQVwithSHA1CKDF");
                provider.addAlgorithm("KeyAgreement.ECMQVWITHSHA224CKDF", PREFIX + "KeyAgreementSpi$MQVwithSHA224CKDF");
                provider.addAlgorithm("KeyAgreement.ECMQVWITHSHA256CKDF", PREFIX + "KeyAgreementSpi$MQVwithSHA256CKDF");
                provider.addAlgorithm("KeyAgreement.ECMQVWITHSHA384CKDF", PREFIX + "KeyAgreementSpi$MQVwithSHA384CKDF");
                provider.addAlgorithm("KeyAgreement.ECMQVWITHSHA512CKDF", PREFIX + "KeyAgreementSpi$MQVwithSHA512CKDF");

                provider.addAlgorithm("KeyAgreement.ECMQVWITHSHA1KDF", PREFIX + "KeyAgreementSpi$MQVwithSHA1KDF");
                provider.addAlgorithm("KeyAgreement.ECMQVWITHSHA224KDF", PREFIX + "KeyAgreementSpi$MQVwithSHA224KDF");
                provider.addAlgorithm("KeyAgreement.ECMQVWITHSHA256KDF", PREFIX + "KeyAgreementSpi$MQVwithSHA256KDF");
                provider.addAlgorithm("KeyAgreement.ECMQVWITHSHA384KDF", PREFIX + "KeyAgreementSpi$MQVwithSHA384KDF");
                provider.addAlgorithm("KeyAgreement.ECMQVWITHSHA512KDF", PREFIX + "KeyAgreementSpi$MQVwithSHA512KDF");

                provider.addAlgorithm("KeyAgreement." + X9ObjectIdentifiers.mqvSinglePass_sha1kdf_scheme, PREFIX + "KeyAgreementSpi$MQVwithSHA1KDFAndSharedInfo");
                provider.addAlgorithm("KeyAgreement." + SECObjectIdentifiers.mqvSinglePass_sha224kdf_scheme, PREFIX + "KeyAgreementSpi$MQVwithSHA224KDFAndSharedInfo");
                provider.addAlgorithm("KeyAgreement." + SECObjectIdentifiers.mqvSinglePass_sha256kdf_scheme, PREFIX + "KeyAgreementSpi$MQVwithSHA256KDFAndSharedInfo");
                provider.addAlgorithm("KeyAgreement." + SECObjectIdentifiers.mqvSinglePass_sha384kdf_scheme, PREFIX + "KeyAgreementSpi$MQVwithSHA384KDFAndSharedInfo");
                provider.addAlgorithm("KeyAgreement." + SECObjectIdentifiers.mqvSinglePass_sha512kdf_scheme, PREFIX + "KeyAgreementSpi$MQVwithSHA512KDFAndSharedInfo");

                registerOid(provider, X9ObjectIdentifiers.dhSinglePass_stdDH_sha1kdf_scheme, "EC", new KeyFactorySpi.EC());
                registerOidAlgorithmParameters(provider, X9ObjectIdentifiers.mqvSinglePass_sha1kdf_scheme, "EC");

                registerOid(provider, SECObjectIdentifiers.mqvSinglePass_sha224kdf_scheme, "ECMQV", new KeyFactorySpi.ECMQV());
                registerOidAlgorithmParameters(provider, SECObjectIdentifiers.mqvSinglePass_sha256kdf_scheme, "EC");

                registerOid(provider, SECObjectIdentifiers.mqvSinglePass_sha256kdf_scheme, "ECMQV", new KeyFactorySpi.ECMQV());
                registerOidAlgorithmParameters(provider, SECObjectIdentifiers.mqvSinglePass_sha224kdf_scheme, "EC");

                registerOid(provider, SECObjectIdentifiers.mqvSinglePass_sha384kdf_scheme, "ECMQV", new KeyFactorySpi.ECMQV());
                registerOidAlgorithmParameters(provider, SECObjectIdentifiers.mqvSinglePass_sha384kdf_scheme, "EC");

                registerOid(provider, SECObjectIdentifiers.mqvSinglePass_sha512kdf_scheme, "ECMQV", new KeyFactorySpi.ECMQV());
                registerOidAlgorithmParameters(provider, SECObjectIdentifiers.mqvSinglePass_sha512kdf_scheme, "EC");

                provider.addAlgorithm("KeyFactory.ECMQV", PREFIX + "KeyFactorySpi$ECMQV");
                provider.addAlgorithm("KeyPairGenerator.ECMQV", PREFIX + "KeyPairGeneratorSpi$ECMQV");
            }

            provider.addAlgorithm("KeyFactory.EC", PREFIX + "KeyFactorySpi$EC");
            provider.addAlgorithm("KeyFactory.ECDSA", PREFIX + "KeyFactorySpi$ECDSA");
            provider.addAlgorithm("KeyFactory.ECDH", PREFIX + "KeyFactorySpi$ECDH");
            provider.addAlgorithm("KeyFactory.ECDHC", PREFIX + "KeyFactorySpi$ECDHC");

            provider.addAlgorithm("KeyPairGenerator.EC", PREFIX + "KeyPairGeneratorSpi$EC");
            provider.addAlgorithm("KeyPairGenerator.ECDSA", PREFIX + "KeyPairGeneratorSpi$ECDSA");
            provider.addAlgorithm("KeyPairGenerator.ECDH", PREFIX + "KeyPairGeneratorSpi$ECDH");
            provider.addAlgorithm("KeyPairGenerator.ECDHWITHSHA1KDF", PREFIX + "KeyPairGeneratorSpi$ECDH");
            provider.addAlgorithm("KeyPairGenerator.ECDHC", PREFIX + "KeyPairGeneratorSpi$ECDHC");
            provider.addAlgorithm("KeyPairGenerator.ECIES", PREFIX + "KeyPairGeneratorSpi$ECDH");

            provider.addAlgorithm("Cipher.ECIES", PREFIX + "IESCipher$ECIES");

            provider.addAlgorithm("Cipher.ECIESwithAES-CBC", PREFIX + "IESCipher$ECIESwithAESCBC");
            provider.addAlgorithm("Cipher.ECIESWITHAES-CBC", PREFIX + "IESCipher$ECIESwithAESCBC");
            provider.addAlgorithm("Cipher.ECIESwithDESEDE-CBC", PREFIX + "IESCipher$ECIESwithDESedeCBC");
            provider.addAlgorithm("Cipher.ECIESWITHDESEDE-CBC", PREFIX + "IESCipher$ECIESwithDESedeCBC");

            provider.addAlgorithm("Signature.ECDSA", PREFIX + "SignatureSpi$ecDSA");
            provider.addAlgorithm("Signature.NONEwithECDSA", PREFIX + "SignatureSpi$ecDSAnone");

            provider.addAlgorithm("Alg.Alias.Signature.SHA1withECDSA", "ECDSA");
            provider.addAlgorithm("Alg.Alias.Signature.ECDSAwithSHA1", "ECDSA");
            provider.addAlgorithm("Alg.Alias.Signature.SHA1WITHECDSA", "ECDSA");
            provider.addAlgorithm("Alg.Alias.Signature.ECDSAWITHSHA1", "ECDSA");
            provider.addAlgorithm("Alg.Alias.Signature.SHA1WithECDSA", "ECDSA");
            provider.addAlgorithm("Alg.Alias.Signature.ECDSAWithSHA1", "ECDSA");
            provider.addAlgorithm("Alg.Alias.Signature.1.2.840.10045.4.1", "ECDSA");
            provider.addAlgorithm("Alg.Alias.Signature." + TeleTrusTObjectIdentifiers.ecSignWithSha1, "ECDSA");

            provider.addAlgorithm("Signature.ECDDSA", PREFIX + "SignatureSpi$ecDetDSA");
            provider.addAlgorithm("Signature.SHA1WITHECDDSA", PREFIX + "SignatureSpi$ecDetDSA");
            provider.addAlgorithm("Signature.SHA224WITHECDDSA", PREFIX + "SignatureSpi$ecDetDSA224");
            provider.addAlgorithm("Signature.SHA256WITHECDDSA", PREFIX + "SignatureSpi$ecDetDSA256");
            provider.addAlgorithm("Signature.SHA384WITHECDDSA", PREFIX + "SignatureSpi$ecDetDSA384");
            provider.addAlgorithm("Signature.SHA512WITHECDDSA", PREFIX + "SignatureSpi$ecDetDSA512");
            provider.addAlgorithm("Signature.SHA3-224WITHECDDSA", PREFIX + "SignatureSpi$ecDetDSASha3_224");
            provider.addAlgorithm("Signature.SHA3-256WITHECDDSA", PREFIX + "SignatureSpi$ecDetDSASha3_256");
            provider.addAlgorithm("Signature.SHA3-384WITHECDDSA", PREFIX + "SignatureSpi$ecDetDSASha3_384");
            provider.addAlgorithm("Signature.SHA3-512WITHECDDSA", PREFIX + "SignatureSpi$ecDetDSASha3_512");

            provider.addAlgorithm("Alg.Alias.Signature.DETECDSA", "ECDDSA");
            provider.addAlgorithm("Alg.Alias.Signature.SHA1WITHDETECDSA", "SHA1WITHECDDSA");
            provider.addAlgorithm("Alg.Alias.Signature.SHA224WITHDETECDSA", "SHA224WITHECDDSA");
            provider.addAlgorithm("Alg.Alias.Signature.SHA256WITHDETECDSA", "SHA256WITHECDDSA");
            provider.addAlgorithm("Alg.Alias.Signature.SHA384WITHDETECDSA", "SHA384WITHECDDSA");
            provider.addAlgorithm("Alg.Alias.Signature.SHA512WITHDETECDSA", "SHA512WITHECDDSA");

            addSignatureAlgorithm(provider, "SHA224", "ECDSA", PREFIX + "SignatureSpi$ecDSA224", X9ObjectIdentifiers.ecdsa_with_SHA224);
            addSignatureAlgorithm(provider, "SHA256", "ECDSA", PREFIX + "SignatureSpi$ecDSA256", X9ObjectIdentifiers.ecdsa_with_SHA256);
            addSignatureAlgorithm(provider, "SHA384", "ECDSA", PREFIX + "SignatureSpi$ecDSA384", X9ObjectIdentifiers.ecdsa_with_SHA384);
            addSignatureAlgorithm(provider, "SHA512", "ECDSA", PREFIX + "SignatureSpi$ecDSA512", X9ObjectIdentifiers.ecdsa_with_SHA512);
            addSignatureAlgorithm(provider, "SHA3-224", "ECDSA", PREFIX + "SignatureSpi$ecDSASha3_224", NISTObjectIdentifiers.id_ecdsa_with_sha3_224);
            addSignatureAlgorithm(provider, "SHA3-256", "ECDSA", PREFIX + "SignatureSpi$ecDSASha3_256", NISTObjectIdentifiers.id_ecdsa_with_sha3_256);
            addSignatureAlgorithm(provider, "SHA3-384", "ECDSA", PREFIX + "SignatureSpi$ecDSASha3_384", NISTObjectIdentifiers.id_ecdsa_with_sha3_384);
            addSignatureAlgorithm(provider, "SHA3-512", "ECDSA", PREFIX + "SignatureSpi$ecDSASha3_512", NISTObjectIdentifiers.id_ecdsa_with_sha3_512);

            addSignatureAlgorithm(provider, "RIPEMD160", "ECDSA", PREFIX + "SignatureSpi$ecDSARipeMD160",TeleTrusTObjectIdentifiers.ecSignWithRipemd160);

            provider.addAlgorithm("Signature.SHA1WITHECNR", PREFIX + "SignatureSpi$ecNR");
            provider.addAlgorithm("Signature.SHA224WITHECNR", PREFIX + "SignatureSpi$ecNR224");
            provider.addAlgorithm("Signature.SHA256WITHECNR", PREFIX + "SignatureSpi$ecNR256");
            provider.addAlgorithm("Signature.SHA384WITHECNR", PREFIX + "SignatureSpi$ecNR384");
            provider.addAlgorithm("Signature.SHA512WITHECNR", PREFIX + "SignatureSpi$ecNR512");

            addSignatureAlgorithm(provider, "SHA1", "CVC-ECDSA", PREFIX + "SignatureSpi$ecCVCDSA", EACObjectIdentifiers.id_TA_ECDSA_SHA_1);
            addSignatureAlgorithm(provider, "SHA224", "CVC-ECDSA", PREFIX + "SignatureSpi$ecCVCDSA224", EACObjectIdentifiers.id_TA_ECDSA_SHA_224);
            addSignatureAlgorithm(provider, "SHA256", "CVC-ECDSA", PREFIX + "SignatureSpi$ecCVCDSA256", EACObjectIdentifiers.id_TA_ECDSA_SHA_256);
            addSignatureAlgorithm(provider, "SHA384", "CVC-ECDSA", PREFIX + "SignatureSpi$ecCVCDSA384", EACObjectIdentifiers.id_TA_ECDSA_SHA_384);
            addSignatureAlgorithm(provider, "SHA512", "CVC-ECDSA", PREFIX + "SignatureSpi$ecCVCDSA512", EACObjectIdentifiers.id_TA_ECDSA_SHA_512);

            addSignatureAlgorithm(provider, "SHA1", "PLAIN-ECDSA", PREFIX + "SignatureSpi$ecCVCDSA", BSIObjectIdentifiers.ecdsa_plain_SHA1);
            addSignatureAlgorithm(provider, "SHA224", "PLAIN-ECDSA", PREFIX + "SignatureSpi$ecCVCDSA224", BSIObjectIdentifiers.ecdsa_plain_SHA224);
            addSignatureAlgorithm(provider, "SHA256", "PLAIN-ECDSA", PREFIX + "SignatureSpi$ecCVCDSA256", BSIObjectIdentifiers.ecdsa_plain_SHA256);
            addSignatureAlgorithm(provider, "SHA384", "PLAIN-ECDSA", PREFIX + "SignatureSpi$ecCVCDSA384", BSIObjectIdentifiers.ecdsa_plain_SHA384);
            addSignatureAlgorithm(provider, "SHA512", "PLAIN-ECDSA", PREFIX + "SignatureSpi$ecCVCDSA512", BSIObjectIdentifiers.ecdsa_plain_SHA512);
            addSignatureAlgorithm(provider, "RIPEMD160", "PLAIN-ECDSA", PREFIX + "SignatureSpi$ecPlainDSARP160", BSIObjectIdentifiers.ecdsa_plain_RIPEMD160);
        }
    }
}
