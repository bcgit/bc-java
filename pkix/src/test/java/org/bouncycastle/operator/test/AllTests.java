package org.bouncycastle.operator.test;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.spec.MGF1ParameterSpec;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import javax.crypto.spec.SecretKeySpec;

import junit.framework.Assert;
import junit.framework.TestCase;
import junit.framework.TestSuite;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.bc.BCObjectIdentifiers;
import org.bouncycastle.asn1.bsi.BSIObjectIdentifiers;
import org.bouncycastle.asn1.cms.GCMParameters;
import org.bouncycastle.asn1.cryptopro.CryptoProObjectIdentifiers;
import org.bouncycastle.asn1.eac.EACObjectIdentifiers;
import org.bouncycastle.asn1.edec.EdECObjectIdentifiers;
import org.bouncycastle.asn1.gnu.GNUObjectIdentifiers;
import org.bouncycastle.asn1.iana.IANAObjectIdentifiers;
import org.bouncycastle.asn1.kisa.KISAObjectIdentifiers;
import org.bouncycastle.asn1.misc.MiscObjectIdentifiers;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.ntt.NTTObjectIdentifiers;
import org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.RSAESOAEPparams;
import org.bouncycastle.asn1.pkcs.RSASSAPSSparams;
import org.bouncycastle.asn1.rosstandart.RosstandartObjectIdentifiers;
import org.bouncycastle.asn1.teletrust.TeleTrusTObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.generators.MLKEMKeyPairGenerator;
import org.bouncycastle.crypto.kems.MLKEMExtractor;
import org.bouncycastle.crypto.params.MLKEMKeyGenerationParameters;
import org.bouncycastle.crypto.params.MLKEMParameters;
import org.bouncycastle.crypto.params.MLKEMPrivateKeyParameters;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.AlgorithmNameFinder;
import org.bouncycastle.operator.DefaultAlgorithmNameFinder;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DefaultKemEncapsulationLengthProvider;
import org.bouncycastle.operator.DefaultSignatureNameFinder;
import org.bouncycastle.operator.InputDecryptor;
import org.bouncycastle.operator.InputDecryptorProvider;
import org.bouncycastle.operator.KemEncapsulationLengthProvider;
import org.bouncycastle.operator.jcajce.JceAsymmetricKeyWrapper;
import org.bouncycastle.operator.jcajce.JceInputDecryptorProviderBuilder;
import org.bouncycastle.pqc.crypto.hqc.HQCKEMExtractor;
import org.bouncycastle.pqc.crypto.hqc.HQCKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.hqc.HQCKeyPairGenerator;
import org.bouncycastle.pqc.crypto.hqc.HQCParameters;
import org.bouncycastle.pqc.crypto.hqc.HQCPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.ntru.NTRUKEMExtractor;
import org.bouncycastle.pqc.crypto.ntru.NTRUKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.ntru.NTRUKeyPairGenerator;
import org.bouncycastle.pqc.crypto.ntru.NTRUParameters;
import org.bouncycastle.pqc.crypto.ntru.NTRUPrivateKeyParameters;
import org.bouncycastle.test.PrintTestResult;
import org.bouncycastle.util.encoders.Hex;

public class AllTests
    extends TestCase
{
    private static final byte[] TEST_DATA = "Hello world!".getBytes();
    private static final String BC = BouncyCastleProvider.PROVIDER_NAME;

    public void setUp()
    {
        if (Security.getProvider(BC) == null)
        {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    public static void main(String[] args)
    {
        TestSuite suite = new TestSuite();
        suite.addTestSuite(AllTests.class);
        PrintTestResult.printResult(junit.textui.TestRunner.run(suite));
    }

    public void testAgainstKnownList()
        throws Exception
    {
        Object[] values = new Object[]{new Object[]{BSIObjectIdentifiers.ecdsa_plain_RIPEMD160, "RIPEMD160WITHPLAIN-ECDSA"},
            new Object[]{BSIObjectIdentifiers.ecdsa_plain_SHA1, "SHA1WITHPLAIN-ECDSA"},
            new Object[]{BSIObjectIdentifiers.ecdsa_plain_SHA224, "SHA224WITHPLAIN-ECDSA"},
            new Object[]{BSIObjectIdentifiers.ecdsa_plain_SHA256, "SHA256WITHPLAIN-ECDSA"},
            new Object[]{BSIObjectIdentifiers.ecdsa_plain_SHA384, "SHA384WITHPLAIN-ECDSA"},
            new Object[]{BSIObjectIdentifiers.ecdsa_plain_SHA512, "SHA512WITHPLAIN-ECDSA"},
            new Object[]{CryptoProObjectIdentifiers.gostR3411_94_with_gostR3410_2001, "GOST3411WITHECGOST3410-2001"},
            new Object[]{CryptoProObjectIdentifiers.gostR3411_94_with_gostR3410_94, "GOST3411WITHGOST3410-94"},
            new Object[]{CryptoProObjectIdentifiers.gostR3411, "GOST3411"},
            new Object[]{RosstandartObjectIdentifiers.id_tc26_signwithdigest_gost_3410_12_256, "GOST3411WITHECGOST3410-2012-256"},
            new Object[]{RosstandartObjectIdentifiers.id_tc26_signwithdigest_gost_3410_12_512, "GOST3411WITHECGOST3410-2012-512"},
            new Object[]{EACObjectIdentifiers.id_TA_ECDSA_SHA_1, "SHA1WITHCVC-ECDSA"},
            new Object[]{EACObjectIdentifiers.id_TA_ECDSA_SHA_224, "SHA224WITHCVC-ECDSA"},
            new Object[]{EACObjectIdentifiers.id_TA_ECDSA_SHA_256, "SHA256WITHCVC-ECDSA"},
            new Object[]{EACObjectIdentifiers.id_TA_ECDSA_SHA_384, "SHA384WITHCVC-ECDSA"},
            new Object[]{EACObjectIdentifiers.id_TA_ECDSA_SHA_512, "SHA512WITHCVC-ECDSA"},
            new Object[]{NISTObjectIdentifiers.id_sha224, "SHA224"},
            new Object[]{NISTObjectIdentifiers.id_sha256, "SHA256"},
            new Object[]{NISTObjectIdentifiers.id_sha384, "SHA384"},
            new Object[]{NISTObjectIdentifiers.id_sha512, "SHA512"},
            new Object[]{NISTObjectIdentifiers.id_sha3_224, "SHA3-224"},
            new Object[]{NISTObjectIdentifiers.id_sha3_256, "SHA3-256"},
            new Object[]{NISTObjectIdentifiers.id_sha3_384, "SHA3-384"},
            new Object[]{NISTObjectIdentifiers.id_sha3_512, "SHA3-512"},
            new Object[]{OIWObjectIdentifiers.dsaWithSHA1, "SHA1WITHDSA"},
            new Object[]{OIWObjectIdentifiers.elGamalAlgorithm, "ELGAMAL"},
            new Object[]{OIWObjectIdentifiers.idSHA1, "SHA1"},
            new Object[]{OIWObjectIdentifiers.md5WithRSA, "MD5WITHRSA"},
            new Object[]{OIWObjectIdentifiers.sha1WithRSA, "SHA1WITHRSA"},
            new Object[]{PKCSObjectIdentifiers.id_RSAES_OAEP, "RSAOAEP"},
            new Object[]{PKCSObjectIdentifiers.id_RSASSA_PSS, "RSAPSS"},
            new Object[]{PKCSObjectIdentifiers.md2WithRSAEncryption, "MD2WITHRSA"},
            new Object[]{PKCSObjectIdentifiers.md5, "MD5"},
            new Object[]{PKCSObjectIdentifiers.md5WithRSAEncryption, "MD5WITHRSA"},
            new Object[]{PKCSObjectIdentifiers.rsaEncryption, "RSA"},
            new Object[]{PKCSObjectIdentifiers.sha1WithRSAEncryption, "SHA1WITHRSA"},
            new Object[]{PKCSObjectIdentifiers.sha224WithRSAEncryption, "SHA224WITHRSA"},
            new Object[]{PKCSObjectIdentifiers.sha256WithRSAEncryption, "SHA256WITHRSA"},
            new Object[]{PKCSObjectIdentifiers.sha384WithRSAEncryption, "SHA384WITHRSA"},
            new Object[]{PKCSObjectIdentifiers.sha512WithRSAEncryption, "SHA512WITHRSA"},
            new Object[]{NISTObjectIdentifiers.id_rsassa_pkcs1_v1_5_with_sha3_224, "SHA3-224WITHRSA"},
            new Object[]{NISTObjectIdentifiers.id_rsassa_pkcs1_v1_5_with_sha3_256, "SHA3-256WITHRSA"},
            new Object[]{NISTObjectIdentifiers.id_rsassa_pkcs1_v1_5_with_sha3_384, "SHA3-384WITHRSA"},
            new Object[]{NISTObjectIdentifiers.id_rsassa_pkcs1_v1_5_with_sha3_512, "SHA3-512WITHRSA"},
            new Object[]{TeleTrusTObjectIdentifiers.ripemd128, "RIPEMD128"},
            new Object[]{TeleTrusTObjectIdentifiers.ripemd160, "RIPEMD160"},
            new Object[]{TeleTrusTObjectIdentifiers.ripemd256, "RIPEMD256"},
            new Object[]{TeleTrusTObjectIdentifiers.rsaSignatureWithripemd128, "RIPEMD128WITHRSA"},
            new Object[]{TeleTrusTObjectIdentifiers.rsaSignatureWithripemd160, "RIPEMD160WITHRSA"},
            new Object[]{TeleTrusTObjectIdentifiers.rsaSignatureWithripemd256, "RIPEMD256WITHRSA"},
            new Object[]{X9ObjectIdentifiers.ecdsa_with_SHA1, "ECDSAWITHSHA1"},
            new Object[]{X9ObjectIdentifiers.ecdsa_with_SHA224, "SHA224WITHECDSA"},
            new Object[]{X9ObjectIdentifiers.ecdsa_with_SHA256, "SHA256WITHECDSA"},
            new Object[]{X9ObjectIdentifiers.ecdsa_with_SHA384, "SHA384WITHECDSA"},
            new Object[]{X9ObjectIdentifiers.ecdsa_with_SHA512, "SHA512WITHECDSA"},
            new Object[]{NISTObjectIdentifiers.id_ecdsa_with_sha3_224, "SHA3-224WITHECDSA"},
            new Object[]{NISTObjectIdentifiers.id_ecdsa_with_sha3_256, "SHA3-256WITHECDSA"},
            new Object[]{NISTObjectIdentifiers.id_ecdsa_with_sha3_384, "SHA3-384WITHECDSA"},
            new Object[]{NISTObjectIdentifiers.id_ecdsa_with_sha3_512, "SHA3-512WITHECDSA"},
            new Object[]{X9ObjectIdentifiers.id_dsa_with_sha1, "SHA1WITHDSA"},
            new Object[]{NISTObjectIdentifiers.dsa_with_sha224, "SHA224WITHDSA"},
            new Object[]{NISTObjectIdentifiers.dsa_with_sha256, "SHA256WITHDSA"},
            new Object[]{NISTObjectIdentifiers.dsa_with_sha384, "SHA384WITHDSA"},
            new Object[]{NISTObjectIdentifiers.dsa_with_sha512, "SHA512WITHDSA"},
            new Object[]{NISTObjectIdentifiers.id_dsa_with_sha3_224, "SHA3-224WITHDSA"},
            new Object[]{NISTObjectIdentifiers.id_dsa_with_sha3_256, "SHA3-256WITHDSA"},
            new Object[]{NISTObjectIdentifiers.id_dsa_with_sha3_384, "SHA3-384WITHDSA"},
            new Object[]{NISTObjectIdentifiers.id_dsa_with_sha3_512, "SHA3-512WITHDSA"},
            new Object[]{BCObjectIdentifiers.falcon_512, "FALCON"},
            new Object[]{BCObjectIdentifiers.falcon_1024, "FALCON"},
            new Object[]{EdECObjectIdentifiers.id_Ed25519, "ED25519"},
            new Object[]{EdECObjectIdentifiers.id_Ed448, "ED448"},
            new Object[]{EdECObjectIdentifiers.id_X25519, "X25519"},
            new Object[]{EdECObjectIdentifiers.id_X448, "X448"},
            new Object[]{NISTObjectIdentifiers.id_ml_dsa_44, "ML-DSA-44"},
            new Object[]{NISTObjectIdentifiers.id_ml_dsa_65, "ML-DSA-65"},
            new Object[]{NISTObjectIdentifiers.id_ml_dsa_87, "ML-DSA-87"},
            new Object[]{NISTObjectIdentifiers.id_hash_ml_dsa_44_with_sha512, "ML-DSA-44-WITH-SHA512"},
            new Object[]{NISTObjectIdentifiers.id_hash_ml_dsa_65_with_sha512, "ML-DSA-65-WITH-SHA512"},
            new Object[]{NISTObjectIdentifiers.id_hash_ml_dsa_87_with_sha512, "ML-DSA-87-WITH-SHA512"},
            new Object[]{NISTObjectIdentifiers.id_slh_dsa_sha2_128s, "SLH-DSA-SHA2-128S"},
            new Object[]{NISTObjectIdentifiers.id_slh_dsa_sha2_128f, "SLH-DSA-SHA2-128F"},
            new Object[]{NISTObjectIdentifiers.id_slh_dsa_sha2_192s, "SLH-DSA-SHA2-192S"},
            new Object[]{NISTObjectIdentifiers.id_slh_dsa_sha2_192f, "SLH-DSA-SHA2-192F"},
            new Object[]{NISTObjectIdentifiers.id_slh_dsa_sha2_256s, "SLH-DSA-SHA2-256S"},
            new Object[]{NISTObjectIdentifiers.id_slh_dsa_sha2_256f, "SLH-DSA-SHA2-256F"},
            new Object[]{NISTObjectIdentifiers.id_slh_dsa_shake_128s, "SLH-DSA-SHAKE-128S"},
            new Object[]{NISTObjectIdentifiers.id_slh_dsa_shake_128f, "SLH-DSA-SHAKE-128F"},
            new Object[]{NISTObjectIdentifiers.id_slh_dsa_shake_192s, "SLH-DSA-SHAKE-192S"},
            new Object[]{NISTObjectIdentifiers.id_slh_dsa_shake_192f, "SLH-DSA-SHAKE-192F"},
            new Object[]{NISTObjectIdentifiers.id_slh_dsa_shake_256s, "SLH-DSA-SHAKE-256S"},
            new Object[]{NISTObjectIdentifiers.id_slh_dsa_shake_256f, "SLH-DSA-SHAKE-256F"},
            new Object[]{NISTObjectIdentifiers.id_hash_slh_dsa_sha2_128s_with_sha256, "SLH-DSA-SHA2-128S-WITH-SHA256"},
            new Object[]{NISTObjectIdentifiers.id_hash_slh_dsa_sha2_128f_with_sha256, "SLH-DSA-SHA2-128F-WITH-SHA256"},
            new Object[]{NISTObjectIdentifiers.id_hash_slh_dsa_sha2_192s_with_sha512, "SLH-DSA-SHA2-192S-WITH-SHA512"},
            new Object[]{NISTObjectIdentifiers.id_hash_slh_dsa_sha2_192f_with_sha512, "SLH-DSA-SHA2-192F-WITH-SHA512"},
            new Object[]{NISTObjectIdentifiers.id_hash_slh_dsa_sha2_256s_with_sha512, "SLH-DSA-SHA2-256S-WITH-SHA512"},
            new Object[]{NISTObjectIdentifiers.id_hash_slh_dsa_sha2_256f_with_sha512, "SLH-DSA-SHA2-256F-WITH-SHA512"},
            new Object[]{NISTObjectIdentifiers.id_hash_slh_dsa_shake_128s_with_shake128, "SLH-DSA-SHAKE-128S-WITH-SHAKE128"},
            new Object[]{NISTObjectIdentifiers.id_hash_slh_dsa_shake_128f_with_shake128, "SLH-DSA-SHAKE-128F-WITH-SHAKE128"},
            new Object[]{NISTObjectIdentifiers.id_hash_slh_dsa_shake_192s_with_shake256, "SLH-DSA-SHAKE-192S-WITH-SHAKE256"},
            new Object[]{NISTObjectIdentifiers.id_hash_slh_dsa_shake_192f_with_shake256, "SLH-DSA-SHAKE-192F-WITH-SHAKE256"},
            new Object[]{NISTObjectIdentifiers.id_hash_slh_dsa_shake_256s_with_shake256, "SLH-DSA-SHAKE-256S-WITH-SHAKE256"},
            new Object[]{NISTObjectIdentifiers.id_hash_slh_dsa_shake_256f_with_shake256, "SLH-DSA-SHAKE-256F-WITH-SHAKE256"},
            new Object[]{BCObjectIdentifiers.sphincsPlus_sha2_128s_r3, "SPHINCS+"},
            new Object[]{BCObjectIdentifiers.sphincsPlus_sha2_128f_r3, "SPHINCS+"},
            new Object[]{BCObjectIdentifiers.sphincsPlus_shake_128s_r3, "SPHINCS+"},
            new Object[]{BCObjectIdentifiers.sphincsPlus_shake_128f_r3, "SPHINCS+"},
            new Object[]{BCObjectIdentifiers.sphincsPlus_haraka_128s_r3, "SPHINCS+"},
            new Object[]{BCObjectIdentifiers.sphincsPlus_haraka_128f_r3, "SPHINCS+"},
            new Object[]{BCObjectIdentifiers.sphincsPlus_sha2_192s_r3, "SPHINCS+"},
            new Object[]{BCObjectIdentifiers.sphincsPlus_sha2_192f_r3, "SPHINCS+"},
            new Object[]{BCObjectIdentifiers.sphincsPlus_shake_192s_r3, "SPHINCS+"},
            new Object[]{BCObjectIdentifiers.sphincsPlus_shake_192f_r3, "SPHINCS+"},
            new Object[]{BCObjectIdentifiers.sphincsPlus_haraka_192s_r3, "SPHINCS+"},
            new Object[]{BCObjectIdentifiers.sphincsPlus_haraka_192f_r3, "SPHINCS+"},
            new Object[]{BCObjectIdentifiers.sphincsPlus_sha2_256s_r3, "SPHINCS+"},
            new Object[]{BCObjectIdentifiers.sphincsPlus_sha2_256f_r3, "SPHINCS+"},
            new Object[]{BCObjectIdentifiers.sphincsPlus_shake_256s_r3, "SPHINCS+"},
            new Object[]{BCObjectIdentifiers.sphincsPlus_shake_256f_r3, "SPHINCS+"},
            new Object[]{BCObjectIdentifiers.sphincsPlus_haraka_256s_r3, "SPHINCS+"},
            new Object[]{BCObjectIdentifiers.sphincsPlus_haraka_256f_r3, "SPHINCS+"},
            new Object[]{BCObjectIdentifiers.sphincsPlus_sha2_128s_r3_simple, "SPHINCS+"},
            new Object[]{BCObjectIdentifiers.sphincsPlus_sha2_128f_r3_simple, "SPHINCS+"},
            new Object[]{BCObjectIdentifiers.sphincsPlus_shake_128s_r3_simple, "SPHINCS+"},
            new Object[]{BCObjectIdentifiers.sphincsPlus_shake_128f_r3_simple, "SPHINCS+"},
            new Object[]{BCObjectIdentifiers.sphincsPlus_haraka_128s_r3_simple, "SPHINCS+"},
            new Object[]{BCObjectIdentifiers.sphincsPlus_haraka_128f_r3_simple, "SPHINCS+"},
            new Object[]{BCObjectIdentifiers.sphincsPlus_sha2_192s_r3_simple, "SPHINCS+"},
            new Object[]{BCObjectIdentifiers.sphincsPlus_sha2_192f_r3_simple, "SPHINCS+"},
            new Object[]{BCObjectIdentifiers.sphincsPlus_shake_192s_r3_simple, "SPHINCS+"},
            new Object[]{BCObjectIdentifiers.sphincsPlus_shake_192f_r3_simple, "SPHINCS+"},
            new Object[]{BCObjectIdentifiers.sphincsPlus_haraka_192s_r3_simple, "SPHINCS+"},
            new Object[]{BCObjectIdentifiers.sphincsPlus_haraka_192f_r3_simple, "SPHINCS+"},
            new Object[]{BCObjectIdentifiers.sphincsPlus_sha2_256s_r3_simple, "SPHINCS+"},
            new Object[]{BCObjectIdentifiers.sphincsPlus_sha2_256f_r3_simple, "SPHINCS+"},
            new Object[]{BCObjectIdentifiers.sphincsPlus_shake_256s_r3_simple, "SPHINCS+"},
            new Object[]{BCObjectIdentifiers.sphincsPlus_shake_256f_r3_simple, "SPHINCS+"},
            new Object[]{BCObjectIdentifiers.sphincsPlus_haraka_256s_r3_simple, "SPHINCS+"},
            new Object[]{BCObjectIdentifiers.sphincsPlus_haraka_256f_r3_simple, "SPHINCS+"},
            new Object[]{GNUObjectIdentifiers.Tiger_192, "Tiger"},
            new Object[]{PKCSObjectIdentifiers.id_alg_hss_lms_hashsig, "LMS"},

            new Object[]{PKCSObjectIdentifiers.RC2_CBC, "RC2/CBC"},
            new Object[]{PKCSObjectIdentifiers.des_EDE3_CBC, "DESEDE-3KEY/CBC"},
            new Object[]{NISTObjectIdentifiers.id_aes128_ECB, "AES-128/ECB"},
            new Object[]{NISTObjectIdentifiers.id_aes192_ECB, "AES-192/ECB"},
            new Object[]{NISTObjectIdentifiers.id_aes256_ECB, "AES-256/ECB"},
            new Object[]{NISTObjectIdentifiers.id_aes128_CBC, "AES-128/CBC"},
            new Object[]{NISTObjectIdentifiers.id_aes192_CBC, "AES-192/CBC"},
            new Object[]{NISTObjectIdentifiers.id_aes256_CBC, "AES-256/CBC"},
            new Object[]{NISTObjectIdentifiers.id_aes128_CFB, "AES-128/CFB"},
            new Object[]{NISTObjectIdentifiers.id_aes192_CFB, "AES-192/CFB"},
            new Object[]{NISTObjectIdentifiers.id_aes256_CFB, "AES-256/CFB"},
            new Object[]{NISTObjectIdentifiers.id_aes128_OFB, "AES-128/OFB"},
            new Object[]{NISTObjectIdentifiers.id_aes192_OFB, "AES-192/OFB"},
            new Object[]{NISTObjectIdentifiers.id_aes256_OFB, "AES-256/OFB"},
            new Object[]{NISTObjectIdentifiers.id_aes128_CCM, "AES-128/CCM"},
            new Object[]{NISTObjectIdentifiers.id_aes192_CCM, "AES-192/CCM"},
            new Object[]{NISTObjectIdentifiers.id_aes256_CCM, "AES-256/CCM"},
            new Object[]{NISTObjectIdentifiers.id_aes128_GCM, "AES-128/GCM"},
            new Object[]{NISTObjectIdentifiers.id_aes192_GCM, "AES-192/GCM"},
            new Object[]{NISTObjectIdentifiers.id_aes256_GCM, "AES-256/GCM"},
            new Object[]{NISTObjectIdentifiers.id_aes128_GMAC, "AES-128/GMAC"},
            new Object[]{NISTObjectIdentifiers.id_aes192_GMAC, "AES-192/GMAC"},
            new Object[]{NISTObjectIdentifiers.id_aes256_GMAC, "AES-256/GMAC"},
            new Object[]{NTTObjectIdentifiers.id_camellia128_cbc, "CAMELLIA-128/CBC"},
            new Object[]{NTTObjectIdentifiers.id_camellia192_cbc, "CAMELLIA-192/CBC"},
            new Object[]{NTTObjectIdentifiers.id_camellia256_cbc, "CAMELLIA-256/CBC"},
            new Object[]{KISAObjectIdentifiers.id_seedCBC, "SEED/CBC"},
            new Object[]{MiscObjectIdentifiers.as_sys_sec_alg_ideaCBC, "IDEA/CBC"},
            new Object[]{MiscObjectIdentifiers.cast5CBC, "CAST5/CBC"},
            new Object[]{MiscObjectIdentifiers.cryptlib_algorithm_blowfish_ECB, "Blowfish/ECB"},
            new Object[]{MiscObjectIdentifiers.cryptlib_algorithm_blowfish_CBC, "Blowfish/CBC"},
            new Object[]{MiscObjectIdentifiers.cryptlib_algorithm_blowfish_CFB, "Blowfish/CFB"},
            new Object[]{MiscObjectIdentifiers.cryptlib_algorithm_blowfish_OFB, "Blowfish/OFB"},
            new Object[]{GNUObjectIdentifiers.Serpent_128_ECB, "Serpent-128/ECB"},
            new Object[]{GNUObjectIdentifiers.Serpent_128_CBC, "Serpent-128/CBC"},
            new Object[]{GNUObjectIdentifiers.Serpent_128_CFB, "Serpent-128/CFB"},
            new Object[]{GNUObjectIdentifiers.Serpent_128_OFB, "Serpent-128/OFB"},
            new Object[]{GNUObjectIdentifiers.Serpent_192_ECB, "Serpent-192/ECB"},
            new Object[]{GNUObjectIdentifiers.Serpent_192_CBC, "Serpent-192/CBC"},
            new Object[]{GNUObjectIdentifiers.Serpent_192_CFB, "Serpent-192/CFB"},
            new Object[]{GNUObjectIdentifiers.Serpent_192_OFB, "Serpent-192/OFB"},
            new Object[]{GNUObjectIdentifiers.Serpent_256_ECB, "Serpent-256/ECB"},
            new Object[]{GNUObjectIdentifiers.Serpent_256_CBC, "Serpent-256/CBC"},
            new Object[]{GNUObjectIdentifiers.Serpent_256_CFB, "Serpent-256/CFB"},
            new Object[]{GNUObjectIdentifiers.Serpent_256_OFB, "Serpent-256/OFB"},
            new Object[]{MiscObjectIdentifiers.id_blake2b160, "BLAKE2b-160"},
            new Object[]{MiscObjectIdentifiers.id_blake2b256, "BLAKE2b-256"},
            new Object[]{MiscObjectIdentifiers.id_blake2b384, "BLAKE2b-384"},
            new Object[]{MiscObjectIdentifiers.id_blake2b512, "BLAKE2b-512"},
            new Object[]{MiscObjectIdentifiers.id_blake2s128, "BLAKE2s-128"},
            new Object[]{MiscObjectIdentifiers.id_blake2s160, "BLAKE2s-160"},
            new Object[]{MiscObjectIdentifiers.id_blake2s224, "BLAKE2s-224"},
            new Object[]{MiscObjectIdentifiers.id_blake2s256, "BLAKE2s-256"},
            new Object[]{MiscObjectIdentifiers.blake3_256, "BLAKE3-256"}};


        for (Object value : values)
        {
            //
            // If this fails then the name finder has probably had entries added that are not captured in
            // this test.
            //
            DefaultAlgorithmNameFinder nameFinder = new DefaultAlgorithmNameFinder();
            assertEquals("default name finder has same number of entries as test case",
                values.length, nameFinder.getOIDSet().size());

            ASN1ObjectIdentifier oid = (ASN1ObjectIdentifier)((Object[])value)[0];
            String name = ((Object[])value)[1].toString();
            assertTrue(nameFinder.hasAlgorithmName(oid));
            assertEquals(nameFinder.getAlgorithmName(oid), name);
            assertEquals(name, nameFinder.getAlgorithmName(new AlgorithmIdentifier(oid)));


            if (name.startsWith("AES-"))
            {
                System.out.println("Skipping for provider resolution " + name);
                continue;
            }

            if (name.equals("RSAOAEP"))
            {
                System.out.println("Skipping for provider resolution " + name);
                continue;
            }

            if (name.startsWith("Blowfish"))
            {
                System.out.println("Skipping for provider resolution " + name);
                continue;
            }

            if (name.startsWith("Serpent"))
            {
                System.out.println("Skipping for provider resolution " + name);
                continue;
            }

            if (name.startsWith("GOST3411") || name.startsWith("CAMELLIA-"))
            {
                System.out.println("Skipping for provider resolution " + name);
                continue;
            }

            if (name.equals("IDEA/CBC") ||
                name.equals("RC2/CBC") ||
                name.equals("CAST5/CBC") ||
                name.equals("SEED/CBC") ||
                name.equals("DESEDE-3KEY/CBC"))
            {
                System.out.println("Skipping for provider resolution " + name);
                continue;
            }


            // Is it a digest?
            try
            {
                MessageDigest.getInstance(nameFinder.getAlgorithmName(oid), BouncyCastleProvider.PROVIDER_NAME);
                assertTrue(true);
                continue;
            }
            catch (Exception ex)
            {

            }

            // Is it a cipher
            try
            {
                Cipher.getInstance(nameFinder.getAlgorithmName(oid), BouncyCastleProvider.PROVIDER_NAME);
                assertTrue(true);
                continue;
            }
            catch (Exception ex)
            {

            }

            // Is it a signature
            try
            {
                Signature.getInstance(nameFinder.getAlgorithmName(oid), BouncyCastleProvider.PROVIDER_NAME);
                assertTrue(true);
                continue;
            }
            catch (Exception ex)
            {

            }

            System.out.println("Could not resolve " + oid.toString() + " " + name + " into either Digest, Cipher or Signature");

            //fail("Could not resolve " + oid.toString() + " " + name + " into either Digest, Cipher or Signature");
        }

    }


    public void testAlgorithmNameFinder()
        throws Exception
    {
        AlgorithmNameFinder nameFinder = new DefaultAlgorithmNameFinder();

        assertTrue(nameFinder.hasAlgorithmName(OIWObjectIdentifiers.elGamalAlgorithm));
        assertFalse(nameFinder.hasAlgorithmName(Extension.authorityKeyIdentifier));

        assertEquals(nameFinder.getAlgorithmName(OIWObjectIdentifiers.elGamalAlgorithm), "ELGAMAL");
        assertEquals(nameFinder.getAlgorithmName(PKCSObjectIdentifiers.rsaEncryption), "RSA");
        assertEquals(nameFinder.getAlgorithmName(PKCSObjectIdentifiers.id_RSAES_OAEP), "RSAOAEP");
        assertEquals(nameFinder.getAlgorithmName(PKCSObjectIdentifiers.md5), "MD5");
        assertEquals(nameFinder.getAlgorithmName(OIWObjectIdentifiers.idSHA1), "SHA1");
        assertEquals(nameFinder.getAlgorithmName(NISTObjectIdentifiers.id_sha224), "SHA224");
        assertEquals(nameFinder.getAlgorithmName(NISTObjectIdentifiers.id_sha256), "SHA256");
        assertEquals(nameFinder.getAlgorithmName(NISTObjectIdentifiers.id_sha384), "SHA384");
        assertEquals(nameFinder.getAlgorithmName(NISTObjectIdentifiers.id_sha512), "SHA512");
        assertEquals(nameFinder.getAlgorithmName(PKCSObjectIdentifiers.sha512WithRSAEncryption), "SHA512WITHRSA");
        assertEquals(nameFinder.getAlgorithmName(PKCSObjectIdentifiers.id_RSASSA_PSS), "RSAPSS");
        assertEquals(nameFinder.getAlgorithmName(TeleTrusTObjectIdentifiers.rsaSignatureWithripemd160), "RIPEMD160WITHRSA");
        assertEquals(nameFinder.getAlgorithmName(new AlgorithmIdentifier(OIWObjectIdentifiers.elGamalAlgorithm, DERNull.INSTANCE)), "ELGAMAL");
        assertEquals(nameFinder.getAlgorithmName(new AlgorithmIdentifier(PKCSObjectIdentifiers.rsaEncryption, DERNull.INSTANCE)), "RSA");
        assertEquals(nameFinder.getAlgorithmName(MiscObjectIdentifiers.id_blake2b160), "BLAKE2b-160");
        assertEquals(nameFinder.getAlgorithmName(MiscObjectIdentifiers.id_blake2b256), "BLAKE2b-256");
        assertEquals(nameFinder.getAlgorithmName(MiscObjectIdentifiers.id_blake2b384), "BLAKE2b-384");
        assertEquals(nameFinder.getAlgorithmName(MiscObjectIdentifiers.id_blake2b512), "BLAKE2b-512");
        assertEquals(nameFinder.getAlgorithmName(MiscObjectIdentifiers.id_blake2s128), "BLAKE2s-128");
        assertEquals(nameFinder.getAlgorithmName(MiscObjectIdentifiers.id_blake2s160), "BLAKE2s-160");
        assertEquals(nameFinder.getAlgorithmName(MiscObjectIdentifiers.id_blake2s224), "BLAKE2s-224");
        assertEquals(nameFinder.getAlgorithmName(MiscObjectIdentifiers.id_blake2s256), "BLAKE2s-256");
        assertEquals(nameFinder.getAlgorithmName(MiscObjectIdentifiers.blake3_256), "BLAKE3-256");

        assertEquals(nameFinder.getAlgorithmName(Extension.authorityKeyIdentifier), Extension.authorityKeyIdentifier.getId());
    }

    public void testSignatureAlgorithmNameFinder()
        throws Exception
    {
        DefaultSignatureNameFinder nameFinder = new DefaultSignatureNameFinder();

        assertFalse(nameFinder.hasAlgorithmName(OIWObjectIdentifiers.elGamalAlgorithm));
        assertFalse(nameFinder.hasAlgorithmName(Extension.authorityKeyIdentifier));

        assertEquals(nameFinder.getAlgorithmName(PKCSObjectIdentifiers.sha512WithRSAEncryption), "SHA512WITHRSA");
        assertEquals(nameFinder.getAlgorithmName(PKCSObjectIdentifiers.id_RSASSA_PSS), "RSASSA-PSS");
        assertEquals("RIPEMD160WITHRSA", nameFinder.getAlgorithmName(TeleTrusTObjectIdentifiers.rsaSignatureWithripemd160));
        assertEquals("ED448", nameFinder.getAlgorithmName(EdECObjectIdentifiers.id_Ed448));
        assertEquals("SHA256WITHRSAANDMGF1",
            nameFinder.getAlgorithmName(
                new AlgorithmIdentifier(PKCSObjectIdentifiers.id_RSASSA_PSS, new RSASSAPSSparams(
                    new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha256),
                    new AlgorithmIdentifier(PKCSObjectIdentifiers.id_mgf1, new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha256)),
                    RSASSAPSSparams.DEFAULT_SALT_LENGTH, RSASSAPSSparams.DEFAULT_TRAILER_FIELD))));
        assertEquals("SHA256WITHRSAANDMGF1USINGSHA1",
            nameFinder.getAlgorithmName(
                new AlgorithmIdentifier(PKCSObjectIdentifiers.id_RSASSA_PSS, new RSASSAPSSparams(
                    new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha256),
                    new AlgorithmIdentifier(PKCSObjectIdentifiers.id_mgf1, new AlgorithmIdentifier(OIWObjectIdentifiers.idSHA1)),
                    RSASSAPSSparams.DEFAULT_SALT_LENGTH, RSASSAPSSparams.DEFAULT_TRAILER_FIELD))));
        assertEquals("ED448", nameFinder.getAlgorithmName(new AlgorithmIdentifier(EdECObjectIdentifiers.id_Ed448)));
        assertEquals(Extension.authorityKeyIdentifier.getId(), nameFinder.getAlgorithmName(Extension.authorityKeyIdentifier));
    }

    public void testOaepWrap()
        throws Exception
    {
        KeyPairGenerator kGen = KeyPairGenerator.getInstance("RSA", BC);

        kGen.initialize(2048);

        KeyPair kp = kGen.generateKeyPair();

        checkAlgorithmId(kp, "SHA-1", OIWObjectIdentifiers.idSHA1);
        checkAlgorithmId(kp, "SHA-224", NISTObjectIdentifiers.id_sha224);
        checkAlgorithmId(kp, "SHA-256", NISTObjectIdentifiers.id_sha256);
        checkAlgorithmId(kp, "SHA-384", NISTObjectIdentifiers.id_sha384);
        checkAlgorithmId(kp, "SHA-512", NISTObjectIdentifiers.id_sha512);
        checkAlgorithmId(kp, "SHA-512/224", NISTObjectIdentifiers.id_sha512_224);
        checkAlgorithmId(kp, "SHA-512/256", NISTObjectIdentifiers.id_sha512_256);
        checkAlgorithmId(kp, "SHA-512(224)", NISTObjectIdentifiers.id_sha512_224);
        checkAlgorithmId(kp, "SHA-512(256)", NISTObjectIdentifiers.id_sha512_256);
    }

    private void checkAlgorithmId(KeyPair kp, String digest, ASN1ObjectIdentifier digestOid)
    {
        JceAsymmetricKeyWrapper wrapper = new JceAsymmetricKeyWrapper(
            new OAEPParameterSpec(digest, "MGF1", new MGF1ParameterSpec(digest), new PSource.PSpecified(Hex.decode("beef"))),
            kp.getPublic()).setProvider(BC);

        Assert.assertEquals(PKCSObjectIdentifiers.id_RSAES_OAEP, wrapper.getAlgorithmIdentifier().getAlgorithm());
        RSAESOAEPparams oaepParams = RSAESOAEPparams.getInstance(wrapper.getAlgorithmIdentifier().getParameters());
        Assert.assertEquals(digestOid, oaepParams.getHashAlgorithm().getAlgorithm());
        Assert.assertEquals(PKCSObjectIdentifiers.id_mgf1, oaepParams.getMaskGenAlgorithm().getAlgorithm());
        Assert.assertEquals(new AlgorithmIdentifier(digestOid, DERNull.INSTANCE), oaepParams.getMaskGenAlgorithm().getParameters());
        Assert.assertEquals(PKCSObjectIdentifiers.id_pSpecified, oaepParams.getPSourceAlgorithm().getAlgorithm());
        Assert.assertEquals(new DEROctetString(Hex.decode("beef")), oaepParams.getPSourceAlgorithm().getParameters());
    }

    /**
     * github #721: BcRSAContentSignerBuilder and BcRSAContentVerifierProviderBuilder
     * used to hardcode RSADigestSigner (PKCS#1 v1.5) regardless of the supplied
     * signature algorithm OID, so passing an id-RSASSA-PSS sigAlgId produced
     * PKCS#1 v1.5 bytes that no PSS verifier accepted. Exercise both directions
     * and a JCE/Bc cross-check round-trip.
     */
    public void testRsaPssBcRoundTripIssue721()
        throws Exception
    {
        if (Security.getProvider(BC) == null)
        {
            Security.addProvider(new BouncyCastleProvider());
        }

        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", BC);
        kpg.initialize(2048);
        java.security.KeyPair kp = kpg.generateKeyPair();

        org.bouncycastle.crypto.params.AsymmetricKeyParameter privBc =
            org.bouncycastle.crypto.util.PrivateKeyFactory.createKey(kp.getPrivate().getEncoded());
        org.bouncycastle.asn1.x509.SubjectPublicKeyInfo spki =
            org.bouncycastle.asn1.x509.SubjectPublicKeyInfo.getInstance(kp.getPublic().getEncoded());
        org.bouncycastle.crypto.params.AsymmetricKeyParameter pubBc =
            org.bouncycastle.crypto.util.PublicKeyFactory.createKey(spki);

        // SHA-256 / MGF1+SHA-256 / saltLen=32 / trailerField=1
        AlgorithmIdentifier sha256AlgId = new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha256, DERNull.INSTANCE);
        AlgorithmIdentifier sigAlgId = new AlgorithmIdentifier(
            PKCSObjectIdentifiers.id_RSASSA_PSS,
            new RSASSAPSSparams(
                sha256AlgId,
                new AlgorithmIdentifier(PKCSObjectIdentifiers.id_mgf1, sha256AlgId),
                new org.bouncycastle.asn1.ASN1Integer(32),
                RSASSAPSSparams.DEFAULT_TRAILER_FIELD));

        byte[] msg = "the quick brown fox jumped over the lazy dog".getBytes();

        // (1) Sign + verify using the lightweight Bc* path on both sides.
        org.bouncycastle.operator.bc.BcRSAContentSignerBuilder bcSignerBuilder =
            new org.bouncycastle.operator.bc.BcRSAContentSignerBuilder(sigAlgId, sha256AlgId);
        org.bouncycastle.operator.ContentSigner bcSigner = bcSignerBuilder.build(privBc);
        bcSigner.getOutputStream().write(msg);
        bcSigner.getOutputStream().close();
        byte[] bcSig = bcSigner.getSignature();

        org.bouncycastle.operator.bc.BcRSAContentVerifierProviderBuilder bcVerifierBuilder =
            new org.bouncycastle.operator.bc.BcRSAContentVerifierProviderBuilder(
                new org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder());
        org.bouncycastle.operator.ContentVerifier bcVerifier =
            bcVerifierBuilder.build(pubBc).get(sigAlgId);
        bcVerifier.getOutputStream().write(msg);
        bcVerifier.getOutputStream().close();
        assertTrue("Bc-signed RSA-PSS sig did not verify under Bc verifier",
            bcVerifier.verify(bcSig));

        // (2) Cross-check: a Bc-produced PSS sig should also validate under
        //     the JCE verifier.
        org.bouncycastle.operator.ContentVerifier jcaVerifier =
            new org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder()
                .setProvider(BC).build(spki).get(sigAlgId);
        jcaVerifier.getOutputStream().write(msg);
        jcaVerifier.getOutputStream().close();
        assertTrue("Bc-signed RSA-PSS sig did not verify under JCE verifier",
            jcaVerifier.verify(bcSig));

        // (3) Reverse cross-check: a JCE-produced PSS sig should validate
        //     under the Bc verifier.
        java.security.spec.PSSParameterSpec pssSpec = new java.security.spec.PSSParameterSpec(
            "SHA-256", "MGF1", new java.security.spec.MGF1ParameterSpec("SHA-256"), 32, 1);
        org.bouncycastle.operator.ContentSigner jcaSigner =
            new org.bouncycastle.operator.jcajce.JcaContentSignerBuilder("RSAPSS", pssSpec)
                .setProvider(BC).build(kp.getPrivate());
        jcaSigner.getOutputStream().write(msg);
        jcaSigner.getOutputStream().close();
        byte[] jcaSig = jcaSigner.getSignature();

        org.bouncycastle.operator.ContentVerifier bcVerifier2 =
            bcVerifierBuilder.build(pubBc).get(jcaSigner.getAlgorithmIdentifier());
        bcVerifier2.getOutputStream().write(msg);
        bcVerifier2.getOutputStream().close();
        assertTrue("JCE-signed RSA-PSS sig did not verify under Bc verifier",
            bcVerifier2.verify(jcaSig));
    }

    /**
     * SHAKE256 used as both the content hash and the mask generation function
     * inside an id-RSASSA-PSS RSASSA-PSS-params encoding (RFC 8702: SHAKE OID
     * appears directly as the MGF AlgorithmIdentifier rather than wrapped in
     * id-mgf1). SHAKEDigest implements Xof, and PSSSigner's maskGenerator
     * branches on {@code mgfDigest instanceof Xof} to use the native
     * variable-length output instead of MGF1.
     */
    public void testRsaPssBcShake256Issue721()
        throws Exception
    {
        if (Security.getProvider(BC) == null)
        {
            Security.addProvider(new BouncyCastleProvider());
        }

        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", BC);
        kpg.initialize(2048);
        java.security.KeyPair kp = kpg.generateKeyPair();

        org.bouncycastle.crypto.params.AsymmetricKeyParameter privBc =
            org.bouncycastle.crypto.util.PrivateKeyFactory.createKey(kp.getPrivate().getEncoded());
        org.bouncycastle.asn1.x509.SubjectPublicKeyInfo spki =
            org.bouncycastle.asn1.x509.SubjectPublicKeyInfo.getInstance(kp.getPublic().getEncoded());
        org.bouncycastle.crypto.params.AsymmetricKeyParameter pubBc =
            org.bouncycastle.crypto.util.PublicKeyFactory.createKey(spki);

        // SHAKE256 hash + SHAKE256 MGF + 64-byte salt + trailerField=1.
        // Per RFC 8702 the MGF AlgorithmIdentifier is the SHAKE OID
        // directly (not id-mgf1 with SHAKE inside); the SHAKE OIDs are
        // parameterless (no DERNull).
        AlgorithmIdentifier shake256AlgId = new AlgorithmIdentifier(NISTObjectIdentifiers.id_shake256);
        AlgorithmIdentifier sigAlgId = new AlgorithmIdentifier(
            PKCSObjectIdentifiers.id_RSASSA_PSS,
            new RSASSAPSSparams(
                shake256AlgId,
                shake256AlgId,
                new org.bouncycastle.asn1.ASN1Integer(64),
                RSASSAPSSparams.DEFAULT_TRAILER_FIELD));

        byte[] msg = "the quick brown fox jumped over the lazy dog".getBytes();

        org.bouncycastle.operator.bc.BcRSAContentSignerBuilder bcSignerBuilder =
            new org.bouncycastle.operator.bc.BcRSAContentSignerBuilder(sigAlgId, shake256AlgId);
        org.bouncycastle.operator.ContentSigner bcSigner = bcSignerBuilder.build(privBc);
        bcSigner.getOutputStream().write(msg);
        bcSigner.getOutputStream().close();
        byte[] bcSig = bcSigner.getSignature();

        org.bouncycastle.operator.bc.BcRSAContentVerifierProviderBuilder bcVerifierBuilder =
            new org.bouncycastle.operator.bc.BcRSAContentVerifierProviderBuilder(
                new org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder());
        org.bouncycastle.operator.ContentVerifier bcVerifier =
            bcVerifierBuilder.build(pubBc).get(sigAlgId);
        bcVerifier.getOutputStream().write(msg);
        bcVerifier.getOutputStream().close();
        assertTrue("Bc-signed RSA-PSS+SHAKE256 sig did not verify under Bc verifier",
            bcVerifier.verify(bcSig));
    }

    public void testDefaultKemEncapsulationLengthProvider()
    {
        KemEncapsulationLengthProvider lengthProvider = new DefaultKemEncapsulationLengthProvider();
        SecureRandom random = CryptoServicesRegistrar.getSecureRandom();

        ASN1ObjectIdentifier[] mlKemOids = new ASN1ObjectIdentifier[]
            {
                NISTObjectIdentifiers.id_alg_ml_kem_512,
                NISTObjectIdentifiers.id_alg_ml_kem_768,
                NISTObjectIdentifiers.id_alg_ml_kem_1024
            };

        MLKEMParameters[] mlKemParams = new MLKEMParameters[]
            {
                MLKEMParameters.ml_kem_512,
                MLKEMParameters.ml_kem_768,
                MLKEMParameters.ml_kem_1024
            };

        for (int i = 0; i != mlKemOids.length; i++)
        {
            MLKEMKeyPairGenerator kpg = new MLKEMKeyPairGenerator();

            kpg.init(new MLKEMKeyGenerationParameters(random, mlKemParams[i]));

            AsymmetricCipherKeyPair kp = kpg.generateKeyPair();

            MLKEMExtractor ext = new MLKEMExtractor((MLKEMPrivateKeyParameters)kp.getPrivate());

            assertEquals(ext.getEncapsulationLength(), lengthProvider.getEncapsulationLength(new AlgorithmIdentifier(mlKemOids[i])));
        }

        ASN1ObjectIdentifier[] ntruOids = new ASN1ObjectIdentifier[]
            {
                BCObjectIdentifiers.ntruhps2048509,
                BCObjectIdentifiers.ntruhps2048677,
                BCObjectIdentifiers.ntruhps4096821,
                BCObjectIdentifiers.ntruhps40961229,
                BCObjectIdentifiers.ntruhrss701,
                BCObjectIdentifiers.ntruhrss1373,
            };

        NTRUParameters[] ntruParams = new NTRUParameters[]
            {
                NTRUParameters.ntruhps2048509,
                NTRUParameters.ntruhps2048677,
                NTRUParameters.ntruhps4096821,
                NTRUParameters.ntruhps40961229,
                NTRUParameters.ntruhrss701,
                NTRUParameters.ntruhrss1373
            };

        for (int i = 0; i != ntruOids.length; i++)
        {
            NTRUKeyPairGenerator kpg = new NTRUKeyPairGenerator();

            kpg.init(new NTRUKeyGenerationParameters(random, ntruParams[i]));

            AsymmetricCipherKeyPair kp = kpg.generateKeyPair();

            NTRUKEMExtractor ext = new NTRUKEMExtractor((NTRUPrivateKeyParameters)kp.getPrivate());

            assertEquals(ext.getEncapsulationLength(), lengthProvider.getEncapsulationLength(new AlgorithmIdentifier(ntruOids[i])));
        }

        ASN1ObjectIdentifier[] hqcOids = new ASN1ObjectIdentifier[]
            {
                BCObjectIdentifiers.hqc128,
                BCObjectIdentifiers.hqc192,
                BCObjectIdentifiers.hqc256
            };

        HQCParameters[] hqcParams = new HQCParameters[]
            {
                HQCParameters.hqc128,
                HQCParameters.hqc192,
                HQCParameters.hqc256
            };

        for (int i = 0; i != hqcOids.length; i++)
        {
            HQCKeyPairGenerator kpg = new HQCKeyPairGenerator();

            kpg.init(new HQCKeyGenerationParameters(random, hqcParams[i]));

            AsymmetricCipherKeyPair kp = kpg.generateKeyPair();

            HQCKEMExtractor ext = new HQCKEMExtractor((HQCPrivateKeyParameters)kp.getPrivate());

            assertEquals(ext.getEncapsulationLength(), lengthProvider.getEncapsulationLength(new AlgorithmIdentifier(hqcOids[i])));
        }
    }

    public void testCompositeMLDsaDigestLookupIssue1767()
    {
        DefaultDigestAlgorithmIdentifierFinder f = new DefaultDigestAlgorithmIdentifierFinder();

        // Unknown sig OID must return null, not throw NPE("digest OID is null").
        assertNull(f.find(new AlgorithmIdentifier(new ASN1ObjectIdentifier("1.2.3.4.5.6.7.8.9"))));

        // BC-namespaced composite OIDs aren't mapped: also null, not NPE.
        assertNull(f.find(new AlgorithmIdentifier(BCObjectIdentifiers.id_MLDSA44_RSA2048_PSS_SHA256)));

        // IANA composite OIDs must return the per-scheme prehash that matches what
        // the composite SignatureSpi feeds the inner signers (the OID name suffix).
        Object[][] expected = new Object[][]
        {
            { IANAObjectIdentifiers.id_MLDSA44_RSA2048_PSS_SHA256,        NISTObjectIdentifiers.id_sha256 },
            { IANAObjectIdentifiers.id_MLDSA44_RSA2048_PKCS15_SHA256,     NISTObjectIdentifiers.id_sha256 },
            { IANAObjectIdentifiers.id_MLDSA44_Ed25519_SHA512,            NISTObjectIdentifiers.id_sha512 },
            { IANAObjectIdentifiers.id_MLDSA44_ECDSA_P256_SHA256,         NISTObjectIdentifiers.id_sha256 },
            { IANAObjectIdentifiers.id_MLDSA65_RSA3072_PSS_SHA512,        NISTObjectIdentifiers.id_sha512 },
            { IANAObjectIdentifiers.id_MLDSA65_RSA3072_PKCS15_SHA512,     NISTObjectIdentifiers.id_sha512 },
            { IANAObjectIdentifiers.id_MLDSA65_RSA4096_PSS_SHA512,        NISTObjectIdentifiers.id_sha512 },
            { IANAObjectIdentifiers.id_MLDSA65_RSA4096_PKCS15_SHA512,     NISTObjectIdentifiers.id_sha512 },
            { IANAObjectIdentifiers.id_MLDSA65_ECDSA_P256_SHA512,         NISTObjectIdentifiers.id_sha512 },
            { IANAObjectIdentifiers.id_MLDSA65_ECDSA_P384_SHA512,         NISTObjectIdentifiers.id_sha512 },
            { IANAObjectIdentifiers.id_MLDSA65_ECDSA_brainpoolP256r1_SHA512, NISTObjectIdentifiers.id_sha512 },
            { IANAObjectIdentifiers.id_MLDSA65_Ed25519_SHA512,            NISTObjectIdentifiers.id_sha512 },
            { IANAObjectIdentifiers.id_MLDSA87_ECDSA_P384_SHA512,         NISTObjectIdentifiers.id_sha512 },
            { IANAObjectIdentifiers.id_MLDSA87_ECDSA_brainpoolP384r1_SHA512, NISTObjectIdentifiers.id_sha512 },
            { IANAObjectIdentifiers.id_MLDSA87_Ed448_SHAKE256,            NISTObjectIdentifiers.id_shake256 },
            { IANAObjectIdentifiers.id_MLDSA87_RSA3072_PSS_SHA512,        NISTObjectIdentifiers.id_sha512 },
            { IANAObjectIdentifiers.id_MLDSA87_RSA4096_PSS_SHA512,        NISTObjectIdentifiers.id_sha512 },
            { IANAObjectIdentifiers.id_MLDSA87_ECDSA_P521_SHA512,         NISTObjectIdentifiers.id_sha512 },
        };
        for (int i = 0; i != expected.length; ++i)
        {
            ASN1ObjectIdentifier sigOid = (ASN1ObjectIdentifier)expected[i][0];
            ASN1ObjectIdentifier expDig = (ASN1ObjectIdentifier)expected[i][1];
            AlgorithmIdentifier got = f.find(new AlgorithmIdentifier(sigOid));
            assertNotNull("missing mapping for " + sigOid.getId(), got);
            assertEquals("wrong digest for " + sigOid.getId(),
                expDig, got.getAlgorithm());
        }
    }

    /**
     * github #1510: JceInputDecryptorProviderBuilder previously assumed
     * algorithm parameters were either a raw IV (ASN1OctetString) or
     * GOST28147Parameters. AES-GCM AlgorithmIdentifiers carry a SEQUENCE
     * (GCMParameters: nonce + icvLen), so init failed when the only
     * fallback was the GOST path. The builder now recognises the AES-GCM
     * (and AES-CCM) OIDs and inits via GCMParameterSpec.
     */
    public void testGcmDecryptorIssue1510()
        throws Exception
    {
        try
        {
            // javax.crypto.spec.GCMParameterSpec is JDK 1.7+; skip on older JREs.
            Class.forName("javax.crypto.spec.GCMParameterSpec");
        }
        catch (ClassNotFoundException e)
        {
            return;
        }

        if (Security.getProvider(BC) == null)
        {
            Security.addProvider(new BouncyCastleProvider());
        }

        byte[] keyBytes = new byte[32];
        new SecureRandom().nextBytes(keyBytes);
        byte[] nonce = new byte[12];
        new SecureRandom().nextBytes(nonce);
        int tagLenBits = 128;
        byte[] plaintext = "JceInputDecryptorProviderBuilder GCM roundtrip — github #1510.".getBytes("UTF-8");

        // Encrypt with a JCE AES-GCM cipher.
        Cipher encCipher = Cipher.getInstance(NISTObjectIdentifiers.id_aes256_GCM.getId(), BC);
        encCipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(keyBytes, "AES"),
            new GCMParameterSpec(tagLenBits, nonce));
        byte[] ciphertext = encCipher.doFinal(plaintext);

        // Hand the AlgorithmIdentifier(id-aes256-GCM, GCMParameters) to the builder.
        AlgorithmIdentifier algId = new AlgorithmIdentifier(
            NISTObjectIdentifiers.id_aes256_GCM,
            new GCMParameters(nonce, tagLenBits / 8));

        InputDecryptorProvider provider = new JceInputDecryptorProviderBuilder()
            .setProvider(BC)
            .build(keyBytes);
        InputDecryptor decryptor = provider.get(algId);

        java.io.InputStream decStream = decryptor.getInputStream(
            new java.io.ByteArrayInputStream(ciphertext));
        java.io.ByteArrayOutputStream bOut = new java.io.ByteArrayOutputStream();
        org.bouncycastle.util.io.Streams.pipeAll(decStream, bOut);

        assertTrue("AES-GCM round-trip via JceInputDecryptorProviderBuilder",
            org.bouncycastle.util.Arrays.areEqual(plaintext, bOut.toByteArray()));
    }
}