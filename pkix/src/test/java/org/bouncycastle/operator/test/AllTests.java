package org.bouncycastle.operator.test;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.Security;
import java.security.Signature;
import java.security.spec.MGF1ParameterSpec;

import javax.crypto.Cipher;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;

import junit.framework.Assert;
import junit.framework.TestCase;
import junit.framework.TestSuite;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.bc.BCObjectIdentifiers;
import org.bouncycastle.asn1.bsi.BSIObjectIdentifiers;
import org.bouncycastle.asn1.cryptopro.CryptoProObjectIdentifiers;
import org.bouncycastle.asn1.eac.EACObjectIdentifiers;
import org.bouncycastle.asn1.edec.EdECObjectIdentifiers;
import org.bouncycastle.asn1.gnu.GNUObjectIdentifiers;
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
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.AlgorithmNameFinder;
import org.bouncycastle.operator.DefaultAlgorithmNameFinder;
import org.bouncycastle.operator.DefaultSignatureNameFinder;
import org.bouncycastle.operator.jcajce.JceAsymmetricKeyWrapper;
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
                nameFinder.getOIDSet().size(), values.length);

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
}