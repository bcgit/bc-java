package org.bouncycastle.operator;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.bc.BCObjectIdentifiers;
import org.bouncycastle.asn1.bsi.BSIObjectIdentifiers;
import org.bouncycastle.asn1.cryptopro.CryptoProObjectIdentifiers;
import org.bouncycastle.asn1.eac.EACObjectIdentifiers;
import org.bouncycastle.asn1.edec.EdECObjectIdentifiers;
import org.bouncycastle.asn1.gm.GMObjectIdentifiers;
import org.bouncycastle.asn1.isara.IsaraObjectIdentifiers;
import org.bouncycastle.asn1.misc.MiscObjectIdentifiers;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.RSASSAPSSparams;
import org.bouncycastle.asn1.rosstandart.RosstandartObjectIdentifiers;
import org.bouncycastle.asn1.teletrust.TeleTrusTObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.X509ObjectIdentifiers;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.util.Strings;

public class DefaultSignatureAlgorithmIdentifierFinder
    implements SignatureAlgorithmIdentifierFinder
{
    private static Map algorithms = new HashMap();
    private static Set noParams = new HashSet();
    private static Map params = new HashMap();
    private static Set pkcs15RsaEncryption = new HashSet();
    private static Map digestOids = new HashMap();

    private static void addAlgorithm(String algorithmName, ASN1ObjectIdentifier algOid)
    {
        if (algorithms.containsKey(algorithmName))
        {
            throw new IllegalStateException("algorithmName already present in addAlgorithm");
        }

        algorithms.put(algorithmName, algOid);
    }

    private static void addDigestOid(ASN1ObjectIdentifier signatureOid, ASN1ObjectIdentifier digestOid)
    {
        if (digestOids.containsKey(signatureOid))
        {
            throw new IllegalStateException("signatureOid already present in addDigestOid");
        }

        digestOids.put(signatureOid, digestOid);
    }

    private static void addParameters(String algorithmName, ASN1Encodable parameters)
    {
        if (parameters == null)
        {
            throw new IllegalArgumentException("use 'noParams' instead for absent parameters");
        }
        if (params.containsKey(algorithmName))
        {
            throw new IllegalStateException("algorithmName already present in addParameters");
        }

        params.put(algorithmName, parameters);
    }

    private static RSASSAPSSparams createPSSParams(AlgorithmIdentifier hashAlgId, int saltSize)
    {
        return new RSASSAPSSparams(
            hashAlgId,
            new AlgorithmIdentifier(PKCSObjectIdentifiers.id_mgf1, hashAlgId),
            new ASN1Integer(saltSize),
            RSASSAPSSparams.DEFAULT_TRAILER_FIELD);
    }

    static
    {
        addAlgorithm("COMPOSITE", MiscObjectIdentifiers.id_alg_composite);

        addAlgorithm("MD2WITHRSAENCRYPTION", PKCSObjectIdentifiers.md2WithRSAEncryption);
        addAlgorithm("MD2WITHRSA", PKCSObjectIdentifiers.md2WithRSAEncryption);
        addAlgorithm("MD5WITHRSAENCRYPTION", PKCSObjectIdentifiers.md5WithRSAEncryption);
        addAlgorithm("MD5WITHRSA", PKCSObjectIdentifiers.md5WithRSAEncryption);
        addAlgorithm("SHA1WITHRSAENCRYPTION", PKCSObjectIdentifiers.sha1WithRSAEncryption);
        addAlgorithm("SHA1WITHRSA", PKCSObjectIdentifiers.sha1WithRSAEncryption);
        addAlgorithm("SHA224WITHRSAENCRYPTION", PKCSObjectIdentifiers.sha224WithRSAEncryption);
        addAlgorithm("SHA224WITHRSA", PKCSObjectIdentifiers.sha224WithRSAEncryption);
        addAlgorithm("SHA256WITHRSAENCRYPTION", PKCSObjectIdentifiers.sha256WithRSAEncryption);
        addAlgorithm("SHA256WITHRSA", PKCSObjectIdentifiers.sha256WithRSAEncryption);
        addAlgorithm("SHA384WITHRSAENCRYPTION", PKCSObjectIdentifiers.sha384WithRSAEncryption);
        addAlgorithm("SHA384WITHRSA", PKCSObjectIdentifiers.sha384WithRSAEncryption);
        addAlgorithm("SHA512WITHRSAENCRYPTION", PKCSObjectIdentifiers.sha512WithRSAEncryption);
        addAlgorithm("SHA512WITHRSA", PKCSObjectIdentifiers.sha512WithRSAEncryption);
        addAlgorithm("SHA512(224)WITHRSAENCRYPTION", PKCSObjectIdentifiers.sha512_224WithRSAEncryption);
        addAlgorithm("SHA512(224)WITHRSA", PKCSObjectIdentifiers.sha512_224WithRSAEncryption);
        addAlgorithm("SHA512(256)WITHRSAENCRYPTION", PKCSObjectIdentifiers.sha512_256WithRSAEncryption);
        addAlgorithm("SHA512(256)WITHRSA", PKCSObjectIdentifiers.sha512_256WithRSAEncryption);
        addAlgorithm("SHA1WITHRSAANDMGF1", PKCSObjectIdentifiers.id_RSASSA_PSS);
        addAlgorithm("SHA224WITHRSAANDMGF1", PKCSObjectIdentifiers.id_RSASSA_PSS);
        addAlgorithm("SHA256WITHRSAANDMGF1", PKCSObjectIdentifiers.id_RSASSA_PSS);
        addAlgorithm("SHA384WITHRSAANDMGF1", PKCSObjectIdentifiers.id_RSASSA_PSS);
        addAlgorithm("SHA512WITHRSAANDMGF1", PKCSObjectIdentifiers.id_RSASSA_PSS);
        addAlgorithm("SHA3-224WITHRSAANDMGF1", PKCSObjectIdentifiers.id_RSASSA_PSS);
        addAlgorithm("SHA3-256WITHRSAANDMGF1", PKCSObjectIdentifiers.id_RSASSA_PSS);
        addAlgorithm("SHA3-384WITHRSAANDMGF1", PKCSObjectIdentifiers.id_RSASSA_PSS);
        addAlgorithm("SHA3-512WITHRSAANDMGF1", PKCSObjectIdentifiers.id_RSASSA_PSS);
        addAlgorithm("RIPEMD160WITHRSAENCRYPTION", TeleTrusTObjectIdentifiers.rsaSignatureWithripemd160);
        addAlgorithm("RIPEMD160WITHRSA", TeleTrusTObjectIdentifiers.rsaSignatureWithripemd160);
        addAlgorithm("RIPEMD128WITHRSAENCRYPTION", TeleTrusTObjectIdentifiers.rsaSignatureWithripemd128);
        addAlgorithm("RIPEMD128WITHRSA", TeleTrusTObjectIdentifiers.rsaSignatureWithripemd128);
        addAlgorithm("RIPEMD256WITHRSAENCRYPTION", TeleTrusTObjectIdentifiers.rsaSignatureWithripemd256);
        addAlgorithm("RIPEMD256WITHRSA", TeleTrusTObjectIdentifiers.rsaSignatureWithripemd256);
        addAlgorithm("SHA1WITHDSA", X9ObjectIdentifiers.id_dsa_with_sha1);
        addAlgorithm("DSAWITHSHA1", X9ObjectIdentifiers.id_dsa_with_sha1);
        addAlgorithm("SHA224WITHDSA", NISTObjectIdentifiers.dsa_with_sha224);
        addAlgorithm("SHA256WITHDSA", NISTObjectIdentifiers.dsa_with_sha256);
        addAlgorithm("SHA384WITHDSA", NISTObjectIdentifiers.dsa_with_sha384);
        addAlgorithm("SHA512WITHDSA", NISTObjectIdentifiers.dsa_with_sha512);
        addAlgorithm("SHA3-224WITHDSA", NISTObjectIdentifiers.id_dsa_with_sha3_224);
        addAlgorithm("SHA3-256WITHDSA", NISTObjectIdentifiers.id_dsa_with_sha3_256);
        addAlgorithm("SHA3-384WITHDSA", NISTObjectIdentifiers.id_dsa_with_sha3_384);
        addAlgorithm("SHA3-512WITHDSA", NISTObjectIdentifiers.id_dsa_with_sha3_512);
        addAlgorithm("SHA3-224WITHECDSA", NISTObjectIdentifiers.id_ecdsa_with_sha3_224);
        addAlgorithm("SHA3-256WITHECDSA", NISTObjectIdentifiers.id_ecdsa_with_sha3_256);
        addAlgorithm("SHA3-384WITHECDSA", NISTObjectIdentifiers.id_ecdsa_with_sha3_384);
        addAlgorithm("SHA3-512WITHECDSA", NISTObjectIdentifiers.id_ecdsa_with_sha3_512);
        addAlgorithm("SHA3-224WITHRSA", NISTObjectIdentifiers.id_rsassa_pkcs1_v1_5_with_sha3_224);
        addAlgorithm("SHA3-256WITHRSA", NISTObjectIdentifiers.id_rsassa_pkcs1_v1_5_with_sha3_256);
        addAlgorithm("SHA3-384WITHRSA", NISTObjectIdentifiers.id_rsassa_pkcs1_v1_5_with_sha3_384);
        addAlgorithm("SHA3-512WITHRSA", NISTObjectIdentifiers.id_rsassa_pkcs1_v1_5_with_sha3_512);
        addAlgorithm("SHA3-224WITHRSAENCRYPTION", NISTObjectIdentifiers.id_rsassa_pkcs1_v1_5_with_sha3_224);
        addAlgorithm("SHA3-256WITHRSAENCRYPTION", NISTObjectIdentifiers.id_rsassa_pkcs1_v1_5_with_sha3_256);
        addAlgorithm("SHA3-384WITHRSAENCRYPTION", NISTObjectIdentifiers.id_rsassa_pkcs1_v1_5_with_sha3_384);
        addAlgorithm("SHA3-512WITHRSAENCRYPTION", NISTObjectIdentifiers.id_rsassa_pkcs1_v1_5_with_sha3_512);
        addAlgorithm("SHA1WITHECDSA", X9ObjectIdentifiers.ecdsa_with_SHA1);
        addAlgorithm("ECDSAWITHSHA1", X9ObjectIdentifiers.ecdsa_with_SHA1);
        addAlgorithm("SHA224WITHECDSA", X9ObjectIdentifiers.ecdsa_with_SHA224);
        addAlgorithm("SHA256WITHECDSA", X9ObjectIdentifiers.ecdsa_with_SHA256);
        addAlgorithm("SHA384WITHECDSA", X9ObjectIdentifiers.ecdsa_with_SHA384);
        addAlgorithm("SHA512WITHECDSA", X9ObjectIdentifiers.ecdsa_with_SHA512);
        addAlgorithm("GOST3411WITHGOST3410", CryptoProObjectIdentifiers.gostR3411_94_with_gostR3410_94);
        addAlgorithm("GOST3411WITHGOST3410-94", CryptoProObjectIdentifiers.gostR3411_94_with_gostR3410_94);
        addAlgorithm("GOST3411WITHECGOST3410", CryptoProObjectIdentifiers.gostR3411_94_with_gostR3410_2001);
        addAlgorithm("GOST3411WITHECGOST3410-2001", CryptoProObjectIdentifiers.gostR3411_94_with_gostR3410_2001);
        addAlgorithm("GOST3411WITHGOST3410-2001", CryptoProObjectIdentifiers.gostR3411_94_with_gostR3410_2001);
        addAlgorithm("GOST3411WITHECGOST3410-2012-256", RosstandartObjectIdentifiers.id_tc26_signwithdigest_gost_3410_12_256);
        addAlgorithm("GOST3411WITHECGOST3410-2012-512", RosstandartObjectIdentifiers.id_tc26_signwithdigest_gost_3410_12_512);
        addAlgorithm("GOST3411WITHGOST3410-2012-256", RosstandartObjectIdentifiers.id_tc26_signwithdigest_gost_3410_12_256);
        addAlgorithm("GOST3411WITHGOST3410-2012-512", RosstandartObjectIdentifiers.id_tc26_signwithdigest_gost_3410_12_512);
        addAlgorithm("GOST3411-2012-256WITHECGOST3410-2012-256", RosstandartObjectIdentifiers.id_tc26_signwithdigest_gost_3410_12_256);
        addAlgorithm("GOST3411-2012-512WITHECGOST3410-2012-512", RosstandartObjectIdentifiers.id_tc26_signwithdigest_gost_3410_12_512);
        addAlgorithm("GOST3411-2012-256WITHGOST3410-2012-256", RosstandartObjectIdentifiers.id_tc26_signwithdigest_gost_3410_12_256);
        addAlgorithm("GOST3411-2012-512WITHGOST3410-2012-512", RosstandartObjectIdentifiers.id_tc26_signwithdigest_gost_3410_12_512);

        addAlgorithm("SHA1WITHCVC-ECDSA", EACObjectIdentifiers.id_TA_ECDSA_SHA_1);
        addAlgorithm("SHA224WITHCVC-ECDSA", EACObjectIdentifiers.id_TA_ECDSA_SHA_224);
        addAlgorithm("SHA256WITHCVC-ECDSA", EACObjectIdentifiers.id_TA_ECDSA_SHA_256);
        addAlgorithm("SHA384WITHCVC-ECDSA", EACObjectIdentifiers.id_TA_ECDSA_SHA_384);
        addAlgorithm("SHA512WITHCVC-ECDSA", EACObjectIdentifiers.id_TA_ECDSA_SHA_512);
        addAlgorithm("SHA3-512WITHSPHINCS256", BCObjectIdentifiers.sphincs256_with_SHA3_512);
        addAlgorithm("SHA512WITHSPHINCS256", BCObjectIdentifiers.sphincs256_with_SHA512);

        addAlgorithm("SHA1WITHPLAIN-ECDSA", BSIObjectIdentifiers.ecdsa_plain_SHA1);
        addAlgorithm("RIPEMD160WITHPLAIN-ECDSA", BSIObjectIdentifiers.ecdsa_plain_RIPEMD160);
        addAlgorithm("SHA224WITHPLAIN-ECDSA", BSIObjectIdentifiers.ecdsa_plain_SHA224);
        addAlgorithm("SHA256WITHPLAIN-ECDSA", BSIObjectIdentifiers.ecdsa_plain_SHA256);
        addAlgorithm("SHA384WITHPLAIN-ECDSA", BSIObjectIdentifiers.ecdsa_plain_SHA384);
        addAlgorithm("SHA512WITHPLAIN-ECDSA", BSIObjectIdentifiers.ecdsa_plain_SHA512);
        addAlgorithm("SHA3-224WITHPLAIN-ECDSA", BSIObjectIdentifiers.ecdsa_plain_SHA3_224);
        addAlgorithm("SHA3-256WITHPLAIN-ECDSA", BSIObjectIdentifiers.ecdsa_plain_SHA3_256);
        addAlgorithm("SHA3-384WITHPLAIN-ECDSA", BSIObjectIdentifiers.ecdsa_plain_SHA3_384);
        addAlgorithm("SHA3-512WITHPLAIN-ECDSA", BSIObjectIdentifiers.ecdsa_plain_SHA3_512);

        addAlgorithm("ED25519", EdECObjectIdentifiers.id_Ed25519);
        addAlgorithm("ED448", EdECObjectIdentifiers.id_Ed448);

        // RFC 8692
        addAlgorithm("SHAKE128WITHRSAPSS", X509ObjectIdentifiers.id_rsassa_pss_shake128);
        addAlgorithm("SHAKE256WITHRSAPSS", X509ObjectIdentifiers.id_rsassa_pss_shake256);
        addAlgorithm("SHAKE128WITHRSASSA-PSS", X509ObjectIdentifiers.id_rsassa_pss_shake128);
        addAlgorithm("SHAKE256WITHRSASSA-PSS", X509ObjectIdentifiers.id_rsassa_pss_shake256);
        addAlgorithm("SHAKE128WITHECDSA", X509ObjectIdentifiers.id_ecdsa_with_shake128);
        addAlgorithm("SHAKE256WITHECDSA", X509ObjectIdentifiers.id_ecdsa_with_shake256);

//        addAlgorithm("RIPEMD160WITHSM2", GMObjectIdentifiers.sm2sign_with_rmd160);
//        addAlgorithm("SHA1WITHSM2", GMObjectIdentifiers.sm2sign_with_sha1);
//        addAlgorithm("SHA224WITHSM2", GMObjectIdentifiers.sm2sign_with_sha224);
        addAlgorithm("SHA256WITHSM2", GMObjectIdentifiers.sm2sign_with_sha256);
//        addAlgorithm("SHA384WITHSM2", GMObjectIdentifiers.sm2sign_with_sha384);
//        addAlgorithm("SHA512WITHSM2", GMObjectIdentifiers.sm2sign_with_sha512);
        addAlgorithm("SM3WITHSM2", GMObjectIdentifiers.sm2sign_with_sm3);

        addAlgorithm("SHA256WITHXMSS", BCObjectIdentifiers.xmss_SHA256ph);
        addAlgorithm("SHA512WITHXMSS", BCObjectIdentifiers.xmss_SHA512ph);
        addAlgorithm("SHAKE128WITHXMSS", BCObjectIdentifiers.xmss_SHAKE128ph);
        addAlgorithm("SHAKE256WITHXMSS", BCObjectIdentifiers.xmss_SHAKE256ph);
        addAlgorithm("SHAKE128(512)WITHXMSS", BCObjectIdentifiers.xmss_SHAKE128_512ph);
        addAlgorithm("SHAKE256(1024)WITHXMSS", BCObjectIdentifiers.xmss_SHAKE256_1024ph);

        addAlgorithm("SHA256WITHXMSSMT", BCObjectIdentifiers.xmss_mt_SHA256ph);
        addAlgorithm("SHA512WITHXMSSMT", BCObjectIdentifiers.xmss_mt_SHA512ph);
        addAlgorithm("SHAKE128WITHXMSSMT", BCObjectIdentifiers.xmss_mt_SHAKE128ph);
        addAlgorithm("SHAKE256WITHXMSSMT", BCObjectIdentifiers.xmss_mt_SHAKE256ph);

        addAlgorithm("SHA256WITHXMSS-SHA256", BCObjectIdentifiers.xmss_SHA256ph);
        addAlgorithm("SHA512WITHXMSS-SHA512", BCObjectIdentifiers.xmss_SHA512ph);
        addAlgorithm("SHAKE128WITHXMSS-SHAKE128", BCObjectIdentifiers.xmss_SHAKE128ph);
        addAlgorithm("SHAKE256WITHXMSS-SHAKE256", BCObjectIdentifiers.xmss_SHAKE256ph);

        addAlgorithm("SHA256WITHXMSSMT-SHA256", BCObjectIdentifiers.xmss_mt_SHA256ph);
        addAlgorithm("SHA512WITHXMSSMT-SHA512", BCObjectIdentifiers.xmss_mt_SHA512ph);
        addAlgorithm("SHAKE128WITHXMSSMT-SHAKE128", BCObjectIdentifiers.xmss_mt_SHAKE128ph);
        addAlgorithm("SHAKE256WITHXMSSMT-SHAKE256", BCObjectIdentifiers.xmss_mt_SHAKE256ph);
        addAlgorithm("SHAKE128(512)WITHXMSSMT-SHAKE128", BCObjectIdentifiers.xmss_mt_SHAKE128_512ph);
        addAlgorithm("SHAKE256(1024)WITHXMSSMT-SHAKE256", BCObjectIdentifiers.xmss_mt_SHAKE256_1024ph);

        addAlgorithm("LMS", PKCSObjectIdentifiers.id_alg_hss_lms_hashsig);

        addAlgorithm("XMSS", IsaraObjectIdentifiers.id_alg_xmss);
        addAlgorithm("XMSS-SHA256", BCObjectIdentifiers.xmss_SHA256);
        addAlgorithm("XMSS-SHA512", BCObjectIdentifiers.xmss_SHA512);
        addAlgorithm("XMSS-SHAKE128", BCObjectIdentifiers.xmss_SHAKE128);
        addAlgorithm("XMSS-SHAKE256", BCObjectIdentifiers.xmss_SHAKE256);

        addAlgorithm("XMSSMT", IsaraObjectIdentifiers.id_alg_xmssmt);
        addAlgorithm("XMSSMT-SHA256", BCObjectIdentifiers.xmss_mt_SHA256);
        addAlgorithm("XMSSMT-SHA512", BCObjectIdentifiers.xmss_mt_SHA512);
        addAlgorithm("XMSSMT-SHAKE128", BCObjectIdentifiers.xmss_mt_SHAKE128);
        addAlgorithm("XMSSMT-SHAKE256", BCObjectIdentifiers.xmss_mt_SHAKE256);

        addAlgorithm("SPHINCS+", BCObjectIdentifiers.sphincsPlus);
        addAlgorithm("SPHINCSPLUS", BCObjectIdentifiers.sphincsPlus);
        addAlgorithm("SPHINCS+-SHA2-128S", BCObjectIdentifiers.sphincsPlus_sha2_128s);
        addAlgorithm("SPHINCS+-SHA2-128F", BCObjectIdentifiers.sphincsPlus_sha2_128f);
        addAlgorithm("SPHINCS+-SHA2-192S", BCObjectIdentifiers.sphincsPlus_sha2_192s);
        addAlgorithm("SPHINCS+-SHA2-192F", BCObjectIdentifiers.sphincsPlus_sha2_192f);
        addAlgorithm("SPHINCS+-SHA2-256S", BCObjectIdentifiers.sphincsPlus_sha2_256s);
        addAlgorithm("SPHINCS+-SHA2-256F", BCObjectIdentifiers.sphincsPlus_sha2_256f);
        addAlgorithm("SPHINCS+-SHAKE-128S", BCObjectIdentifiers.sphincsPlus_shake_128s);
        addAlgorithm("SPHINCS+-SHAKE-128F", BCObjectIdentifiers.sphincsPlus_shake_128f);
        addAlgorithm("SPHINCS+-SHAKE-192S", BCObjectIdentifiers.sphincsPlus_shake_192s);
        addAlgorithm("SPHINCS+-SHAKE-192F", BCObjectIdentifiers.sphincsPlus_shake_192f);
        addAlgorithm("SPHINCS+-SHAKE-256S", BCObjectIdentifiers.sphincsPlus_shake_256s);
        addAlgorithm("SPHINCS+-SHAKE-256F", BCObjectIdentifiers.sphincsPlus_shake_256f);
        addAlgorithm("SPHINCS+-HARAKA-128S-ROBUST", BCObjectIdentifiers.sphincsPlus_haraka_128s_r3);
        addAlgorithm("SPHINCS+-HARAKA-128F-ROBUST", BCObjectIdentifiers.sphincsPlus_haraka_128f_r3);
        addAlgorithm("SPHINCS+-HARAKA-192S-ROBUST", BCObjectIdentifiers.sphincsPlus_haraka_192s_r3);
        addAlgorithm("SPHINCS+-HARAKA-192F-ROBUST", BCObjectIdentifiers.sphincsPlus_haraka_192f_r3);
        addAlgorithm("SPHINCS+-HARAKA-256S-ROBUST", BCObjectIdentifiers.sphincsPlus_haraka_256s_r3);
        addAlgorithm("SPHINCS+-HARAKA-256F-ROBUST", BCObjectIdentifiers.sphincsPlus_haraka_256f_r3);
        addAlgorithm("SPHINCS+-HARAKA-128S-SIMPLE", BCObjectIdentifiers.sphincsPlus_haraka_128s_r3_simple);
        addAlgorithm("SPHINCS+-HARAKA-128F-SIMPLE", BCObjectIdentifiers.sphincsPlus_haraka_128f_r3_simple);
        addAlgorithm("SPHINCS+-HARAKA-192S-SIMPLE", BCObjectIdentifiers.sphincsPlus_haraka_192s_r3_simple);
        addAlgorithm("SPHINCS+-HARAKA-192F-SIMPLE", BCObjectIdentifiers.sphincsPlus_haraka_192f_r3_simple);
        addAlgorithm("SPHINCS+-HARAKA-256S-SIMPLE", BCObjectIdentifiers.sphincsPlus_haraka_256s_r3_simple);
        addAlgorithm("SPHINCS+-HARAKA-256F-SIMPLE", BCObjectIdentifiers.sphincsPlus_haraka_256f_r3_simple);
        addAlgorithm("DILITHIUM2", NISTObjectIdentifiers.id_ml_dsa_44);
        addAlgorithm("DILITHIUM3", NISTObjectIdentifiers.id_ml_dsa_65);
        addAlgorithm("DILITHIUM5", NISTObjectIdentifiers.id_ml_dsa_87);
        addAlgorithm("DILITHIUM2-AES", BCObjectIdentifiers.dilithium2_aes);
        addAlgorithm("DILITHIUM3-AES", BCObjectIdentifiers.dilithium3_aes);
        addAlgorithm("DILITHIUM5-AES", BCObjectIdentifiers.dilithium5_aes);

        addAlgorithm("ML-DSA-44", NISTObjectIdentifiers.id_ml_dsa_44);
        addAlgorithm("ML-DSA-65", NISTObjectIdentifiers.id_ml_dsa_65);
        addAlgorithm("ML-DSA-87", NISTObjectIdentifiers.id_ml_dsa_87);

        addAlgorithm("ML-DSA-44-WITH-SHA512", NISTObjectIdentifiers.id_hash_ml_dsa_44_with_sha512);
        addAlgorithm("ML-DSA-65-WITH-SHA512", NISTObjectIdentifiers.id_hash_ml_dsa_65_with_sha512);
        addAlgorithm("ML-DSA-87-WITH-SHA512", NISTObjectIdentifiers.id_hash_ml_dsa_87_with_sha512);

        addAlgorithm("SLH-DSA-SHA2-128S", NISTObjectIdentifiers.id_slh_dsa_sha2_128s);
        addAlgorithm("SLH-DSA-SHA2-128F", NISTObjectIdentifiers.id_slh_dsa_sha2_128f);
        addAlgorithm("SLH-DSA-SHA2-192S", NISTObjectIdentifiers.id_slh_dsa_sha2_192s);
        addAlgorithm("SLH-DSA-SHA2-192F", NISTObjectIdentifiers.id_slh_dsa_sha2_192f);
        addAlgorithm("SLH-DSA-SHA2-256S", NISTObjectIdentifiers.id_slh_dsa_sha2_256s);
        addAlgorithm("SLH-DSA-SHA2-256F", NISTObjectIdentifiers.id_slh_dsa_sha2_256f);
        addAlgorithm("SLH-DSA-SHAKE-128S", NISTObjectIdentifiers.id_slh_dsa_shake_128s);
        addAlgorithm("SLH-DSA-SHAKE-128F", NISTObjectIdentifiers.id_slh_dsa_shake_128f);
        addAlgorithm("SLH-DSA-SHAKE-192S", NISTObjectIdentifiers.id_slh_dsa_shake_192s);
        addAlgorithm("SLH-DSA-SHAKE-192F", NISTObjectIdentifiers.id_slh_dsa_shake_192f);
        addAlgorithm("SLH-DSA-SHAKE-256S", NISTObjectIdentifiers.id_slh_dsa_shake_256s);
        addAlgorithm("SLH-DSA-SHAKE-256F", NISTObjectIdentifiers.id_slh_dsa_shake_256f);

        addAlgorithm("SLH-DSA-SHA2-128S-WITH-SHA256", NISTObjectIdentifiers.id_hash_slh_dsa_sha2_128s_with_sha256);
        addAlgorithm("SLH-DSA-SHA2-128F-WITH-SHA256", NISTObjectIdentifiers.id_hash_slh_dsa_sha2_128f_with_sha256);
        addAlgorithm("SLH-DSA-SHA2-192S-WITH-SHA512", NISTObjectIdentifiers.id_hash_slh_dsa_sha2_192s_with_sha512);
        addAlgorithm("SLH-DSA-SHA2-192F-WITH-SHA512", NISTObjectIdentifiers.id_hash_slh_dsa_sha2_192f_with_sha512);
        addAlgorithm("SLH-DSA-SHA2-256S-WITH-SHA512", NISTObjectIdentifiers.id_hash_slh_dsa_sha2_256s_with_sha512);
        addAlgorithm("SLH-DSA-SHA2-256F-WITH-SHA512", NISTObjectIdentifiers.id_hash_slh_dsa_sha2_256f_with_sha512);
        addAlgorithm("SLH-DSA-SHAKE-128S-WITH-SHAKE128", NISTObjectIdentifiers.id_hash_slh_dsa_shake_128s_with_shake128);
        addAlgorithm("SLH-DSA-SHAKE-128F-WITH-SHAKE128", NISTObjectIdentifiers.id_hash_slh_dsa_shake_128f_with_shake128);
        addAlgorithm("SLH-DSA-SHAKE-192S-WITH-SHAKE256", NISTObjectIdentifiers.id_hash_slh_dsa_shake_192s_with_shake256);
        addAlgorithm("SLH-DSA-SHAKE-192F-WITH-SHAKE256", NISTObjectIdentifiers.id_hash_slh_dsa_shake_192f_with_shake256);
        addAlgorithm("SLH-DSA-SHAKE-256S-WITH-SHAKE256", NISTObjectIdentifiers.id_hash_slh_dsa_shake_256s_with_shake256);
        addAlgorithm("SLH-DSA-SHAKE-256F-WITH-SHAKE256", NISTObjectIdentifiers.id_hash_slh_dsa_shake_256f_with_shake256);

        addAlgorithm("FALCON-512", BCObjectIdentifiers.falcon_512);
        addAlgorithm("FALCON-1024", BCObjectIdentifiers.falcon_1024);

        addAlgorithm("PICNIC", BCObjectIdentifiers.picnic_signature);
        addAlgorithm("SHA512WITHPICNIC", BCObjectIdentifiers.picnic_with_sha512);
        addAlgorithm("SHA3-512WITHPICNIC", BCObjectIdentifiers.picnic_with_sha3_512);
        addAlgorithm("SHAKE256WITHPICNIC", BCObjectIdentifiers.picnic_with_shake256);

        addAlgorithm("MLDSA44-RSA2048-PSS-SHA256", MiscObjectIdentifiers.id_MLDSA44_RSA2048_PSS_SHA256);
        addAlgorithm("MLDSA44-RSA2048-PKCS15-SHA256", MiscObjectIdentifiers.id_MLDSA44_RSA2048_PKCS15_SHA256);
        addAlgorithm("MLDSA44-ED25519-SHA512", MiscObjectIdentifiers.id_MLDSA44_Ed25519_SHA512);
        addAlgorithm("MLDSA44-ECDSA-P256-SHA256", MiscObjectIdentifiers.id_MLDSA44_ECDSA_P256_SHA256);
        addAlgorithm("MLDSA65-RSA3072-PSS-SHA256", MiscObjectIdentifiers.id_MLDSA65_RSA3072_PSS_SHA256);
        addAlgorithm("MLDSA65-RSA3072-PKCS15-SHA256", MiscObjectIdentifiers.id_MLDSA65_RSA3072_PKCS15_SHA256);
        addAlgorithm("MLDSA65-RSA4096-PSS-SHA384", MiscObjectIdentifiers.id_MLDSA65_RSA4096_PSS_SHA384);
        addAlgorithm("MLDSA65-RSA4096-PKCS15-SHA384", MiscObjectIdentifiers.id_MLDSA65_RSA4096_PKCS15_SHA384);
        addAlgorithm("MLDSA65-ECDSA-P384-SHA384", MiscObjectIdentifiers.id_MLDSA65_ECDSA_P384_SHA384);
        addAlgorithm("MLDSA65-ECDSA-BRAINPOOLP256R1-SHA256", MiscObjectIdentifiers.id_MLDSA65_ECDSA_brainpoolP256r1_SHA256);
        addAlgorithm("MLDSA65-ED25519-SHA512", MiscObjectIdentifiers.id_MLDSA65_Ed25519_SHA512);
        addAlgorithm("MLDSA87-ECDSA-P384-SHA384", MiscObjectIdentifiers.id_MLDSA87_ECDSA_P384_SHA384);
        addAlgorithm("MLDSA87-ECDSA-BRAINPOOLP384R1-SHA384", MiscObjectIdentifiers.id_MLDSA87_ECDSA_brainpoolP384r1_SHA384);
        addAlgorithm("MLDSA87-ED448-SHA512", MiscObjectIdentifiers.id_MLDSA87_Ed448_SHA512);

        addAlgorithm("HASHMLDSA44-RSA2048-PSS-SHA256", MiscObjectIdentifiers.id_HashMLDSA44_RSA2048_PSS_SHA256);
        addAlgorithm("HASHMLDSA44-RSA2048-PKCS15-SHA256", MiscObjectIdentifiers.id_HashMLDSA44_RSA2048_PKCS15_SHA256);
        addAlgorithm("HASHMLDSA44-ED25519-SHA512", MiscObjectIdentifiers.id_HashMLDSA44_Ed25519_SHA512);
        addAlgorithm("HASHMLDSA44-ECDSA-P256-SHA256", MiscObjectIdentifiers.id_HashMLDSA44_ECDSA_P256_SHA256);
        addAlgorithm("HASHMLDSA65-RSA3072-PSS-SHA512", MiscObjectIdentifiers.id_HashMLDSA65_RSA3072_PSS_SHA512);
        addAlgorithm("HASHMLDSA65-RSA3072-PKCS15-SHA512", MiscObjectIdentifiers.id_HashMLDSA65_RSA3072_PKCS15_SHA512);
        addAlgorithm("HASHMLDSA65-RSA4096-PSS-SHA512", MiscObjectIdentifiers.id_HashMLDSA65_RSA4096_PSS_SHA512);
        addAlgorithm("HASHMLDSA65-RSA4096-PKCS15-SHA512", MiscObjectIdentifiers.id_HashMLDSA65_RSA4096_PKCS15_SHA512);
        addAlgorithm("HASHMLDSA65-ECDSA-P384-SHA512", MiscObjectIdentifiers.id_HashMLDSA65_ECDSA_P384_SHA512);
        addAlgorithm("HASHMLDSA65-ECDSA-BRAINPOOLP256R1-SHA512", MiscObjectIdentifiers.id_HashMLDSA65_ECDSA_brainpoolP256r1_SHA512);
        addAlgorithm("HASHMLDSA65-ED25519-SHA512", MiscObjectIdentifiers.id_HashMLDSA65_Ed25519_SHA512);
        addAlgorithm("HASHMLDSA87-ECDSA-P384-SHA512", MiscObjectIdentifiers.id_HashMLDSA87_ECDSA_P384_SHA512);
        addAlgorithm("HASHMLDSA87-ECDSA-BRAINPOOLP384R1-SHA512", MiscObjectIdentifiers.id_HashMLDSA87_ECDSA_brainpoolP384r1_SHA512);
        addAlgorithm("HASHMLDSA87-ED448-SHA512", MiscObjectIdentifiers.id_HashMLDSA87_Ed448_SHA512);

        //
        // According to RFC 3279, the ASN.1 encoding SHALL (id-dsa-with-sha1) or MUST (ecdsa-with-SHA*) omit the parameters field.
        // The parameters field SHALL be NULL for RSA based signature algorithms.
        //
        noParams.add(X9ObjectIdentifiers.ecdsa_with_SHA1);
        noParams.add(X9ObjectIdentifiers.ecdsa_with_SHA224);
        noParams.add(X9ObjectIdentifiers.ecdsa_with_SHA256);
        noParams.add(X9ObjectIdentifiers.ecdsa_with_SHA384);
        noParams.add(X9ObjectIdentifiers.ecdsa_with_SHA512);
        noParams.add(X9ObjectIdentifiers.id_dsa_with_sha1);
        noParams.add(OIWObjectIdentifiers.dsaWithSHA1);
        noParams.add(NISTObjectIdentifiers.dsa_with_sha224);
        noParams.add(NISTObjectIdentifiers.dsa_with_sha256);
        noParams.add(NISTObjectIdentifiers.dsa_with_sha384);
        noParams.add(NISTObjectIdentifiers.dsa_with_sha512);
        noParams.add(NISTObjectIdentifiers.id_dsa_with_sha3_224);
        noParams.add(NISTObjectIdentifiers.id_dsa_with_sha3_256);
        noParams.add(NISTObjectIdentifiers.id_dsa_with_sha3_384);
        noParams.add(NISTObjectIdentifiers.id_dsa_with_sha3_512);
        noParams.add(NISTObjectIdentifiers.id_ecdsa_with_sha3_224);
        noParams.add(NISTObjectIdentifiers.id_ecdsa_with_sha3_256);
        noParams.add(NISTObjectIdentifiers.id_ecdsa_with_sha3_384);
        noParams.add(NISTObjectIdentifiers.id_ecdsa_with_sha3_512);

        noParams.add(BSIObjectIdentifiers.ecdsa_plain_SHA224);
        noParams.add(BSIObjectIdentifiers.ecdsa_plain_SHA256);
        noParams.add(BSIObjectIdentifiers.ecdsa_plain_SHA384);
        noParams.add(BSIObjectIdentifiers.ecdsa_plain_SHA512);
        noParams.add(BSIObjectIdentifiers.ecdsa_plain_SHA3_224);
        noParams.add(BSIObjectIdentifiers.ecdsa_plain_SHA3_256);
        noParams.add(BSIObjectIdentifiers.ecdsa_plain_SHA3_384);
        noParams.add(BSIObjectIdentifiers.ecdsa_plain_SHA3_512);

        //
        // RFC 4491
        //
        noParams.add(CryptoProObjectIdentifiers.gostR3411_94_with_gostR3410_94);
        noParams.add(CryptoProObjectIdentifiers.gostR3411_94_with_gostR3410_2001);
        noParams.add(RosstandartObjectIdentifiers.id_tc26_signwithdigest_gost_3410_12_256);
        noParams.add(RosstandartObjectIdentifiers.id_tc26_signwithdigest_gost_3410_12_512);

        //
        // SPHINCS-256
        //
        noParams.add(BCObjectIdentifiers.sphincs256_with_SHA512);
        noParams.add(BCObjectIdentifiers.sphincs256_with_SHA3_512);

        //
        // SPHINCS-PLUS
        //
        noParams.add(NISTObjectIdentifiers.id_slh_dsa_sha2_128s);
        noParams.add(NISTObjectIdentifiers.id_slh_dsa_sha2_128f);
        noParams.add(NISTObjectIdentifiers.id_slh_dsa_sha2_192s);
        noParams.add(NISTObjectIdentifiers.id_slh_dsa_sha2_192f);
        noParams.add(NISTObjectIdentifiers.id_slh_dsa_sha2_256s);
        noParams.add(NISTObjectIdentifiers.id_slh_dsa_sha2_256f);
        noParams.add(NISTObjectIdentifiers.id_slh_dsa_shake_128s);
        noParams.add(NISTObjectIdentifiers.id_slh_dsa_shake_128f);
        noParams.add(NISTObjectIdentifiers.id_slh_dsa_shake_192s);
        noParams.add(NISTObjectIdentifiers.id_slh_dsa_shake_192f);
        noParams.add(NISTObjectIdentifiers.id_slh_dsa_shake_256s);
        noParams.add(NISTObjectIdentifiers.id_slh_dsa_shake_256f);
        noParams.add(NISTObjectIdentifiers.id_hash_slh_dsa_sha2_128f_with_sha256);
        noParams.add(NISTObjectIdentifiers.id_hash_slh_dsa_sha2_128s_with_sha256);
        noParams.add(NISTObjectIdentifiers.id_hash_slh_dsa_sha2_192s_with_sha512);
        noParams.add(NISTObjectIdentifiers.id_hash_slh_dsa_sha2_192f_with_sha512);
        noParams.add(NISTObjectIdentifiers.id_hash_slh_dsa_sha2_256s_with_sha512);
        noParams.add(NISTObjectIdentifiers.id_hash_slh_dsa_sha2_256f_with_sha512);
        noParams.add(NISTObjectIdentifiers.id_hash_slh_dsa_shake_128s_with_shake128);
        noParams.add(NISTObjectIdentifiers.id_hash_slh_dsa_shake_128f_with_shake128);
        noParams.add(NISTObjectIdentifiers.id_hash_slh_dsa_shake_192s_with_shake256);
        noParams.add(NISTObjectIdentifiers.id_hash_slh_dsa_shake_192f_with_shake256);
        noParams.add(NISTObjectIdentifiers.id_hash_slh_dsa_shake_256s_with_shake256);
        noParams.add(NISTObjectIdentifiers.id_hash_slh_dsa_shake_256f_with_shake256);

        noParams.add(BCObjectIdentifiers.sphincsPlus);
        noParams.add(BCObjectIdentifiers.sphincsPlus_sha2_128s_r3);
        noParams.add(BCObjectIdentifiers.sphincsPlus_sha2_128f_r3);
        noParams.add(BCObjectIdentifiers.sphincsPlus_shake_128s_r3);
        noParams.add(BCObjectIdentifiers.sphincsPlus_shake_128f_r3);
        noParams.add(BCObjectIdentifiers.sphincsPlus_haraka_128s_r3);
        noParams.add(BCObjectIdentifiers.sphincsPlus_haraka_128f_r3);
        noParams.add(BCObjectIdentifiers.sphincsPlus_sha2_192s_r3);
        noParams.add(BCObjectIdentifiers.sphincsPlus_sha2_192f_r3);
        noParams.add(BCObjectIdentifiers.sphincsPlus_shake_192s_r3);
        noParams.add(BCObjectIdentifiers.sphincsPlus_shake_192f_r3);
        noParams.add(BCObjectIdentifiers.sphincsPlus_haraka_192s_r3);
        noParams.add(BCObjectIdentifiers.sphincsPlus_haraka_192f_r3);
        noParams.add(BCObjectIdentifiers.sphincsPlus_sha2_256s_r3);
        noParams.add(BCObjectIdentifiers.sphincsPlus_sha2_256f_r3);
        noParams.add(BCObjectIdentifiers.sphincsPlus_shake_256s_r3);
        noParams.add(BCObjectIdentifiers.sphincsPlus_shake_256f_r3);
        noParams.add(BCObjectIdentifiers.sphincsPlus_haraka_256s_r3);
        noParams.add(BCObjectIdentifiers.sphincsPlus_haraka_256f_r3);
        noParams.add(BCObjectIdentifiers.sphincsPlus_sha2_128s);
        noParams.add(BCObjectIdentifiers.sphincsPlus_sha2_128f);
        noParams.add(BCObjectIdentifiers.sphincsPlus_shake_128s);
        noParams.add(BCObjectIdentifiers.sphincsPlus_shake_128f);
        noParams.add(BCObjectIdentifiers.sphincsPlus_sha2_192s);
        noParams.add(BCObjectIdentifiers.sphincsPlus_sha2_192f);
        noParams.add(BCObjectIdentifiers.sphincsPlus_shake_192s);
        noParams.add(BCObjectIdentifiers.sphincsPlus_shake_192f);
        noParams.add(BCObjectIdentifiers.sphincsPlus_sha2_256s);
        noParams.add(BCObjectIdentifiers.sphincsPlus_sha2_256f);
        noParams.add(BCObjectIdentifiers.sphincsPlus_shake_256s);
        noParams.add(BCObjectIdentifiers.sphincsPlus_shake_256f);

        //
        // Dilithium
        //
        noParams.add(BCObjectIdentifiers.dilithium);
        noParams.add(BCObjectIdentifiers.dilithium2_aes);
        noParams.add(BCObjectIdentifiers.dilithium3_aes);
        noParams.add(BCObjectIdentifiers.dilithium5_aes);

        noParams.add(PKCSObjectIdentifiers.id_alg_hss_lms_hashsig);
        noParams.add(NISTObjectIdentifiers.id_ml_dsa_44);
        noParams.add(NISTObjectIdentifiers.id_ml_dsa_65);
        noParams.add(NISTObjectIdentifiers.id_ml_dsa_87);
        noParams.add(NISTObjectIdentifiers.id_hash_ml_dsa_44_with_sha512);
        noParams.add(NISTObjectIdentifiers.id_hash_ml_dsa_65_with_sha512);
        noParams.add(NISTObjectIdentifiers.id_hash_ml_dsa_87_with_sha512);


        //
        // Falcon
        //
        noParams.add(BCObjectIdentifiers.falcon);
        noParams.add(BCObjectIdentifiers.falcon_512);
        noParams.add(BCObjectIdentifiers.falcon_1024);

        //
        // Picnic
        //
        noParams.add(BCObjectIdentifiers.picnic_signature);
        noParams.add(BCObjectIdentifiers.picnic_with_sha512);
        noParams.add(BCObjectIdentifiers.picnic_with_sha3_512);
        noParams.add(BCObjectIdentifiers.picnic_with_shake256);

        //
        // XMSS
        //
        noParams.add(BCObjectIdentifiers.xmss_SHA256ph);
        noParams.add(BCObjectIdentifiers.xmss_SHA512ph);
        noParams.add(BCObjectIdentifiers.xmss_SHAKE128ph);
        noParams.add(BCObjectIdentifiers.xmss_SHAKE256ph);
        noParams.add(BCObjectIdentifiers.xmss_mt_SHA256ph);
        noParams.add(BCObjectIdentifiers.xmss_mt_SHA512ph);
        noParams.add(BCObjectIdentifiers.xmss_mt_SHAKE128ph);
        noParams.add(BCObjectIdentifiers.xmss_mt_SHAKE256ph);
        noParams.add(BCObjectIdentifiers.xmss_mt_SHAKE128ph);
        noParams.add(BCObjectIdentifiers.xmss_mt_SHAKE256ph);

        noParams.add(BCObjectIdentifiers.xmss_SHA256);
        noParams.add(BCObjectIdentifiers.xmss_SHA512);
        noParams.add(BCObjectIdentifiers.xmss_SHAKE128);
        noParams.add(BCObjectIdentifiers.xmss_SHAKE256);
        noParams.add(BCObjectIdentifiers.xmss_mt_SHA256);
        noParams.add(BCObjectIdentifiers.xmss_mt_SHA512);
        noParams.add(BCObjectIdentifiers.xmss_mt_SHAKE128);
        noParams.add(BCObjectIdentifiers.xmss_mt_SHAKE256);

        noParams.add(IsaraObjectIdentifiers.id_alg_xmss);
        noParams.add(IsaraObjectIdentifiers.id_alg_xmssmt);

        //
        // qTESLA
        //
        noParams.add(BCObjectIdentifiers.qTESLA_p_I);
        noParams.add(BCObjectIdentifiers.qTESLA_p_III);

        //
        // SM2
        //
//        noParams.add(GMObjectIdentifiers.sm2sign_with_rmd160);
//        noParams.add(GMObjectIdentifiers.sm2sign_with_sha1);
//        noParams.add(GMObjectIdentifiers.sm2sign_with_sha224);
        noParams.add(GMObjectIdentifiers.sm2sign_with_sha256);
//        noParams.add(GMObjectIdentifiers.sm2sign_with_sha384);
//        noParams.add(GMObjectIdentifiers.sm2sign_with_sha512);
        noParams.add(GMObjectIdentifiers.sm2sign_with_sm3);

        // EdDSA
        noParams.add(EdECObjectIdentifiers.id_Ed25519);
        noParams.add(EdECObjectIdentifiers.id_Ed448);

        // RFC 8692
        noParams.add(X509ObjectIdentifiers.id_rsassa_pss_shake128);
        noParams.add(X509ObjectIdentifiers.id_rsassa_pss_shake256);
        noParams.add(X509ObjectIdentifiers.id_ecdsa_with_shake128);
        noParams.add(X509ObjectIdentifiers.id_ecdsa_with_shake256);

        //
        // Composite - Draft 13
        //
        noParams.add(MiscObjectIdentifiers.id_MLDSA44_RSA2048_PSS_SHA256);
        noParams.add(MiscObjectIdentifiers.id_MLDSA44_RSA2048_PKCS15_SHA256);
        noParams.add(MiscObjectIdentifiers.id_MLDSA44_Ed25519_SHA512);
        noParams.add(MiscObjectIdentifiers.id_MLDSA44_ECDSA_P256_SHA256);
        noParams.add(MiscObjectIdentifiers.id_MLDSA65_RSA3072_PSS_SHA256);
        noParams.add(MiscObjectIdentifiers.id_MLDSA65_RSA3072_PKCS15_SHA256);
        noParams.add(MiscObjectIdentifiers.id_MLDSA65_RSA4096_PSS_SHA384);
        noParams.add(MiscObjectIdentifiers.id_MLDSA65_RSA4096_PKCS15_SHA384);
        noParams.add(MiscObjectIdentifiers.id_MLDSA65_ECDSA_P384_SHA384);
        noParams.add(MiscObjectIdentifiers.id_MLDSA65_ECDSA_brainpoolP256r1_SHA256);
        noParams.add(MiscObjectIdentifiers.id_MLDSA65_Ed25519_SHA512);
        noParams.add(MiscObjectIdentifiers.id_MLDSA87_ECDSA_P384_SHA384);
        noParams.add(MiscObjectIdentifiers.id_MLDSA87_ECDSA_brainpoolP384r1_SHA384);
        noParams.add(MiscObjectIdentifiers.id_MLDSA87_Ed448_SHA512);

        noParams.add(MiscObjectIdentifiers.id_HashMLDSA44_RSA2048_PSS_SHA256);
        noParams.add(MiscObjectIdentifiers.id_HashMLDSA44_RSA2048_PKCS15_SHA256);
        noParams.add(MiscObjectIdentifiers.id_HashMLDSA44_Ed25519_SHA512);
        noParams.add(MiscObjectIdentifiers.id_HashMLDSA44_ECDSA_P256_SHA256);
        noParams.add(MiscObjectIdentifiers.id_HashMLDSA65_RSA3072_PSS_SHA512);
        noParams.add(MiscObjectIdentifiers.id_HashMLDSA65_RSA3072_PKCS15_SHA512);
        noParams.add(MiscObjectIdentifiers.id_HashMLDSA65_RSA4096_PSS_SHA512);
        noParams.add(MiscObjectIdentifiers.id_HashMLDSA65_RSA4096_PKCS15_SHA512);
        noParams.add(MiscObjectIdentifiers.id_HashMLDSA65_ECDSA_P384_SHA512);
        noParams.add(MiscObjectIdentifiers.id_HashMLDSA65_ECDSA_brainpoolP256r1_SHA512);
        noParams.add(MiscObjectIdentifiers.id_HashMLDSA65_Ed25519_SHA512);
        noParams.add(MiscObjectIdentifiers.id_HashMLDSA87_ECDSA_P384_SHA512);
        noParams.add(MiscObjectIdentifiers.id_HashMLDSA87_ECDSA_brainpoolP384r1_SHA512);
        noParams.add(MiscObjectIdentifiers.id_HashMLDSA87_Ed448_SHA512);

        //
        // PKCS 1.5 encrypted  algorithms
        //
        pkcs15RsaEncryption.add(PKCSObjectIdentifiers.sha1WithRSAEncryption);
        pkcs15RsaEncryption.add(PKCSObjectIdentifiers.sha224WithRSAEncryption);
        pkcs15RsaEncryption.add(PKCSObjectIdentifiers.sha256WithRSAEncryption);
        pkcs15RsaEncryption.add(PKCSObjectIdentifiers.sha384WithRSAEncryption);
        pkcs15RsaEncryption.add(PKCSObjectIdentifiers.sha512WithRSAEncryption);
        pkcs15RsaEncryption.add(PKCSObjectIdentifiers.sha512_224WithRSAEncryption);
        pkcs15RsaEncryption.add(PKCSObjectIdentifiers.sha512_256WithRSAEncryption);
        pkcs15RsaEncryption.add(TeleTrusTObjectIdentifiers.rsaSignatureWithripemd128);
        pkcs15RsaEncryption.add(TeleTrusTObjectIdentifiers.rsaSignatureWithripemd160);
        pkcs15RsaEncryption.add(TeleTrusTObjectIdentifiers.rsaSignatureWithripemd256);
        pkcs15RsaEncryption.add(NISTObjectIdentifiers.id_rsassa_pkcs1_v1_5_with_sha3_224);
        pkcs15RsaEncryption.add(NISTObjectIdentifiers.id_rsassa_pkcs1_v1_5_with_sha3_256);
        pkcs15RsaEncryption.add(NISTObjectIdentifiers.id_rsassa_pkcs1_v1_5_with_sha3_384);
        pkcs15RsaEncryption.add(NISTObjectIdentifiers.id_rsassa_pkcs1_v1_5_with_sha3_512);

        //
        // explicit params
        //
        AlgorithmIdentifier sha1AlgId = new AlgorithmIdentifier(OIWObjectIdentifiers.idSHA1, DERNull.INSTANCE);
        addParameters("SHA1WITHRSAANDMGF1", createPSSParams(sha1AlgId, 20));

        AlgorithmIdentifier sha224AlgId = new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha224, DERNull.INSTANCE);
        addParameters("SHA224WITHRSAANDMGF1", createPSSParams(sha224AlgId, 28));

        AlgorithmIdentifier sha256AlgId = new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha256, DERNull.INSTANCE);
        addParameters("SHA256WITHRSAANDMGF1", createPSSParams(sha256AlgId, 32));

        AlgorithmIdentifier sha384AlgId = new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha384, DERNull.INSTANCE);
        addParameters("SHA384WITHRSAANDMGF1", createPSSParams(sha384AlgId, 48));

        AlgorithmIdentifier sha512AlgId = new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha512, DERNull.INSTANCE);
        addParameters("SHA512WITHRSAANDMGF1", createPSSParams(sha512AlgId, 64));

        AlgorithmIdentifier sha3_224AlgId = new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha3_224, DERNull.INSTANCE);
        addParameters("SHA3-224WITHRSAANDMGF1", createPSSParams(sha3_224AlgId, 28));

        AlgorithmIdentifier sha3_256AlgId = new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha3_256, DERNull.INSTANCE);
        addParameters("SHA3-256WITHRSAANDMGF1", createPSSParams(sha3_256AlgId, 32));

        AlgorithmIdentifier sha3_384AlgId = new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha3_384, DERNull.INSTANCE);
        addParameters("SHA3-384WITHRSAANDMGF1", createPSSParams(sha3_384AlgId, 48));

        AlgorithmIdentifier sha3_512AlgId = new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha3_512, DERNull.INSTANCE);
        addParameters("SHA3-512WITHRSAANDMGF1", createPSSParams(sha3_512AlgId, 64));

        //
        // digests
        //
        addDigestOid(PKCSObjectIdentifiers.sha224WithRSAEncryption, NISTObjectIdentifiers.id_sha224);
        addDigestOid(PKCSObjectIdentifiers.sha256WithRSAEncryption, NISTObjectIdentifiers.id_sha256);
        addDigestOid(PKCSObjectIdentifiers.sha384WithRSAEncryption, NISTObjectIdentifiers.id_sha384);
        addDigestOid(PKCSObjectIdentifiers.sha512WithRSAEncryption, NISTObjectIdentifiers.id_sha512);
        addDigestOid(PKCSObjectIdentifiers.sha512_224WithRSAEncryption, NISTObjectIdentifiers.id_sha512_224);
        addDigestOid(PKCSObjectIdentifiers.sha512_256WithRSAEncryption, NISTObjectIdentifiers.id_sha512_256);
        addDigestOid(NISTObjectIdentifiers.dsa_with_sha224, NISTObjectIdentifiers.id_sha224);
        addDigestOid(NISTObjectIdentifiers.dsa_with_sha256, NISTObjectIdentifiers.id_sha256);
        addDigestOid(NISTObjectIdentifiers.dsa_with_sha384, NISTObjectIdentifiers.id_sha384);
        addDigestOid(NISTObjectIdentifiers.dsa_with_sha512, NISTObjectIdentifiers.id_sha512);
        addDigestOid(NISTObjectIdentifiers.id_dsa_with_sha3_224, NISTObjectIdentifiers.id_sha3_224);
        addDigestOid(NISTObjectIdentifiers.id_dsa_with_sha3_256, NISTObjectIdentifiers.id_sha3_256);
        addDigestOid(NISTObjectIdentifiers.id_dsa_with_sha3_384, NISTObjectIdentifiers.id_sha3_384);
        addDigestOid(NISTObjectIdentifiers.id_dsa_with_sha3_512, NISTObjectIdentifiers.id_sha3_512);
        addDigestOid(NISTObjectIdentifiers.id_ecdsa_with_sha3_224, NISTObjectIdentifiers.id_sha3_224);
        addDigestOid(NISTObjectIdentifiers.id_ecdsa_with_sha3_256, NISTObjectIdentifiers.id_sha3_256);
        addDigestOid(NISTObjectIdentifiers.id_ecdsa_with_sha3_384, NISTObjectIdentifiers.id_sha3_384);
        addDigestOid(NISTObjectIdentifiers.id_ecdsa_with_sha3_512, NISTObjectIdentifiers.id_sha3_512);
        addDigestOid(NISTObjectIdentifiers.id_rsassa_pkcs1_v1_5_with_sha3_224, NISTObjectIdentifiers.id_sha3_224);
        addDigestOid(NISTObjectIdentifiers.id_rsassa_pkcs1_v1_5_with_sha3_256, NISTObjectIdentifiers.id_sha3_256);
        addDigestOid(NISTObjectIdentifiers.id_rsassa_pkcs1_v1_5_with_sha3_384, NISTObjectIdentifiers.id_sha3_384);
        addDigestOid(NISTObjectIdentifiers.id_rsassa_pkcs1_v1_5_with_sha3_512, NISTObjectIdentifiers.id_sha3_512);

        addDigestOid(PKCSObjectIdentifiers.md2WithRSAEncryption, PKCSObjectIdentifiers.md2);
        addDigestOid(PKCSObjectIdentifiers.md4WithRSAEncryption, PKCSObjectIdentifiers.md4);
        addDigestOid(PKCSObjectIdentifiers.md5WithRSAEncryption, PKCSObjectIdentifiers.md5);
        addDigestOid(PKCSObjectIdentifiers.sha1WithRSAEncryption, OIWObjectIdentifiers.idSHA1);
        addDigestOid(TeleTrusTObjectIdentifiers.rsaSignatureWithripemd128, TeleTrusTObjectIdentifiers.ripemd128);
        addDigestOid(TeleTrusTObjectIdentifiers.rsaSignatureWithripemd160, TeleTrusTObjectIdentifiers.ripemd160);
        addDigestOid(TeleTrusTObjectIdentifiers.rsaSignatureWithripemd256, TeleTrusTObjectIdentifiers.ripemd256);
        addDigestOid(CryptoProObjectIdentifiers.gostR3411_94_with_gostR3410_94, CryptoProObjectIdentifiers.gostR3411);
        addDigestOid(CryptoProObjectIdentifiers.gostR3411_94_with_gostR3410_2001, CryptoProObjectIdentifiers.gostR3411);
        addDigestOid(RosstandartObjectIdentifiers.id_tc26_signwithdigest_gost_3410_12_256, RosstandartObjectIdentifiers.id_tc26_gost_3411_12_256);
        addDigestOid(RosstandartObjectIdentifiers.id_tc26_signwithdigest_gost_3410_12_512, RosstandartObjectIdentifiers.id_tc26_gost_3411_12_512);

        addDigestOid(BCObjectIdentifiers.sphincsPlus_sha2_128s_r3, NISTObjectIdentifiers.id_sha256);
        addDigestOid(BCObjectIdentifiers.sphincsPlus_sha2_128f_r3, NISTObjectIdentifiers.id_sha256);
        addDigestOid(BCObjectIdentifiers.sphincsPlus_shake_128s_r3, NISTObjectIdentifiers.id_shake256);
        addDigestOid(BCObjectIdentifiers.sphincsPlus_shake_128f_r3, NISTObjectIdentifiers.id_shake256);
        addDigestOid(BCObjectIdentifiers.sphincsPlus_sha2_192s_r3, NISTObjectIdentifiers.id_sha256);
        addDigestOid(BCObjectIdentifiers.sphincsPlus_sha2_192f_r3, NISTObjectIdentifiers.id_sha256);
        addDigestOid(BCObjectIdentifiers.sphincsPlus_shake_192s_r3, NISTObjectIdentifiers.id_shake256);
        addDigestOid(BCObjectIdentifiers.sphincsPlus_shake_192f_r3, NISTObjectIdentifiers.id_shake256);
        addDigestOid(BCObjectIdentifiers.sphincsPlus_sha2_256s_r3, NISTObjectIdentifiers.id_sha256);
        addDigestOid(BCObjectIdentifiers.sphincsPlus_sha2_256f_r3, NISTObjectIdentifiers.id_sha256);
        addDigestOid(BCObjectIdentifiers.sphincsPlus_shake_256s_r3, NISTObjectIdentifiers.id_shake256);
        addDigestOid(BCObjectIdentifiers.sphincsPlus_shake_256f_r3, NISTObjectIdentifiers.id_shake256);

        addDigestOid(BCObjectIdentifiers.sphincsPlus_sha2_128s_r3_simple, NISTObjectIdentifiers.id_sha256);
        addDigestOid(BCObjectIdentifiers.sphincsPlus_sha2_128f_r3_simple, NISTObjectIdentifiers.id_sha256);
        addDigestOid(BCObjectIdentifiers.sphincsPlus_shake_128s_r3_simple, NISTObjectIdentifiers.id_shake256);
        addDigestOid(BCObjectIdentifiers.sphincsPlus_shake_128f_r3_simple, NISTObjectIdentifiers.id_shake256);
        addDigestOid(BCObjectIdentifiers.sphincsPlus_sha2_192s_r3_simple, NISTObjectIdentifiers.id_sha256);
        addDigestOid(BCObjectIdentifiers.sphincsPlus_sha2_192f_r3_simple, NISTObjectIdentifiers.id_sha256);
        addDigestOid(BCObjectIdentifiers.sphincsPlus_shake_192s_r3_simple, NISTObjectIdentifiers.id_shake256);
        addDigestOid(BCObjectIdentifiers.sphincsPlus_shake_192f_r3_simple, NISTObjectIdentifiers.id_shake256);
        addDigestOid(BCObjectIdentifiers.sphincsPlus_sha2_256s_r3_simple, NISTObjectIdentifiers.id_sha256);
        addDigestOid(BCObjectIdentifiers.sphincsPlus_sha2_256f_r3_simple, NISTObjectIdentifiers.id_sha256);
        addDigestOid(BCObjectIdentifiers.sphincsPlus_shake_256s_r3_simple, NISTObjectIdentifiers.id_shake256);
        addDigestOid(BCObjectIdentifiers.sphincsPlus_shake_256f_r3_simple, NISTObjectIdentifiers.id_shake256);

        addDigestOid(BCObjectIdentifiers.sphincsPlus_sha2_128s, NISTObjectIdentifiers.id_sha256);
        addDigestOid(BCObjectIdentifiers.sphincsPlus_sha2_128f, NISTObjectIdentifiers.id_sha256);
        addDigestOid(BCObjectIdentifiers.sphincsPlus_shake_128s, NISTObjectIdentifiers.id_shake256);
        addDigestOid(BCObjectIdentifiers.sphincsPlus_shake_128f, NISTObjectIdentifiers.id_shake256);
        addDigestOid(BCObjectIdentifiers.sphincsPlus_sha2_192s, NISTObjectIdentifiers.id_sha256);
        addDigestOid(BCObjectIdentifiers.sphincsPlus_sha2_192f, NISTObjectIdentifiers.id_sha256);
        addDigestOid(BCObjectIdentifiers.sphincsPlus_shake_192s, NISTObjectIdentifiers.id_shake256);
        addDigestOid(BCObjectIdentifiers.sphincsPlus_shake_192f, NISTObjectIdentifiers.id_shake256);
        addDigestOid(BCObjectIdentifiers.sphincsPlus_sha2_256s, NISTObjectIdentifiers.id_sha256);
        addDigestOid(BCObjectIdentifiers.sphincsPlus_sha2_256f, NISTObjectIdentifiers.id_sha256);
        addDigestOid(BCObjectIdentifiers.sphincsPlus_shake_256s, NISTObjectIdentifiers.id_shake256);
        addDigestOid(BCObjectIdentifiers.sphincsPlus_shake_256f, NISTObjectIdentifiers.id_shake256);

//        addDigestOid(GMObjectIdentifiers.sm2sign_with_rmd160, TeleTrusTObjectIdentifiers.ripemd160);
//        addDigestOid(GMObjectIdentifiers.sm2sign_with_sha1, OIWObjectIdentifiers.idSHA1);
//        addDigestOid(GMObjectIdentifiers.sm2sign_with_sha224, NISTObjectIdentifiers.id_sha224);
        addDigestOid(GMObjectIdentifiers.sm2sign_with_sha256, NISTObjectIdentifiers.id_sha256);
//        addDigestOid(GMObjectIdentifiers.sm2sign_with_sha384, NISTObjectIdentifiers.id_sha384);
//        addDigestOid(GMObjectIdentifiers.sm2sign_with_sha512, NISTObjectIdentifiers.id_sha512);
        addDigestOid(GMObjectIdentifiers.sm2sign_with_sm3, GMObjectIdentifiers.sm3);

        addDigestOid(X509ObjectIdentifiers.id_rsassa_pss_shake128, NISTObjectIdentifiers.id_shake128);
        addDigestOid(X509ObjectIdentifiers.id_rsassa_pss_shake256, NISTObjectIdentifiers.id_shake256);
        addDigestOid(X509ObjectIdentifiers.id_ecdsa_with_shake128, NISTObjectIdentifiers.id_shake128);
        addDigestOid(X509ObjectIdentifiers.id_ecdsa_with_shake256, NISTObjectIdentifiers.id_shake256);

        addDigestOid(NISTObjectIdentifiers.id_ml_dsa_44, NISTObjectIdentifiers.id_shake256);
        addDigestOid(NISTObjectIdentifiers.id_ml_dsa_65, NISTObjectIdentifiers.id_shake256);
        addDigestOid(NISTObjectIdentifiers.id_ml_dsa_87, NISTObjectIdentifiers.id_shake256);
        addDigestOid(NISTObjectIdentifiers.id_hash_ml_dsa_44_with_sha512, NISTObjectIdentifiers.id_sha512);
        addDigestOid(NISTObjectIdentifiers.id_hash_ml_dsa_65_with_sha512, NISTObjectIdentifiers.id_sha512);
        addDigestOid(NISTObjectIdentifiers.id_hash_ml_dsa_87_with_sha512, NISTObjectIdentifiers.id_sha512);

        addDigestOid(NISTObjectIdentifiers.id_slh_dsa_sha2_128s, NISTObjectIdentifiers.id_sha256);
        addDigestOid(NISTObjectIdentifiers.id_slh_dsa_sha2_128f, NISTObjectIdentifiers.id_sha256);
        addDigestOid(NISTObjectIdentifiers.id_slh_dsa_sha2_192s, NISTObjectIdentifiers.id_sha512);
        addDigestOid(NISTObjectIdentifiers.id_slh_dsa_sha2_192f, NISTObjectIdentifiers.id_sha512);
        addDigestOid(NISTObjectIdentifiers.id_slh_dsa_sha2_256s, NISTObjectIdentifiers.id_sha512);
        addDigestOid(NISTObjectIdentifiers.id_slh_dsa_sha2_256f, NISTObjectIdentifiers.id_sha512);
        addDigestOid(NISTObjectIdentifiers.id_slh_dsa_shake_128s, NISTObjectIdentifiers.id_shake128);
        addDigestOid(NISTObjectIdentifiers.id_slh_dsa_shake_128f, NISTObjectIdentifiers.id_shake128);
        addDigestOid(NISTObjectIdentifiers.id_slh_dsa_shake_192s, NISTObjectIdentifiers.id_shake256);
        addDigestOid(NISTObjectIdentifiers.id_slh_dsa_shake_192f, NISTObjectIdentifiers.id_shake256);
        addDigestOid(NISTObjectIdentifiers.id_slh_dsa_shake_256s, NISTObjectIdentifiers.id_shake256);
        addDigestOid(NISTObjectIdentifiers.id_slh_dsa_shake_256f, NISTObjectIdentifiers.id_shake256);
        addDigestOid(NISTObjectIdentifiers.id_hash_slh_dsa_sha2_128f_with_sha256, NISTObjectIdentifiers.id_sha256);
        addDigestOid(NISTObjectIdentifiers.id_hash_slh_dsa_sha2_128s_with_sha256, NISTObjectIdentifiers.id_sha256);
        addDigestOid(NISTObjectIdentifiers.id_hash_slh_dsa_sha2_192s_with_sha512, NISTObjectIdentifiers.id_sha512);
        addDigestOid(NISTObjectIdentifiers.id_hash_slh_dsa_sha2_192f_with_sha512, NISTObjectIdentifiers.id_sha512);
        addDigestOid(NISTObjectIdentifiers.id_hash_slh_dsa_sha2_256s_with_sha512, NISTObjectIdentifiers.id_sha512);
        addDigestOid(NISTObjectIdentifiers.id_hash_slh_dsa_sha2_256f_with_sha512, NISTObjectIdentifiers.id_sha512);
        addDigestOid(NISTObjectIdentifiers.id_hash_slh_dsa_shake_128s_with_shake128, NISTObjectIdentifiers.id_shake128);
        addDigestOid(NISTObjectIdentifiers.id_hash_slh_dsa_shake_128f_with_shake128, NISTObjectIdentifiers.id_shake128);
        addDigestOid(NISTObjectIdentifiers.id_hash_slh_dsa_shake_192s_with_shake256, NISTObjectIdentifiers.id_shake256);
        addDigestOid(NISTObjectIdentifiers.id_hash_slh_dsa_shake_192f_with_shake256, NISTObjectIdentifiers.id_shake256);
        addDigestOid(NISTObjectIdentifiers.id_hash_slh_dsa_shake_256s_with_shake256, NISTObjectIdentifiers.id_shake256);
        addDigestOid(NISTObjectIdentifiers.id_hash_slh_dsa_shake_256f_with_shake256, NISTObjectIdentifiers.id_shake256);
    }

    public AlgorithmIdentifier find(String sigAlgName)
    {
        String algorithmName = Strings.toUpperCase(sigAlgName);
        ASN1ObjectIdentifier sigOID = (ASN1ObjectIdentifier)algorithms.get(algorithmName);
        if (sigOID == null)
        {
            throw new IllegalArgumentException("Unknown signature type requested: " + sigAlgName);
        }

        if (noParams.contains(sigOID))
        {
            return new AlgorithmIdentifier(sigOID);
        }

        ASN1Encodable sigAlgParams = (ASN1Encodable)params.get(algorithmName);
        if (sigAlgParams == null)
        {
            sigAlgParams = DERNull.INSTANCE;
        }

        return new AlgorithmIdentifier(sigOID, sigAlgParams);
    }
}
