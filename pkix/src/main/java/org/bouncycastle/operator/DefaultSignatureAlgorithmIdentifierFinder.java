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
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.RSASSAPSSparams;
import org.bouncycastle.asn1.rosstandart.RosstandartObjectIdentifiers;
import org.bouncycastle.asn1.teletrust.TeleTrusTObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
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

    private static final ASN1ObjectIdentifier ENCRYPTION_RSA = PKCSObjectIdentifiers.rsaEncryption;
    private static final ASN1ObjectIdentifier ENCRYPTION_DSA = X9ObjectIdentifiers.id_dsa_with_sha1;
    private static final ASN1ObjectIdentifier ENCRYPTION_ECDSA = X9ObjectIdentifiers.ecdsa_with_SHA1;
    private static final ASN1ObjectIdentifier ENCRYPTION_RSA_PSS = PKCSObjectIdentifiers.id_RSASSA_PSS;
    private static final ASN1ObjectIdentifier ENCRYPTION_GOST3410 = CryptoProObjectIdentifiers.gostR3410_94;
    private static final ASN1ObjectIdentifier ENCRYPTION_ECGOST3410 = CryptoProObjectIdentifiers.gostR3410_2001;
    private static final ASN1ObjectIdentifier ENCRYPTION_ECGOST3410_2012_256 = RosstandartObjectIdentifiers.id_tc26_gost_3410_12_256;
    private static final ASN1ObjectIdentifier ENCRYPTION_ECGOST3410_2012_512 = RosstandartObjectIdentifiers.id_tc26_gost_3410_12_512;

    static
    {
        algorithms.put("MD2WITHRSAENCRYPTION", PKCSObjectIdentifiers.md2WithRSAEncryption);
        algorithms.put("MD2WITHRSA", PKCSObjectIdentifiers.md2WithRSAEncryption);
        algorithms.put("MD5WITHRSAENCRYPTION", PKCSObjectIdentifiers.md5WithRSAEncryption);
        algorithms.put("MD5WITHRSA", PKCSObjectIdentifiers.md5WithRSAEncryption);
        algorithms.put("SHA1WITHRSAENCRYPTION", PKCSObjectIdentifiers.sha1WithRSAEncryption);
        algorithms.put("SHA1WITHRSA", PKCSObjectIdentifiers.sha1WithRSAEncryption);
        algorithms.put("SHA224WITHRSAENCRYPTION", PKCSObjectIdentifiers.sha224WithRSAEncryption);
        algorithms.put("SHA224WITHRSA", PKCSObjectIdentifiers.sha224WithRSAEncryption);
        algorithms.put("SHA256WITHRSAENCRYPTION", PKCSObjectIdentifiers.sha256WithRSAEncryption);
        algorithms.put("SHA256WITHRSA", PKCSObjectIdentifiers.sha256WithRSAEncryption);
        algorithms.put("SHA384WITHRSAENCRYPTION", PKCSObjectIdentifiers.sha384WithRSAEncryption);
        algorithms.put("SHA384WITHRSA", PKCSObjectIdentifiers.sha384WithRSAEncryption);
        algorithms.put("SHA512WITHRSAENCRYPTION", PKCSObjectIdentifiers.sha512WithRSAEncryption);
        algorithms.put("SHA512WITHRSA", PKCSObjectIdentifiers.sha512WithRSAEncryption);
        algorithms.put("SHA1WITHRSAANDMGF1", PKCSObjectIdentifiers.id_RSASSA_PSS);
        algorithms.put("SHA224WITHRSAANDMGF1", PKCSObjectIdentifiers.id_RSASSA_PSS);
        algorithms.put("SHA256WITHRSAANDMGF1", PKCSObjectIdentifiers.id_RSASSA_PSS);
        algorithms.put("SHA384WITHRSAANDMGF1", PKCSObjectIdentifiers.id_RSASSA_PSS);
        algorithms.put("SHA512WITHRSAANDMGF1", PKCSObjectIdentifiers.id_RSASSA_PSS);
        algorithms.put("SHA3-224WITHRSAANDMGF1", PKCSObjectIdentifiers.id_RSASSA_PSS);
        algorithms.put("SHA3-256WITHRSAANDMGF1", PKCSObjectIdentifiers.id_RSASSA_PSS);
        algorithms.put("SHA3-384WITHRSAANDMGF1", PKCSObjectIdentifiers.id_RSASSA_PSS);
        algorithms.put("SHA3-512WITHRSAANDMGF1", PKCSObjectIdentifiers.id_RSASSA_PSS);
        algorithms.put("RIPEMD160WITHRSAENCRYPTION", TeleTrusTObjectIdentifiers.rsaSignatureWithripemd160);
        algorithms.put("RIPEMD160WITHRSA", TeleTrusTObjectIdentifiers.rsaSignatureWithripemd160);
        algorithms.put("RIPEMD128WITHRSAENCRYPTION", TeleTrusTObjectIdentifiers.rsaSignatureWithripemd128);
        algorithms.put("RIPEMD128WITHRSA", TeleTrusTObjectIdentifiers.rsaSignatureWithripemd128);
        algorithms.put("RIPEMD256WITHRSAENCRYPTION", TeleTrusTObjectIdentifiers.rsaSignatureWithripemd256);
        algorithms.put("RIPEMD256WITHRSA", TeleTrusTObjectIdentifiers.rsaSignatureWithripemd256);
        algorithms.put("SHA1WITHDSA", X9ObjectIdentifiers.id_dsa_with_sha1);
        algorithms.put("DSAWITHSHA1", X9ObjectIdentifiers.id_dsa_with_sha1);
        algorithms.put("SHA224WITHDSA", NISTObjectIdentifiers.dsa_with_sha224);
        algorithms.put("SHA256WITHDSA", NISTObjectIdentifiers.dsa_with_sha256);
        algorithms.put("SHA384WITHDSA", NISTObjectIdentifiers.dsa_with_sha384);
        algorithms.put("SHA512WITHDSA", NISTObjectIdentifiers.dsa_with_sha512);
        algorithms.put("SHA3-224WITHDSA", NISTObjectIdentifiers.id_dsa_with_sha3_224);
        algorithms.put("SHA3-256WITHDSA", NISTObjectIdentifiers.id_dsa_with_sha3_256);
        algorithms.put("SHA3-384WITHDSA", NISTObjectIdentifiers.id_dsa_with_sha3_384);
        algorithms.put("SHA3-512WITHDSA", NISTObjectIdentifiers.id_dsa_with_sha3_512);
        algorithms.put("SHA3-224WITHECDSA", NISTObjectIdentifiers.id_ecdsa_with_sha3_224);
        algorithms.put("SHA3-256WITHECDSA", NISTObjectIdentifiers.id_ecdsa_with_sha3_256);
        algorithms.put("SHA3-384WITHECDSA", NISTObjectIdentifiers.id_ecdsa_with_sha3_384);
        algorithms.put("SHA3-512WITHECDSA", NISTObjectIdentifiers.id_ecdsa_with_sha3_512);
        algorithms.put("SHA3-224WITHRSA", NISTObjectIdentifiers.id_rsassa_pkcs1_v1_5_with_sha3_224);
        algorithms.put("SHA3-256WITHRSA", NISTObjectIdentifiers.id_rsassa_pkcs1_v1_5_with_sha3_256);
        algorithms.put("SHA3-384WITHRSA", NISTObjectIdentifiers.id_rsassa_pkcs1_v1_5_with_sha3_384);
        algorithms.put("SHA3-512WITHRSA", NISTObjectIdentifiers.id_rsassa_pkcs1_v1_5_with_sha3_512);
        algorithms.put("SHA3-224WITHRSAENCRYPTION", NISTObjectIdentifiers.id_rsassa_pkcs1_v1_5_with_sha3_224);
        algorithms.put("SHA3-256WITHRSAENCRYPTION", NISTObjectIdentifiers.id_rsassa_pkcs1_v1_5_with_sha3_256);
        algorithms.put("SHA3-384WITHRSAENCRYPTION", NISTObjectIdentifiers.id_rsassa_pkcs1_v1_5_with_sha3_384);
        algorithms.put("SHA3-512WITHRSAENCRYPTION", NISTObjectIdentifiers.id_rsassa_pkcs1_v1_5_with_sha3_512);
        algorithms.put("SHA1WITHECDSA", X9ObjectIdentifiers.ecdsa_with_SHA1);
        algorithms.put("ECDSAWITHSHA1", X9ObjectIdentifiers.ecdsa_with_SHA1);
        algorithms.put("SHA224WITHECDSA", X9ObjectIdentifiers.ecdsa_with_SHA224);
        algorithms.put("SHA256WITHECDSA", X9ObjectIdentifiers.ecdsa_with_SHA256);
        algorithms.put("SHA384WITHECDSA", X9ObjectIdentifiers.ecdsa_with_SHA384);
        algorithms.put("SHA512WITHECDSA", X9ObjectIdentifiers.ecdsa_with_SHA512);
        algorithms.put("GOST3411WITHGOST3410", CryptoProObjectIdentifiers.gostR3411_94_with_gostR3410_94);
        algorithms.put("GOST3411WITHGOST3410-94", CryptoProObjectIdentifiers.gostR3411_94_with_gostR3410_94);
        algorithms.put("GOST3411WITHECGOST3410", CryptoProObjectIdentifiers.gostR3411_94_with_gostR3410_2001);
        algorithms.put("GOST3411WITHECGOST3410-2001", CryptoProObjectIdentifiers.gostR3411_94_with_gostR3410_2001);
        algorithms.put("GOST3411WITHGOST3410-2001", CryptoProObjectIdentifiers.gostR3411_94_with_gostR3410_2001);
        algorithms.put("GOST3411WITHECGOST3410-2012-256", RosstandartObjectIdentifiers.id_tc26_signwithdigest_gost_3410_12_256);
        algorithms.put("GOST3411WITHECGOST3410-2012-512", RosstandartObjectIdentifiers.id_tc26_signwithdigest_gost_3410_12_512);
        algorithms.put("GOST3411WITHGOST3410-2012-256", RosstandartObjectIdentifiers.id_tc26_signwithdigest_gost_3410_12_256);
        algorithms.put("GOST3411WITHGOST3410-2012-512", RosstandartObjectIdentifiers.id_tc26_signwithdigest_gost_3410_12_512);
        algorithms.put("GOST3411-2012-256WITHECGOST3410-2012-256", RosstandartObjectIdentifiers.id_tc26_signwithdigest_gost_3410_12_256);
        algorithms.put("GOST3411-2012-512WITHECGOST3410-2012-512", RosstandartObjectIdentifiers.id_tc26_signwithdigest_gost_3410_12_512);
        algorithms.put("GOST3411-2012-256WITHGOST3410-2012-256", RosstandartObjectIdentifiers.id_tc26_signwithdigest_gost_3410_12_256);
        algorithms.put("GOST3411-2012-512WITHGOST3410-2012-512", RosstandartObjectIdentifiers.id_tc26_signwithdigest_gost_3410_12_512);
        algorithms.put("SHA1WITHPLAIN-ECDSA", BSIObjectIdentifiers.ecdsa_plain_SHA1);
        algorithms.put("SHA224WITHPLAIN-ECDSA", BSIObjectIdentifiers.ecdsa_plain_SHA224);
        algorithms.put("SHA256WITHPLAIN-ECDSA", BSIObjectIdentifiers.ecdsa_plain_SHA256);
        algorithms.put("SHA384WITHPLAIN-ECDSA", BSIObjectIdentifiers.ecdsa_plain_SHA384);
        algorithms.put("SHA512WITHPLAIN-ECDSA", BSIObjectIdentifiers.ecdsa_plain_SHA512);
        algorithms.put("RIPEMD160WITHPLAIN-ECDSA", BSIObjectIdentifiers.ecdsa_plain_RIPEMD160);
        algorithms.put("SHA1WITHCVC-ECDSA", EACObjectIdentifiers.id_TA_ECDSA_SHA_1);
        algorithms.put("SHA224WITHCVC-ECDSA", EACObjectIdentifiers.id_TA_ECDSA_SHA_224);
        algorithms.put("SHA256WITHCVC-ECDSA", EACObjectIdentifiers.id_TA_ECDSA_SHA_256);
        algorithms.put("SHA384WITHCVC-ECDSA", EACObjectIdentifiers.id_TA_ECDSA_SHA_384);
        algorithms.put("SHA512WITHCVC-ECDSA", EACObjectIdentifiers.id_TA_ECDSA_SHA_512);
        algorithms.put("SHA3-512WITHSPHINCS256", BCObjectIdentifiers.sphincs256_with_SHA3_512);
        algorithms.put("SHA512WITHSPHINCS256", BCObjectIdentifiers.sphincs256_with_SHA512);

        algorithms.put("ED25519", EdECObjectIdentifiers.id_Ed25519);
        algorithms.put("ED448", EdECObjectIdentifiers.id_Ed448);

//        algorithms.put("RIPEMD160WITHSM2", GMObjectIdentifiers.sm2sign_with_rmd160);
//        algorithms.put("SHA1WITHSM2", GMObjectIdentifiers.sm2sign_with_sha1);
//        algorithms.put("SHA224WITHSM2", GMObjectIdentifiers.sm2sign_with_sha224);
        algorithms.put("SHA256WITHSM2", GMObjectIdentifiers.sm2sign_with_sha256);
//        algorithms.put("SHA384WITHSM2", GMObjectIdentifiers.sm2sign_with_sha384);
//        algorithms.put("SHA512WITHSM2", GMObjectIdentifiers.sm2sign_with_sha512);
        algorithms.put("SM3WITHSM2", GMObjectIdentifiers.sm2sign_with_sm3);

        algorithms.put("SHA256WITHXMSS", BCObjectIdentifiers.xmss_SHA256ph);
        algorithms.put("SHA512WITHXMSS", BCObjectIdentifiers.xmss_SHA512ph);
        algorithms.put("SHAKE128WITHXMSS", BCObjectIdentifiers.xmss_SHAKE128ph);
        algorithms.put("SHAKE256WITHXMSS", BCObjectIdentifiers.xmss_SHAKE256ph);

        algorithms.put("SHA256WITHXMSSMT", BCObjectIdentifiers.xmss_mt_SHA256ph);
        algorithms.put("SHA512WITHXMSSMT", BCObjectIdentifiers.xmss_mt_SHA512ph);
        algorithms.put("SHAKE128WITHXMSSMT", BCObjectIdentifiers.xmss_mt_SHAKE128ph);
        algorithms.put("SHAKE256WITHXMSSMT", BCObjectIdentifiers.xmss_mt_SHAKE256ph);

        algorithms.put("SHA256WITHXMSS-SHA256", BCObjectIdentifiers.xmss_SHA256ph);
        algorithms.put("SHA512WITHXMSS-SHA512", BCObjectIdentifiers.xmss_SHA512ph);
        algorithms.put("SHAKE128WITHXMSS-SHAKE128", BCObjectIdentifiers.xmss_SHAKE128ph);
        algorithms.put("SHAKE256WITHXMSS-SHAKE256", BCObjectIdentifiers.xmss_SHAKE256ph);

        algorithms.put("SHA256WITHXMSSMT-SHA256", BCObjectIdentifiers.xmss_mt_SHA256ph);
        algorithms.put("SHA512WITHXMSSMT-SHA512", BCObjectIdentifiers.xmss_mt_SHA512ph);
        algorithms.put("SHAKE128WITHXMSSMT-SHAKE128", BCObjectIdentifiers.xmss_mt_SHAKE128ph);
        algorithms.put("SHAKE256WITHXMSSMT-SHAKE256", BCObjectIdentifiers.xmss_mt_SHAKE256ph);

        algorithms.put("LMS", PKCSObjectIdentifiers.id_alg_hss_lms_hashsig);

        algorithms.put("XMSS", IsaraObjectIdentifiers.id_alg_xmss);
        algorithms.put("XMSS-SHA256", BCObjectIdentifiers.xmss_SHA256);
        algorithms.put("XMSS-SHA512", BCObjectIdentifiers.xmss_SHA512);
        algorithms.put("XMSS-SHAKE128", BCObjectIdentifiers.xmss_SHAKE128);
        algorithms.put("XMSS-SHAKE256", BCObjectIdentifiers.xmss_SHAKE256);

        algorithms.put("XMSSMT", IsaraObjectIdentifiers.id_alg_xmssmt);
        algorithms.put("XMSSMT-SHA256", BCObjectIdentifiers.xmss_mt_SHA256);
        algorithms.put("XMSSMT-SHA512", BCObjectIdentifiers.xmss_mt_SHA512);
        algorithms.put("XMSSMT-SHAKE128", BCObjectIdentifiers.xmss_mt_SHAKE128);
        algorithms.put("XMSSMT-SHAKE256", BCObjectIdentifiers.xmss_mt_SHAKE256);

        algorithms.put("QTESLA-P-I", BCObjectIdentifiers.qTESLA_p_I);
        algorithms.put("QTESLA-P-III", BCObjectIdentifiers.qTESLA_p_III);

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

        //
        // PKCS 1.5 encrypted  algorithms
        //
        pkcs15RsaEncryption.add(PKCSObjectIdentifiers.sha1WithRSAEncryption);
        pkcs15RsaEncryption.add(PKCSObjectIdentifiers.sha224WithRSAEncryption);
        pkcs15RsaEncryption.add(PKCSObjectIdentifiers.sha256WithRSAEncryption);
        pkcs15RsaEncryption.add(PKCSObjectIdentifiers.sha384WithRSAEncryption);
        pkcs15RsaEncryption.add(PKCSObjectIdentifiers.sha512WithRSAEncryption);
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
        params.put("SHA1WITHRSAANDMGF1", createPSSParams(sha1AlgId, 20));

        AlgorithmIdentifier sha224AlgId = new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha224, DERNull.INSTANCE);
        params.put("SHA224WITHRSAANDMGF1", createPSSParams(sha224AlgId, 28));

        AlgorithmIdentifier sha256AlgId = new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha256, DERNull.INSTANCE);
        params.put("SHA256WITHRSAANDMGF1", createPSSParams(sha256AlgId, 32));

        AlgorithmIdentifier sha384AlgId = new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha384, DERNull.INSTANCE);
        params.put("SHA384WITHRSAANDMGF1", createPSSParams(sha384AlgId, 48));

        AlgorithmIdentifier sha512AlgId = new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha512, DERNull.INSTANCE);
        params.put("SHA512WITHRSAANDMGF1", createPSSParams(sha512AlgId, 64));

        AlgorithmIdentifier sha3_224AlgId = new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha3_224, DERNull.INSTANCE);
        params.put("SHA3-224WITHRSAANDMGF1", createPSSParams(sha3_224AlgId, 28));

        AlgorithmIdentifier sha3_256AlgId = new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha3_256, DERNull.INSTANCE);
        params.put("SHA3-256WITHRSAANDMGF1", createPSSParams(sha3_256AlgId, 32));

        AlgorithmIdentifier sha3_384AlgId = new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha3_384, DERNull.INSTANCE);
        params.put("SHA3-384WITHRSAANDMGF1", createPSSParams(sha3_384AlgId, 48));

        AlgorithmIdentifier sha3_512AlgId = new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha3_512, DERNull.INSTANCE);
        params.put("SHA3-512WITHRSAANDMGF1", createPSSParams(sha3_512AlgId, 64));

        //
        // digests
        //
        digestOids.put(PKCSObjectIdentifiers.sha224WithRSAEncryption, NISTObjectIdentifiers.id_sha224);
        digestOids.put(PKCSObjectIdentifiers.sha256WithRSAEncryption, NISTObjectIdentifiers.id_sha256);
        digestOids.put(PKCSObjectIdentifiers.sha384WithRSAEncryption, NISTObjectIdentifiers.id_sha384);
        digestOids.put(PKCSObjectIdentifiers.sha512WithRSAEncryption, NISTObjectIdentifiers.id_sha512);
        digestOids.put(NISTObjectIdentifiers.dsa_with_sha224, NISTObjectIdentifiers.id_sha224);
        digestOids.put(NISTObjectIdentifiers.dsa_with_sha256, NISTObjectIdentifiers.id_sha256);
        digestOids.put(NISTObjectIdentifiers.dsa_with_sha384, NISTObjectIdentifiers.id_sha384);
        digestOids.put(NISTObjectIdentifiers.dsa_with_sha512, NISTObjectIdentifiers.id_sha512);
        digestOids.put(NISTObjectIdentifiers.id_dsa_with_sha3_224, NISTObjectIdentifiers.id_sha3_224);
        digestOids.put(NISTObjectIdentifiers.id_dsa_with_sha3_256, NISTObjectIdentifiers.id_sha3_256);
        digestOids.put(NISTObjectIdentifiers.id_dsa_with_sha3_384, NISTObjectIdentifiers.id_sha3_384);
        digestOids.put(NISTObjectIdentifiers.id_dsa_with_sha3_512, NISTObjectIdentifiers.id_sha3_512);
        digestOids.put(NISTObjectIdentifiers.id_ecdsa_with_sha3_224, NISTObjectIdentifiers.id_sha3_224);
        digestOids.put(NISTObjectIdentifiers.id_ecdsa_with_sha3_256, NISTObjectIdentifiers.id_sha3_256);
        digestOids.put(NISTObjectIdentifiers.id_ecdsa_with_sha3_384, NISTObjectIdentifiers.id_sha3_384);
        digestOids.put(NISTObjectIdentifiers.id_ecdsa_with_sha3_512, NISTObjectIdentifiers.id_sha3_512);
        digestOids.put(NISTObjectIdentifiers.id_rsassa_pkcs1_v1_5_with_sha3_224, NISTObjectIdentifiers.id_sha3_224);
        digestOids.put(NISTObjectIdentifiers.id_rsassa_pkcs1_v1_5_with_sha3_256, NISTObjectIdentifiers.id_sha3_256);
        digestOids.put(NISTObjectIdentifiers.id_rsassa_pkcs1_v1_5_with_sha3_384, NISTObjectIdentifiers.id_sha3_384);
        digestOids.put(NISTObjectIdentifiers.id_rsassa_pkcs1_v1_5_with_sha3_512, NISTObjectIdentifiers.id_sha3_512);

        digestOids.put(PKCSObjectIdentifiers.md2WithRSAEncryption, PKCSObjectIdentifiers.md2);
        digestOids.put(PKCSObjectIdentifiers.md4WithRSAEncryption, PKCSObjectIdentifiers.md4);
        digestOids.put(PKCSObjectIdentifiers.md5WithRSAEncryption, PKCSObjectIdentifiers.md5);
        digestOids.put(PKCSObjectIdentifiers.sha1WithRSAEncryption, OIWObjectIdentifiers.idSHA1);
        digestOids.put(TeleTrusTObjectIdentifiers.rsaSignatureWithripemd128, TeleTrusTObjectIdentifiers.ripemd128);
        digestOids.put(TeleTrusTObjectIdentifiers.rsaSignatureWithripemd160, TeleTrusTObjectIdentifiers.ripemd160);
        digestOids.put(TeleTrusTObjectIdentifiers.rsaSignatureWithripemd256, TeleTrusTObjectIdentifiers.ripemd256);
        digestOids.put(CryptoProObjectIdentifiers.gostR3411_94_with_gostR3410_94, CryptoProObjectIdentifiers.gostR3411);
        digestOids.put(CryptoProObjectIdentifiers.gostR3411_94_with_gostR3410_2001, CryptoProObjectIdentifiers.gostR3411);
        digestOids.put(RosstandartObjectIdentifiers.id_tc26_signwithdigest_gost_3410_12_256, RosstandartObjectIdentifiers.id_tc26_gost_3411_12_256);
        digestOids.put(RosstandartObjectIdentifiers.id_tc26_signwithdigest_gost_3410_12_512, RosstandartObjectIdentifiers.id_tc26_gost_3411_12_512);

//        digestOids.put(GMObjectIdentifiers.sm2sign_with_rmd160, TeleTrusTObjectIdentifiers.ripemd160);
//        digestOids.put(GMObjectIdentifiers.sm2sign_with_sha1, OIWObjectIdentifiers.idSHA1);
//        digestOids.put(GMObjectIdentifiers.sm2sign_with_sha224, NISTObjectIdentifiers.id_sha224);
        digestOids.put(GMObjectIdentifiers.sm2sign_with_sha256, NISTObjectIdentifiers.id_sha256);
//        digestOids.put(GMObjectIdentifiers.sm2sign_with_sha384, NISTObjectIdentifiers.id_sha384);
//        digestOids.put(GMObjectIdentifiers.sm2sign_with_sha512, NISTObjectIdentifiers.id_sha512);
        digestOids.put(GMObjectIdentifiers.sm2sign_with_sm3, GMObjectIdentifiers.sm3);
    }

    private static AlgorithmIdentifier generate(String signatureAlgorithm)
    {
        AlgorithmIdentifier sigAlgId;

        String algorithmName = Strings.toUpperCase(signatureAlgorithm);
        ASN1ObjectIdentifier sigOID = (ASN1ObjectIdentifier)algorithms.get(algorithmName);
        if (sigOID == null)
        {
            throw new IllegalArgumentException("Unknown signature type requested: " + algorithmName);
        }

        if (noParams.contains(sigOID))
        {
            sigAlgId = new AlgorithmIdentifier(sigOID);
        }
        else if (params.containsKey(algorithmName))
        {
            sigAlgId = new AlgorithmIdentifier(sigOID, (ASN1Encodable)params.get(algorithmName));
        }
        else
        {
            sigAlgId = new AlgorithmIdentifier(sigOID, DERNull.INSTANCE);
        }

        return sigAlgId;
    }

    private static RSASSAPSSparams createPSSParams(AlgorithmIdentifier hashAlgId, int saltSize)
    {
        return new RSASSAPSSparams(
            hashAlgId,
            new AlgorithmIdentifier(PKCSObjectIdentifiers.id_mgf1, hashAlgId),
            new ASN1Integer(saltSize),
            new ASN1Integer(1));
    }

    public AlgorithmIdentifier find(String sigAlgName)
    {
        return generate(sigAlgName);
    }
}