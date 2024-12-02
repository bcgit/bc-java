package org.bouncycastle.cms;

import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.bc.BCObjectIdentifiers;
import org.bouncycastle.asn1.bsi.BSIObjectIdentifiers;
import org.bouncycastle.asn1.cryptopro.CryptoProObjectIdentifiers;
import org.bouncycastle.asn1.eac.EACObjectIdentifiers;
import org.bouncycastle.asn1.edec.EdECObjectIdentifiers;
import org.bouncycastle.asn1.gm.GMObjectIdentifiers;
import org.bouncycastle.asn1.misc.MiscObjectIdentifiers;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.rosstandart.RosstandartObjectIdentifiers;
import org.bouncycastle.asn1.teletrust.TeleTrusTObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.X509ObjectIdentifiers;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;

public class DefaultCMSSignatureAlgorithmNameGenerator
    implements CMSSignatureAlgorithmNameGenerator
{
    private final Map encryptionAlgs = new HashMap();
    private final Map     digestAlgs = new HashMap();
    private final Map     simpleAlgs = new HashMap();

    private void addEntries(ASN1ObjectIdentifier alias, String digest, String encryption)
    {
        addDigestAlg(alias, digest);
        addEncryptionAlg(alias, encryption);
    }

    private void addSimpleAlg(ASN1ObjectIdentifier alias, String algorithmName)
    {
        if (simpleAlgs.containsKey(alias))
        {
            throw new IllegalStateException("object identifier already present in addSimpleAlg");
        }
        
        simpleAlgs.put(alias, algorithmName);
    }

    private void addDigestAlg(ASN1ObjectIdentifier alias, String algorithmName)
    {
        if (digestAlgs.containsKey(alias))
        {
            throw new IllegalStateException("object identifier already present in addDigestAlg");
        }

        digestAlgs.put(alias, algorithmName);
    }

    private void addEncryptionAlg(ASN1ObjectIdentifier alias, String algorithmName)
    {
        if (encryptionAlgs.containsKey(alias))
        {
            throw new IllegalStateException("object identifier already present in addEncryptionAlg");
        }
        
        encryptionAlgs.put(alias, algorithmName);
    }
    
    public DefaultCMSSignatureAlgorithmNameGenerator()
    {
        addEntries(NISTObjectIdentifiers.dsa_with_sha224, "SHA224", "DSA");
        addEntries(NISTObjectIdentifiers.dsa_with_sha256, "SHA256", "DSA");
        addEntries(NISTObjectIdentifiers.dsa_with_sha384, "SHA384", "DSA");
        addEntries(NISTObjectIdentifiers.dsa_with_sha512, "SHA512", "DSA");
        addEntries(NISTObjectIdentifiers.id_dsa_with_sha3_224, "SHA3-224", "DSA");
        addEntries(NISTObjectIdentifiers.id_dsa_with_sha3_256, "SHA3-256", "DSA");
        addEntries(NISTObjectIdentifiers.id_dsa_with_sha3_384, "SHA3-384", "DSA");
        addEntries(NISTObjectIdentifiers.id_dsa_with_sha3_512, "SHA3-512", "DSA");
        addEntries(NISTObjectIdentifiers.id_ecdsa_with_sha3_224, "SHA3-224", "ECDSA");
        addEntries(NISTObjectIdentifiers.id_ecdsa_with_sha3_256, "SHA3-256", "ECDSA");
        addEntries(NISTObjectIdentifiers.id_ecdsa_with_sha3_384, "SHA3-384", "ECDSA");
        addEntries(NISTObjectIdentifiers.id_ecdsa_with_sha3_512, "SHA3-512", "ECDSA");
        addEntries(OIWObjectIdentifiers.dsaWithSHA1, "SHA1", "DSA");
        addEntries(OIWObjectIdentifiers.md4WithRSA, "MD4", "RSA");
        addEntries(OIWObjectIdentifiers.md4WithRSAEncryption, "MD4", "RSA");
        addEntries(OIWObjectIdentifiers.md5WithRSA, "MD5", "RSA");
        addEntries(OIWObjectIdentifiers.sha1WithRSA, "SHA1", "RSA");
        addEntries(PKCSObjectIdentifiers.md2WithRSAEncryption, "MD2", "RSA");
        addEntries(PKCSObjectIdentifiers.md4WithRSAEncryption, "MD4", "RSA");
        addEntries(PKCSObjectIdentifiers.md5WithRSAEncryption, "MD5", "RSA");
        addEntries(PKCSObjectIdentifiers.sha1WithRSAEncryption, "SHA1", "RSA");
        addEntries(PKCSObjectIdentifiers.sha224WithRSAEncryption, "SHA224", "RSA");
        addEntries(PKCSObjectIdentifiers.sha256WithRSAEncryption, "SHA256", "RSA");
        addEntries(PKCSObjectIdentifiers.sha384WithRSAEncryption, "SHA384", "RSA");
        addEntries(PKCSObjectIdentifiers.sha512WithRSAEncryption, "SHA512", "RSA");
        addEntries(PKCSObjectIdentifiers.sha512_224WithRSAEncryption, "SHA512(224)", "RSA");
        addEntries(PKCSObjectIdentifiers.sha512_256WithRSAEncryption, "SHA512(256)", "RSA");
        addEntries(NISTObjectIdentifiers.id_rsassa_pkcs1_v1_5_with_sha3_224, "SHA3-224", "RSA");
        addEntries(NISTObjectIdentifiers.id_rsassa_pkcs1_v1_5_with_sha3_256, "SHA3-256", "RSA");
        addEntries(NISTObjectIdentifiers.id_rsassa_pkcs1_v1_5_with_sha3_384, "SHA3-384", "RSA");
        addEntries(NISTObjectIdentifiers.id_rsassa_pkcs1_v1_5_with_sha3_512, "SHA3-512", "RSA");
        addEntries(X509ObjectIdentifiers.id_rsassa_pss_shake128, "SHAKE128", "RSAPSS");
        addEntries(X509ObjectIdentifiers.id_rsassa_pss_shake256, "SHAKE256", "RSAPSS");

        addEntries(TeleTrusTObjectIdentifiers.rsaSignatureWithripemd128, "RIPEMD128", "RSA");
        addEntries(TeleTrusTObjectIdentifiers.rsaSignatureWithripemd160, "RIPEMD160", "RSA");
        addEntries(TeleTrusTObjectIdentifiers.rsaSignatureWithripemd256, "RIPEMD256", "RSA");

        addEntries(X9ObjectIdentifiers.ecdsa_with_SHA1, "SHA1", "ECDSA");
        addEntries(X9ObjectIdentifiers.ecdsa_with_SHA224, "SHA224", "ECDSA");
        addEntries(X9ObjectIdentifiers.ecdsa_with_SHA256, "SHA256", "ECDSA");
        addEntries(X9ObjectIdentifiers.ecdsa_with_SHA384, "SHA384", "ECDSA");
        addEntries(X9ObjectIdentifiers.ecdsa_with_SHA512, "SHA512", "ECDSA");
        addEntries(X509ObjectIdentifiers.id_ecdsa_with_shake128, "SHAKE128", "ECDSA");
        addEntries(X509ObjectIdentifiers.id_ecdsa_with_shake256, "SHAKE256", "ECDSA");
        addEntries(X9ObjectIdentifiers.id_dsa_with_sha1, "SHA1", "DSA");
        addEntries(EACObjectIdentifiers.id_TA_ECDSA_SHA_1, "SHA1", "ECDSA");
        addEntries(EACObjectIdentifiers.id_TA_ECDSA_SHA_224, "SHA224", "ECDSA");
        addEntries(EACObjectIdentifiers.id_TA_ECDSA_SHA_256, "SHA256", "ECDSA");
        addEntries(EACObjectIdentifiers.id_TA_ECDSA_SHA_384, "SHA384", "ECDSA");
        addEntries(EACObjectIdentifiers.id_TA_ECDSA_SHA_512, "SHA512", "ECDSA");
        addEntries(EACObjectIdentifiers.id_TA_RSA_v1_5_SHA_1, "SHA1", "RSA");
        addEntries(EACObjectIdentifiers.id_TA_RSA_v1_5_SHA_256, "SHA256", "RSA");
        addEntries(EACObjectIdentifiers.id_TA_RSA_PSS_SHA_1, "SHA1", "RSAandMGF1");
        addEntries(EACObjectIdentifiers.id_TA_RSA_PSS_SHA_256, "SHA256", "RSAandMGF1");
        addEntries(BSIObjectIdentifiers.ecdsa_plain_SHA1, "SHA1", "PLAIN-ECDSA");
        addEntries(BSIObjectIdentifiers.ecdsa_plain_SHA224, "SHA224", "PLAIN-ECDSA");
        addEntries(BSIObjectIdentifiers.ecdsa_plain_SHA256, "SHA256", "PLAIN-ECDSA");
        addEntries(BSIObjectIdentifiers.ecdsa_plain_SHA384, "SHA384", "PLAIN-ECDSA");
        addEntries(BSIObjectIdentifiers.ecdsa_plain_SHA512, "SHA512", "PLAIN-ECDSA");
        addEntries(BSIObjectIdentifiers.ecdsa_plain_RIPEMD160, "RIPEMD160", "PLAIN-ECDSA");
        addEntries(BSIObjectIdentifiers.ecdsa_plain_SHA3_224, "SHA3-224", "PLAIN-ECDSA");
        addEntries(BSIObjectIdentifiers.ecdsa_plain_SHA3_256, "SHA3-256", "PLAIN-ECDSA");
        addEntries(BSIObjectIdentifiers.ecdsa_plain_SHA3_384, "SHA3-384", "PLAIN-ECDSA");
        addEntries(BSIObjectIdentifiers.ecdsa_plain_SHA3_512, "SHA3-512", "PLAIN-ECDSA");

//        addEntries(GMObjectIdentifiers.sm2sign_with_rmd160, "RIPEMD160", "SM2");
//        addEntries(GMObjectIdentifiers.sm2sign_with_sha1, "SHA1", "SM2");
//        addEntries(GMObjectIdentifiers.sm2sign_with_sha224, "SHA224", "SM2");
        addEntries(GMObjectIdentifiers.sm2sign_with_sha256, "SHA256", "SM2");
//        addEntries(GMObjectIdentifiers.sm2sign_with_sha384, "SHA384", "SM2");
//        addEntries(GMObjectIdentifiers.sm2sign_with_sha512, "SHA512", "SM2");
        addEntries(GMObjectIdentifiers.sm2sign_with_sm3, "SM3", "SM2");

        addEntries(BCObjectIdentifiers.sphincs256_with_SHA512, "SHA512", "SPHINCS256");
        addEntries(BCObjectIdentifiers.sphincs256_with_SHA3_512, "SHA3-512", "SPHINCS256");

        addEntries(BCObjectIdentifiers.picnic_with_shake256, "SHAKE256", "Picnic");
        addEntries(BCObjectIdentifiers.picnic_with_sha512, "SHA512", "Picnic");
        addEntries(BCObjectIdentifiers.picnic_with_sha3_512, "SHA3-512", "Picnic");

        addEncryptionAlg(X9ObjectIdentifiers.id_dsa, "DSA");
        addEncryptionAlg(PKCSObjectIdentifiers.rsaEncryption, "RSA");
        addEncryptionAlg(TeleTrusTObjectIdentifiers.teleTrusTRSAsignatureAlgorithm, "RSA");
        addEncryptionAlg(X509ObjectIdentifiers.id_ea_rsa, "RSA");
        addEncryptionAlg(PKCSObjectIdentifiers.id_RSASSA_PSS, "RSAandMGF1");
        addEncryptionAlg(CryptoProObjectIdentifiers.gostR3410_94, "GOST3410");
        addEncryptionAlg(CryptoProObjectIdentifiers.gostR3410_2001, "ECGOST3410");
        addEncryptionAlg(new ASN1ObjectIdentifier("1.3.6.1.4.1.5849.1.6.2"), "ECGOST3410");
        addEncryptionAlg(new ASN1ObjectIdentifier("1.3.6.1.4.1.5849.1.1.5"), "GOST3410");
        addEncryptionAlg(RosstandartObjectIdentifiers.id_tc26_gost_3410_12_256, "ECGOST3410-2012-256");
        addEncryptionAlg(RosstandartObjectIdentifiers.id_tc26_gost_3410_12_512, "ECGOST3410-2012-512");
        addEncryptionAlg(CryptoProObjectIdentifiers.gostR3411_94_with_gostR3410_2001, "ECGOST3410");
        addEncryptionAlg(CryptoProObjectIdentifiers.gostR3411_94_with_gostR3410_94, "GOST3410");
        addEncryptionAlg(RosstandartObjectIdentifiers.id_tc26_signwithdigest_gost_3410_12_256, "ECGOST3410-2012-256");
        addEncryptionAlg(RosstandartObjectIdentifiers.id_tc26_signwithdigest_gost_3410_12_512, "ECGOST3410-2012-512");
        addEncryptionAlg(X9ObjectIdentifiers.id_ecPublicKey, "ECDSA");

        addDigestAlg(PKCSObjectIdentifiers.md2, "MD2");
        addDigestAlg(PKCSObjectIdentifiers.md4, "MD4");
        addDigestAlg(PKCSObjectIdentifiers.md5, "MD5");
        addDigestAlg(OIWObjectIdentifiers.idSHA1, "SHA1");
        addDigestAlg(NISTObjectIdentifiers.id_sha224, "SHA224");
        addDigestAlg(NISTObjectIdentifiers.id_sha256, "SHA256");
        addDigestAlg(NISTObjectIdentifiers.id_sha384, "SHA384");
        addDigestAlg(NISTObjectIdentifiers.id_sha512, "SHA512");
        addDigestAlg(NISTObjectIdentifiers.id_sha512_224, "SHA512(224)");
        addDigestAlg(NISTObjectIdentifiers.id_sha512_256, "SHA512(256)");
        addDigestAlg(NISTObjectIdentifiers.id_shake128, "SHAKE128");
        addDigestAlg(NISTObjectIdentifiers.id_shake256, "SHAKE256");
        addDigestAlg(NISTObjectIdentifiers.id_sha3_224, "SHA3-224");
        addDigestAlg(NISTObjectIdentifiers.id_sha3_256, "SHA3-256");
        addDigestAlg(NISTObjectIdentifiers.id_sha3_384, "SHA3-384");
        addDigestAlg(NISTObjectIdentifiers.id_sha3_512, "SHA3-512");
        addDigestAlg(TeleTrusTObjectIdentifiers.ripemd128, "RIPEMD128");
        addDigestAlg(TeleTrusTObjectIdentifiers.ripemd160, "RIPEMD160");
        addDigestAlg(TeleTrusTObjectIdentifiers.ripemd256, "RIPEMD256");
        addDigestAlg(CryptoProObjectIdentifiers.gostR3411,  "GOST3411");
        addDigestAlg(new ASN1ObjectIdentifier("1.3.6.1.4.1.5849.1.2.1"),  "GOST3411");
        addDigestAlg(RosstandartObjectIdentifiers.id_tc26_gost_3411_12_256,  "GOST3411-2012-256");
        addDigestAlg(RosstandartObjectIdentifiers.id_tc26_gost_3411_12_512,  "GOST3411-2012-512");
        addDigestAlg(GMObjectIdentifiers.sm3,  "SM3");

        addSimpleAlg(EdECObjectIdentifiers.id_Ed25519, "Ed25519");
        addSimpleAlg(EdECObjectIdentifiers.id_Ed448, "Ed448");
        addSimpleAlg(PKCSObjectIdentifiers.id_alg_hss_lms_hashsig, "LMS");

        addSimpleAlg(MiscObjectIdentifiers.id_alg_composite, "COMPOSITE");
        addSimpleAlg(BCObjectIdentifiers.falcon_512, "Falcon-512");
        addSimpleAlg(BCObjectIdentifiers.falcon_1024, "Falcon-1024");
        addSimpleAlg(BCObjectIdentifiers.dilithium2, "Dilithium2");
        addSimpleAlg(BCObjectIdentifiers.dilithium3, "Dilithium3");
        addSimpleAlg(BCObjectIdentifiers.dilithium5, "Dilithium5");
        addSimpleAlg(BCObjectIdentifiers.sphincsPlus_sha2_128s, "SPHINCS+-SHA2-128s");
        addSimpleAlg(BCObjectIdentifiers.sphincsPlus_sha2_128f, "SPHINCS+-SHA2-128f");
        addSimpleAlg(BCObjectIdentifiers.sphincsPlus_sha2_192s, "SPHINCS+-SHA2-192s");
        addSimpleAlg(BCObjectIdentifiers.sphincsPlus_sha2_192f, "SPHINCS+-SHA2-192f");
        addSimpleAlg(BCObjectIdentifiers.sphincsPlus_sha2_256s, "SPHINCS+-SHA2-256s");
        addSimpleAlg(BCObjectIdentifiers.sphincsPlus_sha2_256f, "SPHINCS+-SHA2-256f");
        addSimpleAlg(BCObjectIdentifiers.sphincsPlus_shake_128s, "SPHINCS+-SHAKE-128s");
        addSimpleAlg(BCObjectIdentifiers.sphincsPlus_shake_128f, "SPHINCS+-SHAKE-128f");
        addSimpleAlg(BCObjectIdentifiers.sphincsPlus_shake_192s, "SPHINCS+-SHAKE-192s");
        addSimpleAlg(BCObjectIdentifiers.sphincsPlus_shake_192f, "SPHINCS+-SHAKE-192f");
        addSimpleAlg(BCObjectIdentifiers.sphincsPlus_shake_256s, "SPHINCS+-SHAKE-256s");
        addSimpleAlg(BCObjectIdentifiers.sphincsPlus_shake_256f, "SPHINCS+-SHAKE-256f");

        addSimpleAlg(NISTObjectIdentifiers.id_ml_dsa_44, "ML-DSA-44");
        addSimpleAlg(NISTObjectIdentifiers.id_ml_dsa_65, "ML-DSA-65");
        addSimpleAlg(NISTObjectIdentifiers.id_ml_dsa_87, "ML-DSA-87");

        addSimpleAlg(NISTObjectIdentifiers.id_hash_ml_dsa_44_with_sha512, "ML-DSA-44-WITH-SHA512");
        addSimpleAlg(NISTObjectIdentifiers.id_hash_ml_dsa_65_with_sha512, "ML-DSA-65-WITH-SHA512");
        addSimpleAlg(NISTObjectIdentifiers.id_hash_ml_dsa_87_with_sha512, "ML-DSA-87-WITH-SHA512");

        addSimpleAlg(NISTObjectIdentifiers.id_slh_dsa_sha2_128s, "SLH-DSA-SHA2-128S");
        addSimpleAlg(NISTObjectIdentifiers.id_slh_dsa_sha2_128f, "SLH-DSA-SHA2-128F");
        addSimpleAlg(NISTObjectIdentifiers.id_slh_dsa_sha2_192s, "SLH-DSA-SHA2-192S");
        addSimpleAlg(NISTObjectIdentifiers.id_slh_dsa_sha2_192f, "SLH-DSA-SHA2-192F");
        addSimpleAlg(NISTObjectIdentifiers.id_slh_dsa_sha2_256s, "SLH-DSA-SHA2-256S");
        addSimpleAlg(NISTObjectIdentifiers.id_slh_dsa_sha2_256f, "SLH-DSA-SHA2-256F");

        addSimpleAlg(NISTObjectIdentifiers.id_slh_dsa_shake_128s, "SLH-DSA-SHAKE-128S");
        addSimpleAlg(NISTObjectIdentifiers.id_slh_dsa_shake_128f, "SLH-DSA-SHAKE-128F");
        addSimpleAlg(NISTObjectIdentifiers.id_slh_dsa_shake_192s, "SLH-DSA-SHAKE-192S");
        addSimpleAlg(NISTObjectIdentifiers.id_slh_dsa_shake_192f, "SLH-DSA-SHAKE-192F");
        addSimpleAlg(NISTObjectIdentifiers.id_slh_dsa_shake_256s, "SLH-DSA-SHAKE-256S");
        addSimpleAlg(NISTObjectIdentifiers.id_slh_dsa_shake_256f, "SLH-DSA-SHAKE-256F");

        addSimpleAlg(NISTObjectIdentifiers.id_hash_slh_dsa_sha2_128s_with_sha256, "SLH-DSA-SHA2-128S-WITH-SHA256");
        addSimpleAlg(NISTObjectIdentifiers.id_hash_slh_dsa_sha2_128f_with_sha256, "SLH-DSA-SHA2-128F-WITH-SHA256");
        addSimpleAlg(NISTObjectIdentifiers.id_hash_slh_dsa_sha2_192s_with_sha512, "SLH-DSA-SHA2-192S-WITH-SHA512");
        addSimpleAlg(NISTObjectIdentifiers.id_hash_slh_dsa_sha2_192f_with_sha512, "SLH-DSA-SHA2-192F-WITH-SHA512");
        addSimpleAlg(NISTObjectIdentifiers.id_hash_slh_dsa_sha2_256s_with_sha512, "SLH-DSA-SHA2-256S-WITH-SHA512");
        addSimpleAlg(NISTObjectIdentifiers.id_hash_slh_dsa_sha2_256f_with_sha512, "SLH-DSA-SHA2-256F-WITH-SHA512");

        addSimpleAlg(NISTObjectIdentifiers.id_hash_slh_dsa_shake_128s_with_shake128, "SLH-DSA-SHAKE-128S-WITH-SHAKE128");
        addSimpleAlg(NISTObjectIdentifiers.id_hash_slh_dsa_shake_128f_with_shake128, "SLH-DSA-SHAKE-128F-WITH-SHAKE128");
        addSimpleAlg(NISTObjectIdentifiers.id_hash_slh_dsa_shake_192s_with_shake256, "SLH-DSA-SHAKE-192S-WITH-SHAKE256");
        addSimpleAlg(NISTObjectIdentifiers.id_hash_slh_dsa_shake_192f_with_shake256, "SLH-DSA-SHAKE-192F-WITH-SHAKE256");
        addSimpleAlg(NISTObjectIdentifiers.id_hash_slh_dsa_shake_256s_with_shake256, "SLH-DSA-SHAKE-256S-WITH-SHAKE256");
        addSimpleAlg(NISTObjectIdentifiers.id_hash_slh_dsa_shake_256f_with_shake256, "SLH-DSA-SHAKE-256F-WITH-SHAKE256");

        addSimpleAlg(BCObjectIdentifiers.picnic_signature, "Picnic");
    }

    /**
     * Return the digest algorithm using one of the standard JCA string
     * representations rather than the algorithm identifier (if possible).
     */
    private String getDigestAlgName(
        ASN1ObjectIdentifier digestAlgOID)
    {
        String algName = (String)digestAlgs.get(digestAlgOID);

        if (algName != null)
        {
            return algName;
        }

        return digestAlgOID.getId();
    }

    /**
     * Return the digest encryption algorithm using one of the standard
     * JCA string representations rather the the algorithm identifier (if
     * possible).
     */
    private String getEncryptionAlgName(
        ASN1ObjectIdentifier encryptionAlgOID)
    {
        String algName = (String)encryptionAlgs.get(encryptionAlgOID);

        if (algName != null)
        {
            return algName;
        }

        return encryptionAlgOID.getId();
    }

    /**
     * Set the mapping for the encryption algorithm used in association with a SignedData generation
     * or interpretation.
     *
     * @param oid object identifier to map.
     * @param algorithmName algorithm name to use.
     */
    protected void setSigningEncryptionAlgorithmMapping(ASN1ObjectIdentifier oid, String algorithmName)
    {
        encryptionAlgs.put(oid, algorithmName);
    }

    /**
     * Set the mapping for the digest algorithm to use in conjunction with a SignedData generation
     * or interpretation.
     *
     * @param oid object identifier to map.
     * @param algorithmName algorithm name to use.
     */
    protected void setSigningDigestAlgorithmMapping(ASN1ObjectIdentifier oid, String algorithmName)
    {
        digestAlgs.put(oid, algorithmName);
    }

    public String getSignatureName(AlgorithmIdentifier digestAlg, AlgorithmIdentifier encryptionAlg)
    {
        ASN1ObjectIdentifier encryptionAlgOID = encryptionAlg.getAlgorithm();

        String simpleAlgName = (String)simpleAlgs.get(encryptionAlgOID);
        if (simpleAlgName != null)
        {
            return simpleAlgName;
        }

        if (encryptionAlgOID.on(BCObjectIdentifiers.sphincsPlus))
        {
            return "SPHINCSPlus";
        }

        String digestName = getDigestAlgName(encryptionAlgOID);

        if (!digestName.equals(encryptionAlgOID.getId()))
        {
            return digestName + "with" + getEncryptionAlgName(encryptionAlgOID);
        }

        return getDigestAlgName(digestAlg.getAlgorithm()) + "with" + getEncryptionAlgName(encryptionAlgOID);
    }
}
