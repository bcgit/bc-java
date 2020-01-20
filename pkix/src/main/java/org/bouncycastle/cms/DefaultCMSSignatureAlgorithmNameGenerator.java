package org.bouncycastle.cms;

import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.bsi.BSIObjectIdentifiers;
import org.bouncycastle.asn1.cryptopro.CryptoProObjectIdentifiers;
import org.bouncycastle.asn1.eac.EACObjectIdentifiers;
import org.bouncycastle.asn1.edec.EdECObjectIdentifiers;
import org.bouncycastle.asn1.gm.GMObjectIdentifiers;
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

    private void addEntries(ASN1ObjectIdentifier alias, String digest, String encryption)
    {
        digestAlgs.put(alias, digest);
        encryptionAlgs.put(alias, encryption);
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
        addEntries(NISTObjectIdentifiers.id_rsassa_pkcs1_v1_5_with_sha3_224, "SHA3-224", "RSA");
        addEntries(NISTObjectIdentifiers.id_rsassa_pkcs1_v1_5_with_sha3_256, "SHA3-256", "RSA");
        addEntries(NISTObjectIdentifiers.id_rsassa_pkcs1_v1_5_with_sha3_384, "SHA3-384", "RSA");
        addEntries(NISTObjectIdentifiers.id_rsassa_pkcs1_v1_5_with_sha3_512, "SHA3-512", "RSA");
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

        addEntries(TeleTrusTObjectIdentifiers.rsaSignatureWithripemd128, "RIPEMD128", "RSA");
        addEntries(TeleTrusTObjectIdentifiers.rsaSignatureWithripemd160, "RIPEMD160", "RSA");
        addEntries(TeleTrusTObjectIdentifiers.rsaSignatureWithripemd256, "RIPEMD256", "RSA");

        addEntries(X9ObjectIdentifiers.ecdsa_with_SHA1, "SHA1", "ECDSA");
        addEntries(X9ObjectIdentifiers.ecdsa_with_SHA224, "SHA224", "ECDSA");
        addEntries(X9ObjectIdentifiers.ecdsa_with_SHA256, "SHA256", "ECDSA");
        addEntries(X9ObjectIdentifiers.ecdsa_with_SHA384, "SHA384", "ECDSA");
        addEntries(X9ObjectIdentifiers.ecdsa_with_SHA512, "SHA512", "ECDSA");
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

//        addEntries(GMObjectIdentifiers.sm2sign_with_rmd160, "RIPEMD160", "SM2");
//        addEntries(GMObjectIdentifiers.sm2sign_with_sha1, "SHA1", "SM2");
//        addEntries(GMObjectIdentifiers.sm2sign_with_sha224, "SHA224", "SM2");
        addEntries(GMObjectIdentifiers.sm2sign_with_sha256, "SHA256", "SM2");
//        addEntries(GMObjectIdentifiers.sm2sign_with_sha384, "SHA384", "SM2");
//        addEntries(GMObjectIdentifiers.sm2sign_with_sha512, "SHA512", "SM2");
        addEntries(GMObjectIdentifiers.sm2sign_with_sm3, "SM3", "SM2");

        encryptionAlgs.put(X9ObjectIdentifiers.id_dsa, "DSA");
        encryptionAlgs.put(PKCSObjectIdentifiers.rsaEncryption, "RSA");
        encryptionAlgs.put(TeleTrusTObjectIdentifiers.teleTrusTRSAsignatureAlgorithm, "RSA");
        encryptionAlgs.put(X509ObjectIdentifiers.id_ea_rsa, "RSA");
        encryptionAlgs.put(PKCSObjectIdentifiers.id_RSASSA_PSS, "RSAandMGF1");
        encryptionAlgs.put(CryptoProObjectIdentifiers.gostR3410_94, "GOST3410");
        encryptionAlgs.put(CryptoProObjectIdentifiers.gostR3410_2001, "ECGOST3410");
        encryptionAlgs.put(new ASN1ObjectIdentifier("1.3.6.1.4.1.5849.1.6.2"), "ECGOST3410");
        encryptionAlgs.put(new ASN1ObjectIdentifier("1.3.6.1.4.1.5849.1.1.5"), "GOST3410");
        encryptionAlgs.put(RosstandartObjectIdentifiers.id_tc26_gost_3410_12_256, "ECGOST3410-2012-256");
        encryptionAlgs.put(RosstandartObjectIdentifiers.id_tc26_gost_3410_12_512, "ECGOST3410-2012-512");
        encryptionAlgs.put(CryptoProObjectIdentifiers.gostR3411_94_with_gostR3410_2001, "ECGOST3410");
        encryptionAlgs.put(CryptoProObjectIdentifiers.gostR3411_94_with_gostR3410_94, "GOST3410");
        encryptionAlgs.put(RosstandartObjectIdentifiers.id_tc26_signwithdigest_gost_3410_12_256, "ECGOST3410-2012-256");
        encryptionAlgs.put(RosstandartObjectIdentifiers.id_tc26_signwithdigest_gost_3410_12_512, "ECGOST3410-2012-512");

        digestAlgs.put(PKCSObjectIdentifiers.md2, "MD2");
        digestAlgs.put(PKCSObjectIdentifiers.md4, "MD4");
        digestAlgs.put(PKCSObjectIdentifiers.md5, "MD5");
        digestAlgs.put(OIWObjectIdentifiers.idSHA1, "SHA1");
        digestAlgs.put(NISTObjectIdentifiers.id_sha224, "SHA224");
        digestAlgs.put(NISTObjectIdentifiers.id_sha256, "SHA256");
        digestAlgs.put(NISTObjectIdentifiers.id_sha384, "SHA384");
        digestAlgs.put(NISTObjectIdentifiers.id_sha512, "SHA512");
        digestAlgs.put(NISTObjectIdentifiers.id_sha3_224, "SHA3-224");
        digestAlgs.put(NISTObjectIdentifiers.id_sha3_256, "SHA3-256");
        digestAlgs.put(NISTObjectIdentifiers.id_sha3_384, "SHA3-384");
        digestAlgs.put(NISTObjectIdentifiers.id_sha3_512, "SHA3-512");
        digestAlgs.put(TeleTrusTObjectIdentifiers.ripemd128, "RIPEMD128");
        digestAlgs.put(TeleTrusTObjectIdentifiers.ripemd160, "RIPEMD160");
        digestAlgs.put(TeleTrusTObjectIdentifiers.ripemd256, "RIPEMD256");
        digestAlgs.put(CryptoProObjectIdentifiers.gostR3411,  "GOST3411");
        digestAlgs.put(new ASN1ObjectIdentifier("1.3.6.1.4.1.5849.1.2.1"),  "GOST3411");
        digestAlgs.put(RosstandartObjectIdentifiers.id_tc26_gost_3411_12_256,  "GOST3411-2012-256");
        digestAlgs.put(RosstandartObjectIdentifiers.id_tc26_gost_3411_12_512,  "GOST3411-2012-512");
        digestAlgs.put(GMObjectIdentifiers.sm3,  "SM3");
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
        if (EdECObjectIdentifiers.id_Ed25519.equals(encryptionAlg.getAlgorithm()))
        {
            return "Ed25519";
        }
        if (EdECObjectIdentifiers.id_Ed448.equals(encryptionAlg.getAlgorithm()))
        {
            return "Ed448";
        }

        String digestName = getDigestAlgName(encryptionAlg.getAlgorithm());

        if (!digestName.equals(encryptionAlg.getAlgorithm().getId()))
        {
            return digestName + "with" + getEncryptionAlgName(encryptionAlg.getAlgorithm());
        }

        return getDigestAlgName(digestAlg.getAlgorithm()) + "with" + getEncryptionAlgName(encryptionAlg.getAlgorithm());
    }
}
