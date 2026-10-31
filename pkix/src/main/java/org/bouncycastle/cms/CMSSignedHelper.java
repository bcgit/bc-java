package org.bouncycastle.cms;

import java.util.ArrayList;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.BERTags;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.cms.OtherRevocationInfoFormat;
import org.bouncycastle.asn1.eac.EACObjectIdentifiers;
import org.bouncycastle.asn1.edec.EdECObjectIdentifiers;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.teletrust.TeleTrusTObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.AttributeCertificate;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.asn1.x509.CertificateList;
import org.bouncycastle.asn1.x509.X509ObjectIdentifiers;
import org.bouncycastle.cert.X509AttributeCertificateHolder;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.operator.DigestAlgorithmIdentifierFinder;
import org.bouncycastle.util.CollectionStore;
import org.bouncycastle.util.Integers;
import org.bouncycastle.util.Store;

class CMSSignedHelper
{
    static final CMSSignedHelper INSTANCE = new CMSSignedHelper();

    /**
     * The digest algorithms RFC 9882, Table 1, allows a SignerInfo to name for each ML-DSA
     * parameter set, keyed by signature algorithm OID.
     */
    private static final HashMap ML_DSA_DIGESTS = new HashMap();

    /** the security parameter n of each SLH-DSA parameter set, keyed by signature algorithm OID. */
    private static final HashMap SLH_DSA_N = new HashMap();

    /** the output size in bits of the fixed-length NIST digests, keyed by OID. */
    private static final HashMap DIGEST_OUTPUT_BITS = new HashMap();

    static
    {
        HashSet mlDsa87 = new HashSet();
        mlDsa87.add(NISTObjectIdentifiers.id_sha512);
        mlDsa87.add(NISTObjectIdentifiers.id_sha3_512);
        mlDsa87.add(NISTObjectIdentifiers.id_shake256);
        mlDsa87.add(NISTObjectIdentifiers.id_shake256_len);

        HashSet mlDsa65 = new HashSet(mlDsa87);
        mlDsa65.add(NISTObjectIdentifiers.id_sha384);
        mlDsa65.add(NISTObjectIdentifiers.id_sha3_384);

        HashSet mlDsa44 = new HashSet(mlDsa65);
        mlDsa44.add(NISTObjectIdentifiers.id_sha256);
        mlDsa44.add(NISTObjectIdentifiers.id_sha3_256);
        mlDsa44.add(NISTObjectIdentifiers.id_shake128);
        mlDsa44.add(NISTObjectIdentifiers.id_shake128_len);

        ML_DSA_DIGESTS.put(NISTObjectIdentifiers.id_ml_dsa_44, mlDsa44);
        ML_DSA_DIGESTS.put(NISTObjectIdentifiers.id_ml_dsa_65, mlDsa65);
        ML_DSA_DIGESTS.put(NISTObjectIdentifiers.id_ml_dsa_87, mlDsa87);

        Integer n16 = Integers.valueOf(16), n24 = Integers.valueOf(24), n32 = Integers.valueOf(32);
        SLH_DSA_N.put(NISTObjectIdentifiers.id_slh_dsa_sha2_128s, n16);
        SLH_DSA_N.put(NISTObjectIdentifiers.id_slh_dsa_sha2_128f, n16);
        SLH_DSA_N.put(NISTObjectIdentifiers.id_slh_dsa_shake_128s, n16);
        SLH_DSA_N.put(NISTObjectIdentifiers.id_slh_dsa_shake_128f, n16);
        SLH_DSA_N.put(NISTObjectIdentifiers.id_slh_dsa_sha2_192s, n24);
        SLH_DSA_N.put(NISTObjectIdentifiers.id_slh_dsa_sha2_192f, n24);
        SLH_DSA_N.put(NISTObjectIdentifiers.id_slh_dsa_shake_192s, n24);
        SLH_DSA_N.put(NISTObjectIdentifiers.id_slh_dsa_shake_192f, n24);
        SLH_DSA_N.put(NISTObjectIdentifiers.id_slh_dsa_sha2_256s, n32);
        SLH_DSA_N.put(NISTObjectIdentifiers.id_slh_dsa_sha2_256f, n32);
        SLH_DSA_N.put(NISTObjectIdentifiers.id_slh_dsa_shake_256s, n32);
        SLH_DSA_N.put(NISTObjectIdentifiers.id_slh_dsa_shake_256f, n32);

        Integer b224 = Integers.valueOf(224), b256 = Integers.valueOf(256), b384 = Integers.valueOf(384), b512 = Integers.valueOf(512);
        DIGEST_OUTPUT_BITS.put(NISTObjectIdentifiers.id_sha224, b224);
        DIGEST_OUTPUT_BITS.put(NISTObjectIdentifiers.id_sha512_224, b224);
        DIGEST_OUTPUT_BITS.put(NISTObjectIdentifiers.id_sha3_224, b224);
        DIGEST_OUTPUT_BITS.put(NISTObjectIdentifiers.id_sha256, b256);
        DIGEST_OUTPUT_BITS.put(NISTObjectIdentifiers.id_sha512_256, b256);
        DIGEST_OUTPUT_BITS.put(NISTObjectIdentifiers.id_sha3_256, b256);
        DIGEST_OUTPUT_BITS.put(NISTObjectIdentifiers.id_shake128, b256);
        DIGEST_OUTPUT_BITS.put(NISTObjectIdentifiers.id_sha384, b384);
        DIGEST_OUTPUT_BITS.put(NISTObjectIdentifiers.id_sha3_384, b384);
        DIGEST_OUTPUT_BITS.put(NISTObjectIdentifiers.id_sha512, b512);
        DIGEST_OUTPUT_BITS.put(NISTObjectIdentifiers.id_sha3_512, b512);
        DIGEST_OUTPUT_BITS.put(NISTObjectIdentifiers.id_shake256, b512);
    }

    /**
     * Check that the digest algorithm a SignerInfo names is one its "pure" signature algorithm
     * permits: RFC 9882 sec. 3.3 (ML-DSA), RFC 9814 sec. 4 (SLH-DSA) and RFC 8419 sec. 3
     * (Ed25519 and Ed448). Other signature algorithms are not restricted.
     *
     * @param sigAlgId         the SignerInfo signatureAlgorithm.
     * @param digAlgId         the SignerInfo digestAlgorithm.
     * @param signedAttrsPresent true if the SignerInfo carries signed attributes.
     * @throws CMSException if the digest algorithm is not permitted with the signature algorithm.
     */
    static void checkDigestAlgorithm(AlgorithmIdentifier sigAlgId, AlgorithmIdentifier digAlgId, boolean signedAttrsPresent)
        throws CMSException
    {
        ASN1ObjectIdentifier sigAlgOid = sigAlgId.getAlgorithm();
        ASN1ObjectIdentifier digAlgOid = digAlgId.getAlgorithm();

        HashSet mlDsaDigests = (HashSet)ML_DSA_DIGESTS.get(sigAlgOid);
        if (mlDsaDigests != null)
        {
            // RFC 9882 3.3: without signed attributes the digestAlgorithm MUST be SHA-512; with them
            // it is restricted to the digests of Table 1 that match the parameter set's strength.
            if (!signedAttrsPresent)
            {
                if (!NISTObjectIdentifiers.id_sha512.equals(digAlgOid))
                {
                    throw new CMSException("ML-DSA without signed attributes requires SHA-512 as digest algorithm (RFC 9882 3.3)");
                }
                return;
            }
            if (!mlDsaDigests.contains(digAlgOid) || shakeOutputTooShort(digAlgId))
            {
                throw new CMSException("digest algorithm " + digAlgOid + " not permitted with " + sigAlgOid + " (RFC 9882 3.3)");
            }
            return;
        }

        Integer slhDsaN = (Integer)SLH_DSA_N.get(sigAlgOid);
        if (slhDsaN != null)
        {
            // RFC 9814 4: with signed attributes the digest MUST be at least twice the size of the
            // tree hash; without them it has no significance and only SHOULD match the tree hash.
            if (signedAttrsPresent)
            {
                int digestBits = getDigestOutputBits(digAlgId);
                if (digestBits >= 0 && digestBits < 2 * 8 * slhDsaN.intValue())
                {
                    throw new CMSException("digest algorithm " + digAlgOid + " too short for " + sigAlgOid + " with signed attributes (RFC 9814 4)");
                }
            }
            return;
        }

        if (EdECObjectIdentifiers.id_Ed25519.equals(sigAlgOid))
        {
            // RFC 8419 3.1, 3.2
            if (!NISTObjectIdentifiers.id_sha512.equals(digAlgOid))
            {
                throw new CMSException("Ed25519 requires SHA-512 as digest algorithm (RFC 8419 3)");
            }
            return;
        }

        if (EdECObjectIdentifiers.id_Ed448.equals(sigAlgOid))
        {
            // RFC 8419 3.1, 3.2: SHAKE256 with 512 bits of output, as id-shake256 or id-shake256-len(512)
            if (NISTObjectIdentifiers.id_shake256.equals(digAlgOid))
            {
                return;
            }
            if (NISTObjectIdentifiers.id_shake256_len.equals(digAlgOid) && getDigestOutputBits(digAlgId) == 512)
            {
                return;
            }
            throw new CMSException("Ed448 requires SHAKE256 with 512 bits of output as digest algorithm (RFC 8419 3)");
        }
    }

    /**
     * Return true for an id-shake128-len / id-shake256-len identifier whose output length is
     * below the 256 / 512 bits of the plain SHAKE128 / SHAKE256 digest identifiers.
     */
    private static boolean shakeOutputTooShort(AlgorithmIdentifier digAlgId)
    {
        ASN1ObjectIdentifier digAlgOid = digAlgId.getAlgorithm();

        if (NISTObjectIdentifiers.id_shake128_len.equals(digAlgOid))
        {
            return getDigestOutputBits(digAlgId) < 256;
        }
        if (NISTObjectIdentifiers.id_shake256_len.equals(digAlgOid))
        {
            return getDigestOutputBits(digAlgId) < 512;
        }
        return false;
    }

    /**
     * Return the output size in bits of a NIST digest identifier, or -1 if it is not one.
     */
    private static int getDigestOutputBits(AlgorithmIdentifier digAlgId)
    {
        ASN1ObjectIdentifier digAlgOid = digAlgId.getAlgorithm();

        Integer bits = (Integer)DIGEST_OUTPUT_BITS.get(digAlgOid);
        if (bits != null)
        {
            return bits.intValue();
        }

        if (NISTObjectIdentifiers.id_shake128_len.equals(digAlgOid) || NISTObjectIdentifiers.id_shake256_len.equals(digAlgOid))
        {
            ASN1Encodable params = digAlgId.getParameters();
            if (params == null)
            {
                return -1;
            }
            try
            {
                return ASN1Integer.getInstance(params).intValueExact();
            }
            catch (RuntimeException e)
            {
                return -1;
            }
        }
        return -1;
    }

    private static final HashSet RSA_SIG_ALGS = new HashSet(); 

    static
    {
        RSA_SIG_ALGS.add(EACObjectIdentifiers.id_TA_RSA_v1_5_SHA_1);
        RSA_SIG_ALGS.add(EACObjectIdentifiers.id_TA_RSA_v1_5_SHA_256);

        RSA_SIG_ALGS.add(NISTObjectIdentifiers.id_rsassa_pkcs1_v1_5_with_sha3_224);
        RSA_SIG_ALGS.add(NISTObjectIdentifiers.id_rsassa_pkcs1_v1_5_with_sha3_256);
        RSA_SIG_ALGS.add(NISTObjectIdentifiers.id_rsassa_pkcs1_v1_5_with_sha3_384);
        RSA_SIG_ALGS.add(NISTObjectIdentifiers.id_rsassa_pkcs1_v1_5_with_sha3_512);

        RSA_SIG_ALGS.add(OIWObjectIdentifiers.md4WithRSA);
        RSA_SIG_ALGS.add(OIWObjectIdentifiers.md4WithRSAEncryption);
        RSA_SIG_ALGS.add(OIWObjectIdentifiers.md5WithRSA);
        RSA_SIG_ALGS.add(OIWObjectIdentifiers.sha1WithRSA);

        RSA_SIG_ALGS.add(PKCSObjectIdentifiers.md2WithRSAEncryption);
        RSA_SIG_ALGS.add(PKCSObjectIdentifiers.md4WithRSAEncryption);
        RSA_SIG_ALGS.add(PKCSObjectIdentifiers.md5WithRSAEncryption);
        RSA_SIG_ALGS.add(PKCSObjectIdentifiers.rsaEncryption);
        RSA_SIG_ALGS.add(PKCSObjectIdentifiers.sha1WithRSAEncryption);
        RSA_SIG_ALGS.add(PKCSObjectIdentifiers.sha224WithRSAEncryption);
        RSA_SIG_ALGS.add(PKCSObjectIdentifiers.sha256WithRSAEncryption);
        RSA_SIG_ALGS.add(PKCSObjectIdentifiers.sha384WithRSAEncryption);
        RSA_SIG_ALGS.add(PKCSObjectIdentifiers.sha512WithRSAEncryption);

        RSA_SIG_ALGS.add(TeleTrusTObjectIdentifiers.teleTrusTRSAsignatureAlgorithm);

        RSA_SIG_ALGS.add(X509ObjectIdentifiers.id_ea_rsa);
    }

    boolean isRSASigAlg(AlgorithmIdentifier algId)
    {
        return RSA_SIG_ALGS.contains(algId.getAlgorithm());
    }

    AlgorithmIdentifier fixDigestAlgID(AlgorithmIdentifier algId, DigestAlgorithmIdentifierFinder dgstAlgFinder)
    {
        ASN1Encodable params = algId.getParameters();
        if (params == null || DERNull.INSTANCE.equals(params))
        {
            return dgstAlgFinder.find(algId.getAlgorithm());
        }
        else
        {
            return algId;
        }
    }

    void setSigningEncryptionAlgorithmMapping(ASN1ObjectIdentifier oid, String algorithmName)
    {
        if ("RSA".equals(algorithmName))
        {
            RSA_SIG_ALGS.add(oid);
        }
        else
        {
            RSA_SIG_ALGS.remove(oid);
        }
    }

    Store getCertificates(ASN1Set certSet)
    {
        if (certSet != null)
        {
            List certList = new ArrayList(certSet.size());

            for (Enumeration en = certSet.getObjects(); en.hasMoreElements();)
            {
                ASN1Primitive obj = ((ASN1Encodable)en.nextElement()).toASN1Primitive();

                if (obj instanceof ASN1Sequence)
                {
                    certList.add(new X509CertificateHolder(Certificate.getInstance(obj)));
                }
            }

            return new CollectionStore(certList);
        }

        return new CollectionStore(new ArrayList());
    }

    Store getAttributeCertificates(ASN1Set certSet)
    {
        if (certSet != null)
        {
            List certList = new ArrayList(certSet.size());

            for (Enumeration en = certSet.getObjects(); en.hasMoreElements();)
            {
                ASN1Primitive obj = ((ASN1Encodable)en.nextElement()).toASN1Primitive();

                if (obj instanceof ASN1TaggedObject)
                {
                    ASN1TaggedObject tObj = (ASN1TaggedObject)obj;

                    // CertificateChoices ::= CHOICE {
                    //     certificate Certificate,
                    //     extendedCertificate [0] IMPLICIT ExtendedCertificate,  -- Obsolete
                    //     v1AttrCert [1] IMPLICIT AttributeCertificateV1,        -- Obsolete
                    //     v2AttrCert [2] IMPLICIT AttributeCertificateV2,
                    //     other [3] IMPLICIT OtherCertificateFormat }
                    if (tObj.getTagNo() == 1 || tObj.getTagNo() == 2)
                    {
                        certList.add(new X509AttributeCertificateHolder(AttributeCertificate.getInstance(tObj.getBaseUniversal(false, BERTags.SEQUENCE))));
                    }
                }
            }

            return new CollectionStore(certList);
        }

        return new CollectionStore(new ArrayList());
    }

    Store getCRLs(ASN1Set crlSet)
    {
        if (crlSet != null)
        {
            List crlList = new ArrayList(crlSet.size());

            for (Enumeration en = crlSet.getObjects(); en.hasMoreElements();)
            {
                ASN1Primitive obj = ((ASN1Encodable)en.nextElement()).toASN1Primitive();

                if (obj instanceof ASN1Sequence)
                {
                    crlList.add(new X509CRLHolder(CertificateList.getInstance(obj)));
                }
            }

            return new CollectionStore(crlList);
        }

        return new CollectionStore(new ArrayList());
    }

    Store getOtherRevocationInfo(ASN1ObjectIdentifier otherRevocationInfoFormat, ASN1Set crlSet)
    {
        if (crlSet != null)
        {
            List    crlList = new ArrayList(crlSet.size());

            for (Enumeration en = crlSet.getObjects(); en.hasMoreElements();)
            {
                ASN1Primitive obj = ((ASN1Encodable)en.nextElement()).toASN1Primitive();

                if (obj instanceof ASN1TaggedObject)
                {
                    ASN1TaggedObject tObj = ASN1TaggedObject.getInstance(obj);

                    if (tObj.hasContextTag(1))
                    {
                        OtherRevocationInfoFormat other = OtherRevocationInfoFormat.getInstance(tObj, false);

                        if (otherRevocationInfoFormat.equals(other.getInfoFormat()))
                        {
                            crlList.add(other.getInfo());
                        }
                    }
                }
            }

            return new CollectionStore(crlList);
        }

        return new CollectionStore(new ArrayList());
    }
}
