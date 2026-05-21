package org.bouncycastle.cms;

import java.util.ArrayList;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.List;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.BERTags;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.cms.OtherRevocationInfoFormat;
import org.bouncycastle.asn1.eac.EACObjectIdentifiers;
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
import org.bouncycastle.util.Store;

class CMSSignedHelper
{
    static final CMSSignedHelper INSTANCE = new CMSSignedHelper();

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
