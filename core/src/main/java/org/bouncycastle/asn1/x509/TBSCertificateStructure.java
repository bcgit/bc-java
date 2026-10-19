package org.bouncycastle.asn1.x509;

import org.bouncycastle.asn1.ASN1BitString;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.BERTags;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;

/**
 * The TBSCertificate object.
 * <pre>
 * TBSCertificate ::= SEQUENCE {
 *      version          [ 0 ]  Version DEFAULT v1(0),
 *      serialNumber            CertificateSerialNumber,
 *      signature               AlgorithmIdentifier,
 *      issuer                  Name,
 *      validity                Validity,
 *      subject                 Name,
 *      subjectPublicKeyInfo    SubjectPublicKeyInfo,
 *      issuerUniqueID    [ 1 ] IMPLICIT UniqueIdentifier OPTIONAL,
 *      subjectUniqueID   [ 2 ] IMPLICIT UniqueIdentifier OPTIONAL,
 *      extensions        [ 3 ] Extensions OPTIONAL
 *      }
 * </pre>
 * <p>
 * Note: issuerUniqueID and subjectUniqueID are both deprecated by the IETF. This class
 * will parse them, but you really shouldn't be creating new ones.
 * @deprecated use TBSCertificate
 */
public class TBSCertificateStructure
    extends ASN1Object
    implements X509ObjectIdentifiers, PKCSObjectIdentifiers
{
    ASN1Sequence            seq;

    ASN1Integer             version;
    ASN1Integer             serialNumber;
    AlgorithmIdentifier     signature;
    X500Name                issuer;
    Validity                validity;
    X500Name                subject;
    SubjectPublicKeyInfo    subjectPublicKeyInfo;
    ASN1BitString           issuerUniqueId;
    ASN1BitString           subjectUniqueId;
    X509Extensions          extensions;

    public static TBSCertificateStructure getInstance(
        ASN1TaggedObject obj,
        boolean          explicit)
    {
        return getInstance(ASN1Sequence.getInstance(obj, explicit));
    }

    public static TBSCertificateStructure getInstance(
        Object  obj)
    {
        if (obj instanceof TBSCertificateStructure)
        {
            return (TBSCertificateStructure)obj;
        }
        else if (obj != null)
        {
            return new TBSCertificateStructure(ASN1Sequence.getInstance(obj));
        }

        return null;
    }

    public TBSCertificateStructure(
        ASN1Sequence  seq)
    {
        int         seqStart = 0;

        this.seq = seq;

        //
        // some certficates don't include a version number - we assume v1
        //
        if (seq.getObjectAt(0) instanceof ASN1TaggedObject)
        {
            version = ASN1Integer.getInstance((ASN1TaggedObject)seq.getObjectAt(0), true);
        }
        else
        {
            seqStart = -1;          // field 0 is missing!
            version = ASN1Integer.ZERO;
        }

        serialNumber = ASN1Integer.getInstance(seq.getObjectAt(seqStart + 1));

        signature = AlgorithmIdentifier.getInstance(seq.getObjectAt(seqStart + 2));
        issuer = X500Name.getInstance(seq.getObjectAt(seqStart + 3));
        validity = Validity.getInstance(seq.getObjectAt(seqStart + 4));
        subject = X500Name.getInstance(seq.getObjectAt(seqStart + 5));
        subjectPublicKeyInfo = SubjectPublicKeyInfo.getInstance(seq.getObjectAt(seqStart + 6));

        // issuerUniqueID [1], subjectUniqueID [2] and extensions [3], each at most once and in that order
        int lastTagNo = 0;
        for (int pos = seqStart + 7; pos < seq.size(); pos++)
        {
            ASN1TaggedObject extra = ASN1TaggedObject.getInstance(seq.getObjectAt(pos), BERTags.CONTEXT_SPECIFIC);
            if (extra.getTagNo() <= lastTagNo)
            {
                throw new IllegalArgumentException("tag [" + extra.getTagNo() + "] repeated or out of order");
            }
            lastTagNo = extra.getTagNo();

            switch (extra.getTagNo())
            {
            case 1:
                issuerUniqueId = ASN1BitString.getInstance(extra, false);
                break;
            case 2:
                subjectUniqueId = ASN1BitString.getInstance(extra, false);
                break;
            case 3:
                extensions = X509Extensions.getInstance(extra);
                break;
            default:
                throw new IllegalArgumentException("unknown tag encountered: " + extra.getTagNo());
            }
        }
    }

    public int getVersion()
    {
        return version.intValueExact() + 1;
    }

    public ASN1Integer getVersionNumber()
    {
        return version;
    }

    public ASN1Integer getSerialNumber()
    {
        return serialNumber;
    }

    public AlgorithmIdentifier getSignature()
    {
        return signature;
    }

    public X500Name getIssuer()
    {
        return issuer;
    }

    public Validity getValidity()
    {
        return validity;
    }

    public Time getStartDate()
    {
        return validity.getNotBefore();
    }

    public Time getEndDate()
    {
        return validity.getNotAfter();
    }

    public X500Name getSubject()
    {
        return subject;
    }

    public SubjectPublicKeyInfo getSubjectPublicKeyInfo()
    {
        return subjectPublicKeyInfo;
    }

    public ASN1BitString getIssuerUniqueId()
    {
        return issuerUniqueId;
    }

    public ASN1BitString getSubjectUniqueId()
    {
        return subjectUniqueId;
    }

    public X509Extensions getExtensions()
    {
        return extensions;
    }

    public ASN1Primitive toASN1Primitive()
    {
        return seq;
    }
}
