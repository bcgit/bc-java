package org.bouncycastle.asn1.x509;

import org.bouncycastle.asn1.ASN1BitString;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.x500.X500Name;

/**
 * Represents the ASN.1 structure TBSCertificateLogEntry.
 * <p>
 * TBSCertificateLogEntry ::= SEQUENCE {
 * version               [0] EXPLICIT Version DEFAULT v1,
 * issuer                    Name,
 * validity                  Validity,
 * subject                   Name,
 * subjectPublicKeyAlgorithm AlgorithmIdentifier,
 * subjectPublicKeyInfoHash  OCTET STRING,
 * issuerUniqueID        [1] IMPLICIT UniqueIdentifier OPTIONAL,
 * subjectUniqueID       [2] IMPLICIT UniqueIdentifier OPTIONAL,
 * extensions            [3] EXPLICIT Extensions OPTIONAL
 * }
 * <p>
 * This structure is similar to the TBSCertificate defined in
 * {@link org.bouncycastle.asn1.x509.TBSCertificate}, but replaces the
 * SubjectPublicKeyInfo with a hash of the SubjectPublicKeyInfo.
 */
public class TBSCertificateLogEntry
    extends ASN1Object
{
    private ASN1Integer version;
    private X500Name issuer;
    private Validity validity;
    private X500Name subject;
    private AlgorithmIdentifier subjectPublicKeyAlgorithm;
    private ASN1OctetString subjectPublicKeyInfoHash;

    private ASN1BitString issuerUniqueID;
    private ASN1BitString subjectUniqueID;
    private Extensions extensions;

    public static TBSCertificateLogEntry getInstance(Object obj)
    {
        if (obj instanceof TBSCertificateLogEntry)
        {
            return (TBSCertificateLogEntry)obj;
        }
        else if (obj != null)
        {
            return new TBSCertificateLogEntry(ASN1Sequence.getInstance(obj));
        }

        return null;
    }

    private TBSCertificateLogEntry(ASN1Sequence seq)
    {
        int index = 0;

        ASN1Encodable current = seq.getObjectAt(index);

        if (current instanceof ASN1TaggedObject)
        {
            ASN1TaggedObject tagged = ASN1TaggedObject.getInstance(current);
            if (tagged.getTagNo() == 0)
            {
                version = ASN1Integer.getInstance(tagged, true);
                index++;
            }
        }

        if (version == null)
        {
            version = new ASN1Integer(0); // v1 default
        }

        issuer = X500Name.getInstance(seq.getObjectAt(index++));
        validity = Validity.getInstance(seq.getObjectAt(index++));
        subject = X500Name.getInstance(seq.getObjectAt(index++));
        subjectPublicKeyAlgorithm = AlgorithmIdentifier.getInstance(seq.getObjectAt(index++));
        subjectPublicKeyInfoHash = ASN1OctetString.getInstance(seq.getObjectAt(index++));

        while (index < seq.size())
        {
            ASN1TaggedObject tagged = ASN1TaggedObject.getInstance(seq.getObjectAt(index++));

            switch (tagged.getTagNo())
            {
            case 1:
                issuerUniqueID = ASN1BitString.getInstance(tagged, false);
                break;
            case 2:
                subjectUniqueID = ASN1BitString.getInstance(tagged, false);
                break;
            case 3:
                extensions = Extensions.getInstance(tagged, true);
                break;
            default:
                throw new IllegalArgumentException("Unknown tag in TBSCertificateLogEntry: " + tagged.getTagNo());
            }
        }
    }

    /**
     * Convenience constructor that mirrors the per-entry fields of an existing
     * {@link TBSCertificate}, substituting the SubjectPublicKeyInfo with the
     * supplied hash. Version, issuer, validity, subject, the public-key
     * algorithm, unique IDs and extensions are copied from {@code tbsCert};
     * the serial number and outer signature algorithm carried by the
     * TBSCertificate are intentionally not represented here.
     *
     * @param tbsCert TBSCertificate to copy the shared fields from.
     * @param subjectPublicKeyInfoHash hash of the encoded SubjectPublicKeyInfo.
     */
    public TBSCertificateLogEntry(TBSCertificate tbsCert, byte[] subjectPublicKeyInfoHash)
    {
        this(
            tbsCert.getVersion(),
            tbsCert.getIssuer(),
            tbsCert.getValidity(),
            tbsCert.getSubject(),
            tbsCert.getSubjectPublicKeyInfo().getAlgorithm(),
            new DEROctetString(subjectPublicKeyInfoHash),
            tbsCert.getIssuerUniqueId(),
            tbsCert.getSubjectUniqueId(),
            tbsCert.getExtensions());
    }

    public TBSCertificateLogEntry(
        ASN1Integer version,
        X500Name issuer,
        Validity validity,
        X500Name subject,
        AlgorithmIdentifier subjectPublicKeyAlgorithm,
        ASN1OctetString subjectPublicKeyInfoHash,
        ASN1BitString issuerUniqueID,
        ASN1BitString subjectUniqueID,
        Extensions extensions)
    {
        this.version = version;
        this.issuer = issuer;
        this.validity = validity;
        this.subject = subject;
        this.subjectPublicKeyAlgorithm = subjectPublicKeyAlgorithm;
        this.subjectPublicKeyInfoHash = subjectPublicKeyInfoHash;
        this.issuerUniqueID = issuerUniqueID;
        this.subjectUniqueID = subjectUniqueID;
        this.extensions = extensions;
    }

    public ASN1Integer getVersion()
    {
        return version;
    }

    public X500Name getIssuer()
    {
        return issuer;
    }

    public Validity getValidity()
    {
        return validity;
    }

    public X500Name getSubject()
    {
        return subject;
    }

    public AlgorithmIdentifier getSubjectPublicKeyAlgorithm()
    {
        return subjectPublicKeyAlgorithm;
    }

    public ASN1OctetString getSubjectPublicKeyInfoHash()
    {
        return subjectPublicKeyInfoHash;
    }

    public ASN1BitString getIssuerUniqueID()
    {
        return issuerUniqueID;
    }

    public ASN1BitString getSubjectUniqueID()
    {
        return subjectUniqueID;
    }

    public Extensions getExtensions()
    {
        return extensions;
    }

    @Override
    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector(9);

        if (!version.hasValue(0))
        {
            v.add(new DERTaggedObject(true, 0, version));
        }

        v.add(issuer);
        v.add(validity);
        v.add(subject);
        v.add(subjectPublicKeyAlgorithm);
        v.add(subjectPublicKeyInfoHash);

        if (issuerUniqueID != null)
        {
            v.add(new DERTaggedObject(false, 1, issuerUniqueID));
        }

        if (subjectUniqueID != null)
        {
            v.add(new DERTaggedObject(false, 2, subjectUniqueID));
        }

        if (extensions != null)
        {
            v.add(new DERTaggedObject(true, 3, extensions));
        }

        return new DERSequence(v);
    }
}
