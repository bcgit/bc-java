package org.bouncycastle.asn1.x509;

import org.bouncycastle.asn1.ASN1BitString;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.x500.X500Name;

/**
 * <pre>
 *     DeltaCertificateDescriptor ::= SEQUENCE {
 *      serialNumber          CertificateSerialNumber,
 *      signature             [0] IMPLICIT AlgorithmIdentifier
 *           {SIGNATURE_ALGORITHM, {...}} OPTIONAL,
 *      issuer                [1] IMPLICIT Name OPTIONAL,
 *      validity              [2] IMPLICIT Validity OPTIONAL,
 *      subject               [3] IMPLICIT Name OPTIONAL,
 *      subjectPublicKeyInfo  SubjectPublicKeyInfo,
 *      extensions            [4] IMPLICIT Extensions{CertExtensions}
 *           OPTIONAL,
 *      signatureValue        BIT STRING
 *    }
 *    </pre>
 */
public class DeltaCertificateDescriptor
    extends ASN1Object
{
    private final ASN1Integer serialNumber;

    private AlgorithmIdentifier signature;
    private X500Name issuer;
    private ASN1Sequence validity;
    private X500Name subject;
    private SubjectPublicKeyInfo subjectPublicKeyInfo;
    private Extensions extensions;

    private final ASN1BitString signatureValue;

    public static DeltaCertificateDescriptor getInstance(
        Object  obj)
    {
        if (obj instanceof DeltaCertificateDescriptor)
        {
            return (DeltaCertificateDescriptor)obj;
        }
        else if (obj != null)
        {
            return new DeltaCertificateDescriptor(ASN1Sequence.getInstance(obj));
        }

        return null;
    }

    /**
     * Retrieve a DeltaCertificateDescriptor for a passed in Extensions object, if present.
     *
     * @param extensions the extensions object to be examined.
     * @return  the DeltaCertificateDescriptor, null if the extension is not present.
     */
    public static DeltaCertificateDescriptor fromExtensions(Extensions extensions)
    {
        return getInstance(Extensions.getExtensionParsedValue(extensions, Extension.deltaCertificateDescriptor));
    }

    /**
     * Create a new trimmed descriptor based on the passed in base but using the extensions from newExtensions.
     *
     * @param base Base DeltaCertificateDescriptor
     * @param newExtensions extension to use with new descriptor (can be null)
     */
    DeltaCertificateDescriptor(DeltaCertificateDescriptor base, Extensions newExtensions)
    {
        this.serialNumber = base.serialNumber;
        this.signature = base.signature;
        this.issuer = base.issuer;
        this.validity = base.validity;
        this.subject = base.subject;
        this.subjectPublicKeyInfo = base.subjectPublicKeyInfo;
        this.extensions = newExtensions;
        this.signatureValue = base.signatureValue;
    }

    private DeltaCertificateDescriptor(ASN1Sequence seq)
    {
        this.serialNumber = ASN1Integer.getInstance(seq.getObjectAt(0));

        int idx = 1;
        ASN1Encodable next = seq.getObjectAt(idx);
        while (next instanceof ASN1TaggedObject)
        {
            ASN1TaggedObject tagged = ASN1TaggedObject.getInstance(next);
            switch (tagged.getTagNo())
            {
            case 0:
                signature = AlgorithmIdentifier.getInstance(tagged, false);
                break;
            case 1:
                issuer = X500Name.getInstance(tagged, true);   // issuer
                break;
            case 2:
                validity = ASN1Sequence.getInstance(tagged, false);
                break;
            case 3:
                subject = X500Name.getInstance(tagged, true);   // subject
                break;
            }
            next = seq.getObjectAt(idx++);
        }

        subjectPublicKeyInfo = subjectPublicKeyInfo.getInstance(next);

        next = seq.getObjectAt(idx);
        while (next instanceof ASN1TaggedObject)
        {
            ASN1TaggedObject tagged = ASN1TaggedObject.getInstance(next);
            switch (tagged.getTagNo())
            {
            case 4:
                extensions = Extensions.getInstance(tagged, false);   // subject
                break;
            }
            next = seq.getObjectAt(idx++);
        }

        signatureValue = ASN1BitString.getInstance(next);
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

    public ASN1Sequence getValidity()
    {
        return validity;
    }

    public X500Name getSubject()
    {
        return subject;
    }

    public SubjectPublicKeyInfo getSubjectPublicKeyInfo()
    {
        return subjectPublicKeyInfo;
    }

    public Extensions getExtensions()
    {
        return extensions;
    }

    public ASN1BitString getSignatureValue()
    {
        return signatureValue;
    }

    private void addOptional(ASN1EncodableVector v, int tag, boolean explicit, ASN1Object obj)
    {
        if (obj != null)
        {
             v.add(new DERTaggedObject(explicit, tag, obj));
        }
    }

    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector(7);

        v.add(serialNumber);
        addOptional(v, 0, false, signature);
        addOptional(v, 1, true, issuer); // CHOICE
        addOptional(v, 2, false, validity);
        addOptional(v, 3, true, subject);  // CHOICE
        v.add(subjectPublicKeyInfo);
        addOptional(v, 4, false, extensions);
        v.add(signatureValue);

        return new DERSequence(v);
    }
}
