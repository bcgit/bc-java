package org.bouncycastle.asn1.x509;

import java.util.Enumeration;

import org.bouncycastle.asn1.ASN1BitString;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.x500.X500Name;

/**
 * <pre>
 * DeltaCertificateDescriptor ::= SEQUENCE {
 *   serialNumber          CertificateSerialNumber,
 *   signature             [0] EXPLICIT AlgorithmIdentifier {SIGNATURE_ALGORITHM, {...}} OPTIONAL,
 *   issuer                [1] EXPLICIT Name OPTIONAL,
 *   validity              [2] EXPLICIT Validity OPTIONAL,
 *   subject               [3] EXPLICIT Name OPTIONAL,
 *   subjectPublicKeyInfo  SubjectPublicKeyInfo,
 *   extensions            [4] EXPLICIT Extensions{CertExtensions} OPTIONAL,
 *   signatureValue        BIT STRING
 * }
 * </pre>
 */
public class DeltaCertificateDescriptor
    extends ASN1Object
{
    private final ASN1Integer serialNumber;
    private final AlgorithmIdentifier signature;
    private final X500Name issuer;
    private final Validity validity;
    private final X500Name subject;
    private final SubjectPublicKeyInfo subjectPublicKeyInfo;
    private final Extensions extensions;
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

    private DeltaCertificateDescriptor(ASN1Sequence seq)
    {
        ASN1Integer serialNumber = ASN1Integer.getInstance(seq.getObjectAt(0));

        int idx = 1;
        ASN1Encodable next = seq.getObjectAt(idx++);

        AlgorithmIdentifier signature = null;
        X500Name issuer = null;
        Validity validity = null;
        X500Name subject = null;
        while (next instanceof ASN1TaggedObject)
        {
            ASN1TaggedObject tagged = ASN1TaggedObject.getInstance(next);
            switch (tagged.getTagNo())
            {
            case 0:
                signature = AlgorithmIdentifier.getInstance(tagged, true);
                break;
            case 1:
                issuer = X500Name.getInstance(tagged, true);   // issuer
                break;
            case 2:
                validity = Validity.getInstance(tagged, true);
                break;
            case 3:
                subject = X500Name.getInstance(tagged, true);   // subject
                break;
            }
            next = seq.getObjectAt(idx++);
        }

        SubjectPublicKeyInfo subjectPublicKeyInfo = SubjectPublicKeyInfo.getInstance(next);

        next = seq.getObjectAt(idx);

        Extensions extensions = null;
        while (next instanceof ASN1TaggedObject)
        {
            ASN1TaggedObject tagged = ASN1TaggedObject.getInstance(next);
            switch (tagged.getTagNo())
            {
            case 4:
                extensions = Extensions.getInstance(tagged, true);
                break;
            }
            next = seq.getObjectAt(idx++);
        }

        ASN1BitString signatureValue = ASN1BitString.getInstance(next);

        this.serialNumber = serialNumber;
        this.signature = signature;
        this.issuer = issuer;
        this.validity = validity;
        this.subject = subject;
        this.subjectPublicKeyInfo = subjectPublicKeyInfo;
        this.extensions = extensions;
        this.signatureValue = signatureValue;
    }

    public DeltaCertificateDescriptor(ASN1Integer serialNumber, AlgorithmIdentifier signature, X500Name issuer,
        Validity validity, X500Name subject, SubjectPublicKeyInfo subjectPublicKeyInfo, Extensions extensions,
        ASN1BitString signatureValue)
    {
        if (serialNumber == null)
        {
            throw new NullPointerException("'serialNumber' cannot be null");
        }
        if (subjectPublicKeyInfo == null)
        {
            throw new NullPointerException("'subjectPublicKeyInfo' cannot be null");
        }
        if (signatureValue == null)
        {
            throw new NullPointerException("'signatureValue' cannot be null");
        }

        this.serialNumber = serialNumber;
        this.signature = signature;
        this.issuer = issuer;
        this.validity = validity;
        this.subject = subject;
        this.subjectPublicKeyInfo = subjectPublicKeyInfo;
        this.extensions = extensions;
        this.signatureValue = signatureValue;
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

    /** @deprecated Use getValidityObject instead. */
    public ASN1Sequence getValidity()
    {
        return (ASN1Sequence)validity.toASN1Primitive();
    }

    public Validity getValidityObject()
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

    /** @deprecated Use DeltaCertificateTool#trimDeltaCertificateDescriptor instead. */
    public DeltaCertificateDescriptor trimTo(TBSCertificate baseTbsCertificate, Extensions tbsExtensions)
    {
        return trimDeltaCertificateDescriptor(this, baseTbsCertificate, tbsExtensions);
    }

    // NB: This can replace DeltaCertificateTool#trimDeltaCertificateDescriptor once 'trimTo' is removed
    private static DeltaCertificateDescriptor trimDeltaCertificateDescriptor(DeltaCertificateDescriptor descriptor,
        TBSCertificate tbsCertificate, Extensions tbsExtensions)
    {
        ASN1Integer serialNumber = descriptor.getSerialNumber();

        AlgorithmIdentifier signature = descriptor.getSignature();
        if (signature != null && signature.equals(tbsCertificate.getSignature()))
        {
            signature = null;
        }

        X500Name issuer = descriptor.getIssuer();
        if (issuer != null && issuer.equals(tbsCertificate.getIssuer()))
        {
            issuer = null;
        }

        Validity validity = descriptor.getValidityObject();
        if (validity != null && validity.equals(tbsCertificate.getValidity()))
        {
            validity = null;
        }

        X500Name subject = descriptor.getSubject();
        if (subject != null && subject.equals(tbsCertificate.getSubject()))
        {
            subject = null;
        }

        SubjectPublicKeyInfo subjectPublicKeyInfo = descriptor.getSubjectPublicKeyInfo();

        Extensions extensions = descriptor.getExtensions();
        if (extensions != null)
        {
            /*
             * draft-bonnell-lamps-chameleon-certs-05 4.1:
             *
             * [The extensions] field MUST NOT contain any extension:
             * - which has the same criticality and DER-encoded value as encoded in the Base Certificate,
             * - whose type does not appear in the Base Certificate, or
             * - which is of the DCD extension type (recursive Delta Certificates are not permitted).
             * 
             * [...] The ordering of extensions in [the extensions] field MUST be relative to the ordering of the
             * extensions as they are encoded in the Delta [recte Base] Certificate.
             */

            ExtensionsGenerator generator = new ExtensionsGenerator();

            for (Enumeration extEn = tbsExtensions.oids(); extEn.hasMoreElements();)
            {
                ASN1ObjectIdentifier oid = (ASN1ObjectIdentifier)extEn.nextElement();
                if (Extension.deltaCertificateDescriptor.equals(oid))
                {
                    continue;
                }

                Extension deltaExtension = extensions.getExtension(oid);
                if (deltaExtension != null && !deltaExtension.equals(tbsExtensions.getExtension(oid)))
                {
                    generator.addExtension(deltaExtension);
                }
            }

            extensions = generator.isEmpty() ? null : generator.generate();
        }

        ASN1BitString signatureValue = descriptor.getSignatureValue();

        return new DeltaCertificateDescriptor(serialNumber, signature, issuer, validity, subject,
            subjectPublicKeyInfo, extensions, signatureValue);
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
        ASN1EncodableVector v = new ASN1EncodableVector(8);

        v.add(serialNumber);
        addOptional(v, 0, true, signature);
        addOptional(v, 1, true, issuer); // CHOICE
        addOptional(v, 2, true, validity);
        addOptional(v, 3, true, subject);  // CHOICE
        v.add(subjectPublicKeyInfo);
        addOptional(v, 4, true, extensions);
        v.add(signatureValue);

        return new DERSequence(v);
    }
}
