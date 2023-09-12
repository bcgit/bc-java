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
                extensions = Extensions.getInstance(tagged, false); 
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

    public DeltaCertificateDescriptor trimTo(TBSCertificate baseTbsCertificate, Extensions tbsExtensions)
    {
        AlgorithmIdentifier signature = baseTbsCertificate.signature;
        X500Name issuer = baseTbsCertificate.issuer;
        ASN1Sequence validity = new DERSequence(new ASN1Encodable[]
        {
            baseTbsCertificate.startDate, baseTbsCertificate.endDate
        });
        X500Name subject = baseTbsCertificate.subject;
        ASN1Sequence s = ASN1Sequence.getInstance(toASN1Primitive());
        ASN1EncodableVector v = new ASN1EncodableVector();

        Enumeration en = s.getObjects();
        v.add((ASN1Encodable)en.nextElement());

        ASN1Encodable next = (ASN1Encodable)en.nextElement();
        while (next instanceof ASN1TaggedObject)
        {
            ASN1TaggedObject tagged = ASN1TaggedObject.getInstance(next);
            switch (tagged.getTagNo())
            {
            case 0:
                AlgorithmIdentifier sig = AlgorithmIdentifier.getInstance(tagged, false);
                if (!sig.equals(signature))
                {
                    v.add(next);
                }
                break;
            case 1:
                X500Name iss = X500Name.getInstance(tagged, true);   // issuer
                if (!iss.equals(issuer))
                {
                    v.add(next);
                }
                break;
            case 2:
                ASN1Sequence val = ASN1Sequence.getInstance(tagged, false);
                if (!val.equals(validity))
                {
                    v.add(next);
                }
                break;
            case 3:
                X500Name sub = X500Name.getInstance(tagged, true);   // subject
                if (!sub.equals(subject))
                {
                    v.add(next);
                }
                break;
            }
            next = (ASN1Encodable)en.nextElement();
        }

        v.add(next);

        next = (ASN1Encodable)en.nextElement();
        while (next instanceof ASN1TaggedObject)
        {
            ASN1TaggedObject tagged = ASN1TaggedObject.getInstance(next);
            switch (tagged.getTagNo())
            {
            case 4:
                Extensions deltaExts = Extensions.getInstance(tagged, false);
                ExtensionsGenerator deltaExtGen = new ExtensionsGenerator();
                for (Enumeration extEn = deltaExts.oids(); extEn.hasMoreElements(); )
                {
                    Extension deltaExt = deltaExts.getExtension((ASN1ObjectIdentifier)extEn.nextElement());
                    Extension primaryExt = tbsExtensions.getExtension(deltaExt.getExtnId());

                    if (primaryExt != null)
                    {
                        if (!deltaExt.equals(primaryExt))
                        {
                            deltaExtGen.addExtension(deltaExt);
                        }
                    }
                }

                DeltaCertificateDescriptor trimmedDeltaCertDesc;
                if (!deltaExtGen.isEmpty())
                {
                    v.add(new DERTaggedObject(false, 4, deltaExtGen.generate()));
                }
            }
            next = (ASN1Encodable)en.nextElement();
        }

        v.add(next);

        return new DeltaCertificateDescriptor(new DERSequence(v));
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
