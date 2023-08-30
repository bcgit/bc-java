package org.bouncycastle.pkcs;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.pkcs.Attribute;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;

/**
 * The delta certificate request attribute defined in: https://datatracker.ietf.org/doc/draft-bonnell-lamps-chameleon-certs/
 */
public class DeltaCertificateRequestAttributeValue
    implements ASN1Encodable
{
    private final X500Name subject;
    private final SubjectPublicKeyInfo subjectPKInfo;
    private final Extensions extensions;
    private final AlgorithmIdentifier signatureAlgorithm;
    private final ASN1Sequence attrSeq;

    public DeltaCertificateRequestAttributeValue(Attribute attribute)
    {
        this(ASN1Sequence.getInstance(attribute.getAttributeValues()[0]));
    }

    DeltaCertificateRequestAttributeValue(ASN1Sequence attrSeq)
    {
        this.attrSeq = attrSeq;
        // TODO: validate attribute size

        int idx = 0;
        if (attrSeq.getObjectAt(0) instanceof ASN1TaggedObject)
        {
            subject = X500Name.getInstance(ASN1TaggedObject.getInstance(attrSeq.getObjectAt(0)), true);
            idx++;
        }
        else
        {
            subject = null;
        }

        subjectPKInfo = SubjectPublicKeyInfo.getInstance(attrSeq.getObjectAt(idx));
        idx++;

        Extensions ext = null;
        AlgorithmIdentifier sigAlg = null;

        if (idx != attrSeq.size())
        {
            while (idx < attrSeq.size())
            {
                ASN1TaggedObject tagObj = ASN1TaggedObject.getInstance(attrSeq.getObjectAt(idx));
                if (tagObj.getTagNo() == 1)
                {
                    ext = Extensions.getInstance(tagObj, false);
                }
                else if (tagObj.getTagNo() == 2)
                {
                    sigAlg = AlgorithmIdentifier.getInstance(tagObj, false);
                }
                else
                {
                    throw new IllegalArgumentException("unknown tag");
                }
                idx++;
            }
        }

        this.extensions = ext;
        this.signatureAlgorithm = sigAlg;
    }

    public X500Name getSubject()
    {
        return subject;
    }

    public SubjectPublicKeyInfo getSubjectPKInfo()
    {
        return subjectPKInfo;
    }

    public Extensions getExtensions()
    {
        return extensions;
    }

    public AlgorithmIdentifier getSignatureAlgorithm()
    {
        return signatureAlgorithm;
    }

    @Override
    public ASN1Primitive toASN1Primitive()
    {
        return attrSeq;
    }
}
