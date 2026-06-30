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
 * The delta certificate request attribute defined in
 * <a href="https://datatracker.ietf.org/doc/draft-bonnell-lamps-chameleon-certs/">draft-bonnell-lamps-chameleon-certs</a>.
 * Carries the alternate subject, public key, optional extensions and optional signature
 * algorithm needed to derive the delta certificate request from the base PKCS#10 request.
 */
public class DeltaCertificateRequestAttributeValue
    implements ASN1Encodable
{
    private final X500Name subject;
    private final SubjectPublicKeyInfo subjectPKInfo;
    private final Extensions extensions;
    private final AlgorithmIdentifier signatureAlgorithm;
    private final ASN1Sequence attrSeq;

    /**
     * Construct from an {@link Attribute} whose first value is a DeltaCertificateRequest sequence.
     *
     * @param attribute the carrier attribute taken from a PKCS#10 request.
     */
    public DeltaCertificateRequestAttributeValue(Attribute attribute)
    {
        this(ASN1Sequence.getInstance(attribute.getAttributeValues()[0]));
    }

    /**
     * Coerce an object into a DeltaCertificateRequestAttributeValue.
     *
     * @param o either an existing instance, an ASN.1 sequence, or {@code null}.
     * @return the value, or {@code null} if {@code o} is null.
     */
    public static DeltaCertificateRequestAttributeValue getInstance(Object o)
    {
        if (o instanceof DeltaCertificateRequestAttributeValue)
        {
            return (DeltaCertificateRequestAttributeValue)o;
        }

        if (o != null)
        {
            return new DeltaCertificateRequestAttributeValue(ASN1Sequence.getInstance(o));
        }

        return null;
    }

    DeltaCertificateRequestAttributeValue(ASN1Sequence attrSeq)
    {
        this.attrSeq = attrSeq;

        if (attrSeq.size() == 0)
        {
            throw new IllegalArgumentException("DeltaCertificateRequest must contain a subjectPKInfo");
        }

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
                    ext = Extensions.getInstance(tagObj, true);
                }
                else if (tagObj.getTagNo() == 2)
                {
                    sigAlg = AlgorithmIdentifier.getInstance(tagObj, true);
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

    /**
     * Return the subject distinguished name, or {@code null} if the delta request reuses the
     * base request's subject.
     */
    public X500Name getSubject()
    {
        return subject;
    }

    /**
     * Return the alternate SubjectPublicKeyInfo carried by the delta request.
     */
    public SubjectPublicKeyInfo getSubjectPKInfo()
    {
        return subjectPKInfo;
    }

    /**
     * Return the extensions carried by the delta request, or {@code null} if none are present.
     */
    public Extensions getExtensions()
    {
        return extensions;
    }

    /**
     * Return the signature algorithm declared for the delta request's signature, or
     * {@code null} if the delta reuses the base request's signature algorithm.
     */
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
