package org.bouncycastle.asn1.pkcs;

import java.util.Enumeration;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.X509Name;

/**
 * PKCS10 CertificationRequestInfo object.
 * <pre>
 *  CertificationRequestInfo ::= SEQUENCE {
 *   version             INTEGER { v1(0) } (v1,...),
 *   subject             Name,
 *   subjectPKInfo   SubjectPublicKeyInfo{{ PKInfoAlgorithms }},
 *   attributes          [0] Attributes{{ CRIAttributes }}
 *  }
 *
 *  Attributes { ATTRIBUTE:IOSet } ::= SET OF Attribute{{ IOSet }}
 *
 *  Attribute { ATTRIBUTE:IOSet } ::= SEQUENCE {
 *    type    ATTRIBUTE.&amp;id({IOSet}),
 *    values  SET SIZE(1..MAX) OF ATTRIBUTE.&amp;Type({IOSet}{\@type})
 *  }
 * </pre>
 */
public class CertificationRequestInfo
    extends ASN1Object
{
    ASN1Integer              version = new ASN1Integer(0);
    X500Name                subject;
    SubjectPublicKeyInfo    subjectPKInfo;
    ASN1Set                 attributes = null;

    public static CertificationRequestInfo getInstance(
        Object  obj)
    {
        if (obj instanceof CertificationRequestInfo)
        {
            return (CertificationRequestInfo)obj;
        }
        else if (obj != null)
        {
            return new CertificationRequestInfo(ASN1Sequence.getInstance(obj));
        }

        return null;
    }

    /**
     * Basic constructor.
     * <p>
     * Note: Early on a lot of CAs would only accept messages with attributes missing. As the ASN.1 def shows
     * the attributes field is not optional so should always at least contain an empty set. If a fully compliant
     * request is required, pass in an empty set, the class will otherwise interpret a null as it should
     * encode the request with the field missing.
     * </p>
     *
     * @param subject subject to be associated with the public key
     * @param pkInfo public key to be associated with subject
     * @param attributes any attributes to be associated with the request.
     */
    public CertificationRequestInfo(
        X500Name                subject,
        SubjectPublicKeyInfo    pkInfo,
        ASN1Set                 attributes)
    {
        if ((subject == null) || (pkInfo == null))
        {
            throw new IllegalArgumentException("Not all mandatory fields set in CertificationRequestInfo generator.");
        }

        validateAttributes(attributes);

        this.subject = subject;
        this.subjectPKInfo = pkInfo;
        this.attributes = attributes;
    }

    /**
     * @deprecated use X500Name method.
     */
    public CertificationRequestInfo(
        X509Name                subject,
        SubjectPublicKeyInfo    pkInfo,
        ASN1Set                 attributes)
    {
        this(X500Name.getInstance(subject.toASN1Primitive()), pkInfo, attributes);
    }

    /**
     * @deprecated use getInstance().
     */
    public CertificationRequestInfo(
        ASN1Sequence  seq)
    {
        version = (ASN1Integer)seq.getObjectAt(0);

        subject = X500Name.getInstance(seq.getObjectAt(1));
        subjectPKInfo = SubjectPublicKeyInfo.getInstance(seq.getObjectAt(2));

        //
        // some CertificationRequestInfo objects seem to treat this field
        // as optional.
        //
        if (seq.size() > 3)
        {
            ASN1TaggedObject tagobj = (ASN1TaggedObject)seq.getObjectAt(3);
            attributes = ASN1Set.getInstance(tagobj, false);
        }

        validateAttributes(attributes);

        if ((subject == null) || (version == null) || (subjectPKInfo == null))
        {
            throw new IllegalArgumentException("Not all mandatory fields set in CertificationRequestInfo generator.");
        }
    }

    public ASN1Integer getVersion()
    {
        return version;
    }

    public X500Name getSubject()
    {
        return subject;
    }

    public SubjectPublicKeyInfo getSubjectPublicKeyInfo()
    {
        return subjectPKInfo;
    }

    public ASN1Set getAttributes()
    {
        return attributes;
    }

    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector(4);

        v.add(version);
        v.add(subject);
        v.add(subjectPKInfo);

        if (attributes != null)
        {
            v.add(new DERTaggedObject(false, 0, attributes));
        }

        return new DERSequence(v);
    }

    private static void validateAttributes(ASN1Set attributes)
    {
        if (attributes == null)
        {
            return;
        }

        for (Enumeration en = attributes.getObjects(); en.hasMoreElements();)
        {
            Attribute attr = Attribute.getInstance(en.nextElement());
            if (attr.getAttrType().equals(PKCSObjectIdentifiers.pkcs_9_at_challengePassword))
            {
                if (attr.getAttrValues().size() != 1)
                {
                    throw new IllegalArgumentException("challengePassword attribute must have one value");
                }
            }
        }
    }
}
