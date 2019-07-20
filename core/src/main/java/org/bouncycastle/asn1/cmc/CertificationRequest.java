package org.bouncycastle.asn1.cmc;

import java.io.IOException;
import java.math.BigInteger;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;

/**
 * <pre>
 *   CertificationRequest ::= SEQUENCE {
 *     certificationRequestInfo  SEQUENCE {
 *       version                   INTEGER,
 *       subject                   Name,
 *       subjectPublicKeyInfo      SEQUENCE {
 *          algorithm                 AlgorithmIdentifier,
 *          subjectPublicKey          BIT STRING },
 *       attributes                [0] IMPLICIT SET OF Attribute },
 *    signatureAlgorithm        AlgorithmIdentifier,
 *    signature                 BIT STRING
 *  }
 * </pre>
 */
public class CertificationRequest
    extends ASN1Object
{
    private static final ASN1Integer ZERO = new ASN1Integer(0);

    private final CertificationRequestInfo certificationRequestInfo;
    private final AlgorithmIdentifier signatureAlgorithm;
    private final DERBitString signature;

    public CertificationRequest(
        X500Name                subject,
        AlgorithmIdentifier     subjectPublicAlgorithm,
        DERBitString            subjectPublicKey,
        ASN1Set                 attributes,
        AlgorithmIdentifier     signatureAlgorithm,
        DERBitString            signature)
    {
        this.certificationRequestInfo = new CertificationRequestInfo(subject, subjectPublicAlgorithm, subjectPublicKey, attributes);
        this.signatureAlgorithm = signatureAlgorithm;
        this.signature = signature;
    }

    private CertificationRequest(ASN1Sequence seq)
    {
        if (seq.size() != 3)
        {
            throw new IllegalArgumentException("incorrect sequence size");
        }
        this.certificationRequestInfo = new CertificationRequestInfo(ASN1Sequence.getInstance(seq.getObjectAt(0)));
        this.signatureAlgorithm = AlgorithmIdentifier.getInstance(seq.getObjectAt(1));
        this.signature = DERBitString.getInstance(seq.getObjectAt(2));
    }

    public static CertificationRequest getInstance(Object o)
    {
        if (o instanceof CertificationRequest)
        {
            return (CertificationRequest)o;
        }

        if (o != null)
        {
            return new CertificationRequest(ASN1Sequence.getInstance(o));
        }

        return null;
    }

    public BigInteger getVersion()
    {
        return certificationRequestInfo.getVersion().getValue();
    }

    public X500Name getSubject()
    {
        return certificationRequestInfo.getSubject();
    }

    public ASN1Set getAttributes()
    {
        return certificationRequestInfo.getAttributes();
    }

    public AlgorithmIdentifier getSubjectPublicKeyAlgorithm()
    {
        return AlgorithmIdentifier.getInstance(certificationRequestInfo.getSubjectPublicKeyInfo().getObjectAt(0));
    }

    public DERBitString getSubjectPublicKey()
    {
        return DERBitString.getInstance(certificationRequestInfo.getSubjectPublicKeyInfo().getObjectAt(1));
    }

    /**
     * If the public key is an encoded object this will return the ASN.1 primitives encoded - if the bitstring
     * can't be decoded this routine throws an IOException.
     *
     * @exception IOException - if the bit string doesn't represent a DER encoded object.
     * @return the public key as an ASN.1 primitive.
     */
    public ASN1Primitive parsePublicKey()
        throws IOException
    {
        return ASN1Primitive.fromByteArray(getSubjectPublicKey().getOctets());
    }

    public AlgorithmIdentifier getSignatureAlgorithm()
    {
        return signatureAlgorithm;
    }

    public DERBitString getSignature()
    {
        return signature;
    }

    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector(3);

        v.add(certificationRequestInfo);
        v.add(signatureAlgorithm);
        v.add(signature);

        return new DERSequence(v);
    }

    private class CertificationRequestInfo
        extends ASN1Object
    {
        private final ASN1Integer version;
        private final X500Name subject;
        private final ASN1Sequence subjectPublicKeyInfo;
        private final ASN1Set attributes;

        private CertificationRequestInfo(
            ASN1Sequence  seq)
        {
            if (seq.size() != 4)
            {
                throw new IllegalArgumentException("incorrect sequence size for CertificationRequestInfo");
            }
            version = ASN1Integer.getInstance(seq.getObjectAt(0));

            subject = X500Name.getInstance(seq.getObjectAt(1));
            subjectPublicKeyInfo = ASN1Sequence.getInstance(seq.getObjectAt(2));
            if (subjectPublicKeyInfo.size() != 2)
            {
                throw new IllegalArgumentException("incorrect subjectPublicKeyInfo size for CertificationRequestInfo");
            }

            ASN1TaggedObject tagobj = (ASN1TaggedObject)seq.getObjectAt(3);
            if (tagobj.getTagNo() != 0)
            {
                throw new IllegalArgumentException("incorrect tag number on attributes for CertificationRequestInfo");
            }
            attributes = ASN1Set.getInstance(tagobj, false);
        }

        private CertificationRequestInfo(X500Name subject, AlgorithmIdentifier algorithm, DERBitString subjectPublicKey, ASN1Set attributes)
        {
            this.version = ZERO;
            this.subject = subject;
            this.subjectPublicKeyInfo = new DERSequence(new ASN1Encodable[] { algorithm, subjectPublicKey });
            this.attributes = attributes;
        }

        private ASN1Integer getVersion()
        {
            return version;
        }

        private X500Name getSubject()
        {
            return subject;
        }

        private ASN1Sequence getSubjectPublicKeyInfo()
        {
            return subjectPublicKeyInfo;
        }

        private ASN1Set getAttributes()
        {
            return attributes;
        }

        public ASN1Primitive toASN1Primitive()
        {
            ASN1EncodableVector v = new ASN1EncodableVector(4);

            v.add(version);
            v.add(subject);
            v.add(subjectPublicKeyInfo);
            v.add(new DERTaggedObject(false, 0, attributes));

            return new DERSequence(v);
        }
    }
}
