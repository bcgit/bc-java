package org.bouncycastle.asn1.cms;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x509.CertificateList;

public class TimeStampAndCRL
    extends ASN1Object
{
    private ContentInfo timeStamp;
    private CertificateList crl;

    public TimeStampAndCRL(ContentInfo timeStamp)
    {
        this.timeStamp = timeStamp;
    }

    private TimeStampAndCRL(ASN1Sequence seq)
    {
        this.timeStamp = ContentInfo.getInstance(seq.getObjectAt(0));
        if (seq.size() == 2)
        {
            this.crl = CertificateList.getInstance(seq.getObjectAt(1));
        }
    }

    public static TimeStampAndCRL getInstance(Object obj)
    {
        if (obj instanceof TimeStampAndCRL)
        {
            return (TimeStampAndCRL)obj;
        }
        else if (obj != null)
        {
            return new TimeStampAndCRL(ASN1Sequence.getInstance(obj));
        }

        return null;
    }

    public ContentInfo getTimeStampToken()
    {
        return this.timeStamp;
    }

    /** @deprecated use getCRL() */
    public CertificateList getCertificateList()
    {
        return this.crl;
    }

    public CertificateList getCRL()
    {
        return this.crl;
    }

    /**
     * <pre>
     * TimeStampAndCRL ::= SEQUENCE {
     *     timeStamp   TimeStampToken,          -- according to RFC 3161
     *     crl         CertificateList OPTIONAL -- according to RFC 5280
     *  }
     * </pre>
     * @return
     */
    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector();

        v.add(timeStamp);

        if (crl != null)
        {
            v.add(crl);
        }

        return new DERSequence(v);
    }
}
