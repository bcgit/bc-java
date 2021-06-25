package org.bouncycastle.asn1.ocsp;

import java.util.Enumeration;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1GeneralizedTime;
import org.bouncycastle.asn1.ASN1IA5String;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;

public class CrlID
    extends ASN1Object
{
    private ASN1IA5String        crlUrl;
    private ASN1Integer          crlNum;
    private ASN1GeneralizedTime  crlTime;

    private CrlID(
        ASN1Sequence    seq)
    {
        Enumeration    e = seq.getObjects();

        while (e.hasMoreElements())
        {
            ASN1TaggedObject    o = (ASN1TaggedObject)e.nextElement();

            switch (o.getTagNo())
            {
            case 0:
                crlUrl = ASN1IA5String.getInstance(o, true);
                break;
            case 1:
                crlNum = ASN1Integer.getInstance(o, true);
                break;
            case 2:
                crlTime = ASN1GeneralizedTime.getInstance(o, true);
                break;
            default:
                throw new IllegalArgumentException(
                        "unknown tag number: " + o.getTagNo());
            }
        }
    }

    public static CrlID getInstance(
        Object  obj)
    {
        if (obj instanceof CrlID)
        {
            return (CrlID)obj;
        }
        else if (obj != null)
        {
            return new CrlID(ASN1Sequence.getInstance(obj));
        }

        return null;
    }

    /**
     * @deprecated Use {@link #getCrlUrlIA5()} instead.
     */
    public DERIA5String getCrlUrl()
    {
        return null == crlUrl || crlUrl instanceof DERIA5String
            ?   (DERIA5String)crlUrl
            :   new DERIA5String(crlUrl.getString(), false);
    }

    public ASN1IA5String getCrlUrlIA5()
    {
        return crlUrl;
    }

    public ASN1Integer getCrlNum()
    {
        return crlNum;
    }

    public ASN1GeneralizedTime getCrlTime()
    {
        return crlTime;
    }

    /**
     * Produce an object suitable for an ASN1OutputStream.
     * <pre>
     * CrlID ::= SEQUENCE {
     *     crlUrl               [0]     EXPLICIT IA5String OPTIONAL,
     *     crlNum               [1]     EXPLICIT INTEGER OPTIONAL,
     *     crlTime              [2]     EXPLICIT GeneralizedTime OPTIONAL }
     * </pre>
     */
    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector(3);

        if (crlUrl != null)
        {
            v.add(new DERTaggedObject(true, 0, crlUrl));
        }

        if (crlNum != null)
        {
            v.add(new DERTaggedObject(true, 1, crlNum));
        }

        if (crlTime != null)
        {
            v.add(new DERTaggedObject(true, 2, crlTime));
        }

        return new DERSequence(v);
    }
}
