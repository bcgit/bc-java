package com.github.gv2011.bcasn.asn1.tsp;

import java.util.Enumeration;

import com.github.gv2011.bcasn.asn1.ASN1EncodableVector;
import com.github.gv2011.bcasn.asn1.ASN1Object;
import com.github.gv2011.bcasn.asn1.ASN1Primitive;
import com.github.gv2011.bcasn.asn1.ASN1Sequence;
import com.github.gv2011.bcasn.asn1.DERSequence;
import com.github.gv2011.bcasn.asn1.cmp.PKIStatusInfo;
import com.github.gv2011.bcasn.asn1.cms.ContentInfo;


public class TimeStampResp
    extends ASN1Object
{
    PKIStatusInfo pkiStatusInfo;

    ContentInfo timeStampToken;

    public static TimeStampResp getInstance(Object o)
    {
        if (o instanceof TimeStampResp)
        {
            return (TimeStampResp) o;
        }
        else if (o != null)
        {
            return new TimeStampResp(ASN1Sequence.getInstance(o));
        }

        return null;
    }

    private TimeStampResp(ASN1Sequence seq)
    {

        Enumeration e = seq.getObjects();

        // status
        pkiStatusInfo = PKIStatusInfo.getInstance(e.nextElement());

        if (e.hasMoreElements())
        {
            timeStampToken = ContentInfo.getInstance(e.nextElement());
        }
    }

    public TimeStampResp(PKIStatusInfo pkiStatusInfo, ContentInfo timeStampToken)
    {
        this.pkiStatusInfo = pkiStatusInfo;
        this.timeStampToken = timeStampToken;
    }

    public PKIStatusInfo getStatus()
    {
        return pkiStatusInfo;
    }

    public ContentInfo getTimeStampToken()
    {
        return timeStampToken;
    }

    /**
     * <pre>
     * TimeStampResp ::= SEQUENCE  {
     *   status                  PKIStatusInfo,
     *   timeStampToken          TimeStampToken     OPTIONAL  }
     * </pre>
     */
    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector();
        
        v.add(pkiStatusInfo);
        if (timeStampToken != null)
        {
            v.add(timeStampToken);
        }

        return new DERSequence(v);
    }
}
