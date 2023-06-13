package org.bouncycastle.asn1.cmp;

import java.math.BigInteger;

import org.bouncycastle.asn1.ASN1BitString;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERSequence;

/**
 *  PKIStatusInfo ::= SEQUENCE {
 *          status        PKIStatus,
 *          statusString  PKIFreeText     OPTIONAL,
 *          failInfo      PKIFailureInfo  OPTIONAL
 *      }
 */
public class PKIStatusInfo
    extends ASN1Object
{
    ASN1Integer status;
    PKIFreeText statusString;
    ASN1BitString failInfo;

    private PKIStatusInfo(
        ASN1Sequence seq)
    {
        this.status = ASN1Integer.getInstance(seq.getObjectAt(0));

        this.statusString = null;
        this.failInfo = null;

        if (seq.size() > 2)
        {
            this.statusString = PKIFreeText.getInstance(seq.getObjectAt(1));
            this.failInfo = ASN1BitString.getInstance(seq.getObjectAt(2));
        }
        else if (seq.size() > 1)
        {
            Object obj = seq.getObjectAt(1);
            if (obj instanceof ASN1BitString)
            {
                this.failInfo = ASN1BitString.getInstance(obj);
            }
            else
            {
                this.statusString = PKIFreeText.getInstance(obj);
            }
        }
    }

    /**
     * @param status
     */
    public PKIStatusInfo(PKIStatus status)
    {
        this.status = ASN1Integer.getInstance(status.toASN1Primitive());
    }

    /**
     * @param status
     * @param statusString
     */
    public PKIStatusInfo(
        PKIStatus status,
        PKIFreeText statusString)
    {
        this.status = ASN1Integer.getInstance(status.toASN1Primitive());
        this.statusString = statusString;
    }

    public PKIStatusInfo(
        PKIStatus status,
        PKIFreeText statusString,
        PKIFailureInfo failInfo)
    {
        this.status = ASN1Integer.getInstance(status.toASN1Primitive());
        this.statusString = statusString;
        this.failInfo = failInfo;
    }

    public static PKIStatusInfo getInstance(
        ASN1TaggedObject obj,
        boolean explicit)
    {
        return getInstance(ASN1Sequence.getInstance(obj, explicit));
    }

    public static PKIStatusInfo getInstance(
        Object obj)
    {
        if (obj instanceof PKIStatusInfo)
        {
            return (PKIStatusInfo)obj;
        }
        else if (obj != null)
        {
            return new PKIStatusInfo(ASN1Sequence.getInstance(obj));
        }

        return null;
    }

    public BigInteger getStatus()
    {
        return status.getValue();
    }

    public PKIFreeText getStatusString()
    {
        return statusString;
    }

    public ASN1BitString getFailInfo()
    {
        return failInfo;
    }

    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector(3);

        v.add(status);

        if (statusString != null)
        {
            v.add(statusString);
        }

        if (failInfo != null)
        {
            v.add(failInfo);
        }

        return new DERSequence(v);
    }
}
