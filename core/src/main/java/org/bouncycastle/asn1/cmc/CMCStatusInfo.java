package org.bouncycastle.asn1.cmc;

import org.bouncycastle.asn1.ASN1Choice;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERUTF8String;

/**
 * <pre>
 * -- Used to return status state in a response
 *
 * id-cmc-statusInfo OBJECT IDENTIFIER ::= {id-cmc 1}
 *
 * CMCStatusInfo ::= SEQUENCE {
 *     cMCStatus       CMCStatus,
 *     bodyList        SEQUENCE SIZE (1..MAX) OF BodyPartID,
 *     statusString    UTF8String OPTIONAL,
 *     otherInfo        CHOICE {
 *       failInfo         CMCFailInfo,
 *       pendInfo         PendInfo } OPTIONAL
 * }
 * </pre>
 */
public class CMCStatusInfo
    extends ASN1Object
{
    private final CMCStatus cMCStatus;
    private final ASN1Sequence bodyList;
    private final DERUTF8String statusString;
    private final OtherInfo otherInfo;

    CMCStatusInfo(CMCStatus cMCStatus, ASN1Sequence bodyList, DERUTF8String statusString, OtherInfo otherInfo)
    {
        this.cMCStatus = cMCStatus;
        this.bodyList = bodyList;
        this.statusString = statusString;
        this.otherInfo = otherInfo;
    }

    private CMCStatusInfo(ASN1Sequence seq)
    {
        if (seq.size() < 2 || seq.size() > 4)
        {
            throw new IllegalArgumentException("incorrect sequence size");
        }
        this.cMCStatus = CMCStatus.getInstance(seq.getObjectAt(0));
        this.bodyList = ASN1Sequence.getInstance(seq.getObjectAt(1));

        if (seq.size() > 3)
        {
            this.statusString = DERUTF8String.getInstance(seq.getObjectAt(2));
            this.otherInfo = OtherInfo.getInstance(seq.getObjectAt(3));
        }
        else if (seq.size() > 2)
        {
            if (seq.getObjectAt(2) instanceof  DERUTF8String)
            {
                this.statusString = DERUTF8String.getInstance(seq.getObjectAt(2));
                this.otherInfo = null;
            }
            else
            {
                this.statusString = null;
                this.otherInfo = OtherInfo.getInstance(seq.getObjectAt(2));
            }
        }
        else
        {
            this.statusString = null;
            this.otherInfo = null;
        }
    }

    public static CMCStatusInfo getInstance(Object o)
    {
        if (o instanceof CMCStatusInfo)
        {
            return (CMCStatusInfo)o;
        }

        if (o != null)
        {
            return new CMCStatusInfo(ASN1Sequence.getInstance(o));
        }

        return null;
    }

    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector(4);
        v.add(cMCStatus);
        v.add(bodyList);
        if (statusString != null)
        {
            v.add(statusString);
        }
        if (otherInfo != null)
        {
            v.add(otherInfo);
        }
        return new DERSequence(v);
    }

    public CMCStatus getCMCStatus()
    {
        return cMCStatus;
    }

    public BodyPartID[] getBodyList()
    {
        return Utils.toBodyPartIDArray(bodyList);
    }

    public DERUTF8String getStatusString()
    {
        return statusString;
    }

    public boolean hasOtherInfo()
    {
        return otherInfo != null;
    }

    public OtherInfo getOtherInfo()
    {
        return otherInfo;
    }

    /**
     * Other info implements the choice component of CMCStatusInfo.
     */
    public static class OtherInfo
        extends ASN1Object
        implements ASN1Choice
    {
        private final CMCFailInfo failInfo;
        private final PendInfo pendInfo;

        private static OtherInfo getInstance(Object obj)
        {
            if (obj instanceof OtherInfo)
            {
                return (OtherInfo)obj;
            }

            if (obj instanceof ASN1Encodable)
            {
                ASN1Encodable asn1Value = ((ASN1Encodable)obj).toASN1Primitive();

                if (asn1Value instanceof ASN1Integer) // CMCFail info is an asn1 integer.
                {
                    return new OtherInfo(CMCFailInfo.getInstance(asn1Value));
                }
                else if (asn1Value instanceof ASN1Sequence) // PendInfo is a sequence.
                {
                    return new OtherInfo(PendInfo.getInstance(asn1Value));
                }
            }
            throw new IllegalArgumentException("unknown object in getInstance(): " + obj.getClass().getName());
        }

        OtherInfo(CMCFailInfo failInfo)
        {
            this(failInfo, null);
        }

        OtherInfo(PendInfo pendInfo)
        {
            this(null, pendInfo);
        }

        private OtherInfo(CMCFailInfo failInfo, PendInfo pendInfo)
        {
            this.failInfo = failInfo;
            this.pendInfo = pendInfo;
        }

        public boolean isFailInfo()
        {
            return failInfo != null;
        }

        public ASN1Primitive toASN1Primitive()
        {
            if (pendInfo != null)
            {
                return pendInfo.toASN1Primitive();
            }
            return failInfo.toASN1Primitive();
        }
    }
}
