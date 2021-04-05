package org.bouncycastle.asn1.cmc;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERUTF8String;

/**
 * <pre>
 * --  Replaces CMC Status Info
 * --
 *
 * id-cmc-statusInfoV2 OBJECT IDENTIFIER ::= {id-cmc 25}
 *
 * CMCStatusInfoV2 ::= SEQUENCE {
 *  cMCStatus             CMCStatus,
 *  bodyList              SEQUENCE SIZE (1..MAX) OF BodyPartReference,
 *  statusString          UTF8String OPTIONAL,
 *  otherStatusInfo             OtherStatusInfo OPTIONAL
 * }
 *
 * OtherStatusInfo ::= CHOICE {
 *  failInfo              CMCFailInfo,
 *  pendInfo              PendInfo,
 *  extendedFailInfo      ExtendedFailInfo
 * }
 *
 * PendInfo ::= SEQUENCE {
 * pendToken           OCTET STRING,
 * pendTime            GeneralizedTime
 * }
 *
 * ExtendedFailInfo ::= SEQUENCE {
 * failInfoOID            OBJECT IDENTIFIER,
 * failInfoValue          ANY DEFINED BY failInfoOID
 * }
 * </pre>
 */
public class CMCStatusInfoV2
    extends ASN1Object
{
    private final CMCStatus cMCStatus;
    private final ASN1Sequence bodyList;
    private final DERUTF8String statusString;
    private final OtherStatusInfo otherStatusInfo;

    CMCStatusInfoV2(CMCStatus cMCStatus, ASN1Sequence bodyList, DERUTF8String statusString, OtherStatusInfo otherStatusInfo)
    {
        this.cMCStatus = cMCStatus;
        this.bodyList = bodyList;
        this.statusString = statusString;
        this.otherStatusInfo = otherStatusInfo;
    }

    private CMCStatusInfoV2(ASN1Sequence seq)
    {
        if (seq.size() < 2 || seq.size() > 4)
        {
            throw new IllegalArgumentException("incorrect sequence size");
        }
        this.cMCStatus = CMCStatus.getInstance(seq.getObjectAt(0));
        this.bodyList = ASN1Sequence.getInstance(seq.getObjectAt(1));

        if (seq.size() > 2)
        {
            if (seq.size() == 4)
            {
                this.statusString = DERUTF8String.getInstance(seq.getObjectAt(2));
                this.otherStatusInfo = OtherStatusInfo.getInstance(seq.getObjectAt(3));
            }
            else if (seq.getObjectAt(2) instanceof DERUTF8String)
            {
                this.statusString = DERUTF8String.getInstance(seq.getObjectAt(2));
                this.otherStatusInfo = null;
            }
            else
            {
                this.statusString = null;
                this.otherStatusInfo = OtherStatusInfo.getInstance(seq.getObjectAt(2));
            }
        }
        else
        {
            this.statusString = null;
            this.otherStatusInfo = null;
        }
    }


    public CMCStatus getcMCStatus()
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

    public OtherStatusInfo getOtherStatusInfo()
    {
        return otherStatusInfo;
    }

    public boolean hasOtherInfo()
    {
        return otherStatusInfo != null;
    }

    public static CMCStatusInfoV2 getInstance(Object o)
    {
        if (o instanceof CMCStatusInfoV2)
        {
            return (CMCStatusInfoV2)o;
        }

        if (o != null)
        {
            return new CMCStatusInfoV2(ASN1Sequence.getInstance(o));
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

        if (otherStatusInfo != null)
        {
            v.add(otherStatusInfo);
        }

        return new DERSequence(v);
    }
}
