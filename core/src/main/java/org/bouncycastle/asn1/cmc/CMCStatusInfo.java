package org.bouncycastle.asn1.cmc;

import java.io.IOException;

import org.bouncycastle.asn1.ASN1Choice;
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

    public CMCStatusInfo(CMCStatus cMCStatus, ASN1Sequence bodyList, DERUTF8String statusString)
    {
        this.cMCStatus = cMCStatus;
        this.bodyList = bodyList;
        this.statusString = statusString;
        this.otherInfo = null;
    }

    public CMCStatusInfo(CMCStatus cMCStatus, ASN1Sequence bodyList, DERUTF8String statusString, OtherInfo otherInfo)
    {
        this.cMCStatus = cMCStatus;
        this.bodyList = bodyList;
        this.statusString = statusString;
        this.otherInfo = otherInfo;
    }

    /**
     * Create from ASN1Sequence.
     * @param seq The source sequence.
     */
    public CMCStatusInfo(ASN1Sequence seq)
    {
        this.cMCStatus = CMCStatus.getInstance(seq.getObjectAt(0));
        this.bodyList = ASN1Sequence.getInstance(seq.getObjectAt(1));
        this.statusString = DERUTF8String.getInstance(seq.getObjectAt(2));
        if (seq.size()>3) {
            otherInfo = OtherInfo.getInstance(seq.getObjectAt(3));
        } else {
            otherInfo = null;
        }
    }

    public static CMCStatusInfo getInstance(Object o)
    {
        if (o instanceof CMCStatusInfo)
        {
            return (CMCStatusInfo)o;
        }

        if (o != null) {
            return new CMCStatusInfo(ASN1Sequence.getInstance(o));
        }

        return null;
    }

    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(cMCStatus);
        v.add(bodyList);
        v.add(statusString);
        if (otherInfo != null) {
            v.add(otherInfo);
        }
        return new DERSequence(v);
    }

    public boolean hasOtherInfo() {
        return otherInfo != null;
    }

    public CMCStatus getcMCStatus()
    {
        return cMCStatus;
    }

    public ASN1Sequence getBodyList()
    {
        return bodyList;
    }

    public DERUTF8String getStatusString()
    {
        return statusString;
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


        public static OtherInfo getInstance(Object obj)
        {
            if (obj instanceof OtherInfo)
            {
                return (OtherInfo)obj;
            }

            if (obj instanceof CMCFailInfo)
            {
                return new OtherInfo((CMCFailInfo)obj, null);
            }
            else if (obj instanceof PendInfo)
            {
                return new OtherInfo(null, (PendInfo)obj);
            }
            else if (obj instanceof ASN1Integer) // CMCFail info is an asn1 integer.
            {
                return getInstance(CMCFailInfo.getInstance(obj));
            }
            else if (obj instanceof ASN1Sequence) // PendInfo is a sequence.
            {
                return getInstance(PendInfo.getInstance(obj));
            }
            else if (obj instanceof byte[])
            {
                try
                {
                    return getInstance(ASN1Primitive.fromByteArray((byte[])obj));
                }
                catch (IOException e)
                {
                    throw new IllegalArgumentException("unknown encoding in getInstance()");
                }
            }
            throw new IllegalArgumentException("unknown object in getInstance(): " + obj.getClass().getName());
        }

        private OtherInfo(CMCFailInfo failInfo, PendInfo pendInfo)
        {
            this.failInfo = failInfo;
            this.pendInfo = pendInfo;
        }

        public boolean isFailInfo() {
            return failInfo != null;
        }

        public byte[] getEncoded()
            throws IOException
        {
            if (pendInfo!= null) {
                return pendInfo.getEncoded();
            }
            return failInfo.getEncoded();
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
