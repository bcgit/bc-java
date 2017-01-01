package org.bouncycastle.asn1.cmc;

import org.bouncycastle.asn1.ASN1EncodableVector;
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

    public CMCStatusInfo(ASN1Sequence seq)
    {
        this.cMCStatus = CMCStatus.getInstance(seq.getObjectAt(0));
        this.bodyList = ASN1Sequence.getInstance(seq.getObjectAt(1));
        this.statusString = DERUTF8String.getInstance(seq.getObjectAt(2));
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
        ASN1EncodableVector v = new ASN1EncodableVector();
          // TODO: not finished.
        v.add(cMCStatus);
        v.add(bodyList);
        v.add(statusString);

        return new DERSequence(v);
    }
}
