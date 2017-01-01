package org.bouncycastle.asn1.cmc;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;

/**
 * <pre>
 * --  Replaces CMC Status Info
 * --
 *
 * id-cmc-statusInfoV2 OBJECT IDENTIFIER ::= {id-cmc 25}
 *
 * CMCStatusInfoV2 ::= SEQUENCE {
 *    cMCStatus             CMCStatus,
 *    bodyList              SEQUENCE SIZE (1..MAX) OF
 *                                         BodyPartReference,
 *    statusString          UTF8String OPTIONAL,
 *    otherInfo             CHOICE {
 *          failInfo               CMCFailInfo,
 *          pendInfo               PendInfo,
 *          extendedFailInfo       SEQUENCE {
 *              failInfoOID            OBJECT IDENTIFIER,
 *              failInfoValue          AttributeValue
 *          }
 *    } OPTIONAL
 * }
 * </pre>
 */
public class CMCStatusInfoV2
    extends ASN1Object
{
    private final AlgorithmIdentifier cMCStatus;
    private final ASN1Sequence bodyList;
    private final DERUTF8String statusString;
    private final ASN1Encodable otherInfo;

    private CMCStatusInfoV2(ASN1Sequence seq)
    {
        if (seq.size() < 2 || seq.size() > 4)
        {
            throw new IllegalArgumentException("incorrect sequence size");
        }
        this.cMCStatus = AlgorithmIdentifier.getInstance(seq.getObjectAt(0));
        this.bodyList = ASN1Sequence.getInstance(seq.getObjectAt(1));

        if (seq.size() > 2)
        {
            if (seq.size() == 4)
            {
                this.statusString = DERUTF8String.getInstance(seq.getObjectAt(2));
                this.otherInfo = seq.getObjectAt(3);
            }
            else if (seq.getObjectAt(2) instanceof DERUTF8String)
            {
                this.statusString = DERUTF8String.getInstance(seq.getObjectAt(2));
                this.otherInfo = null;
            }
            else
            {
                this.statusString = null;
                this.otherInfo = seq.getObjectAt(2);
            }
        }
        else
        {
            this.statusString = null;
            this.otherInfo = null;
        }
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
        ASN1EncodableVector v = new ASN1EncodableVector();

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
}
