package org.bouncycastle.oer.its.ieee1609dot2;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;

/**
 * <pre>
 *     ToBeSignedData ::= SEQUENCE {
 *         payload SignedDataPayload,
 *         headerInfo HeaderInfo
 *     }
 * </pre>
 */
public class ToBeSignedData
    extends ASN1Object
{
    private final SignedDataPayload payload;
    private final HeaderInfo headerInfo;


    public ToBeSignedData(SignedDataPayload payload, HeaderInfo headerInfo)
    {
        this.payload = payload;
        this.headerInfo = headerInfo;
    }

    public static ToBeSignedData getInstance(Object o)
    {
        if (o instanceof ToBeSignedData)
        {
            return (ToBeSignedData)o;
        }

        ASN1Sequence seq = ASN1Sequence.getInstance(o);
        return new Builder()
            .setPayload(SignedDataPayload.getInstance(seq.getObjectAt(0)))
            .setHeaderInfo(HeaderInfo.getInstance(seq.getObjectAt(1)))
            .createToBeSignedData();
    }

    public SignedDataPayload getPayload()
    {
        return payload;
    }

    public HeaderInfo getHeaderInfo()
    {
        return headerInfo;
    }

    public ASN1Primitive toASN1Primitive()
    {
        return new DERSequence(new ASN1Encodable[]{payload, headerInfo});
    }

    public static class Builder
    {

        private SignedDataPayload payload;
        private HeaderInfo headerInfo;

        public Builder setPayload(SignedDataPayload payload)
        {
            this.payload = payload;
            return this;
        }

        public Builder setHeaderInfo(HeaderInfo headerInfo)
        {
            this.headerInfo = headerInfo;
            return this;
        }

        public ToBeSignedData createToBeSignedData()
        {
            return new ToBeSignedData(payload, headerInfo);
        }
    }

}