package org.bouncycastle.asn1.crmf;

import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;

public class SubsequentMessage
    extends ASN1Object
{
    public static final SubsequentMessage encrCert = new SubsequentMessage(0);
    public static final SubsequentMessage challengeResp = new SubsequentMessage(1);

    private final ASN1Integer value;

    private SubsequentMessage(int value)
    {
        this.value = new ASN1Integer(value);
    }

    public static SubsequentMessage valueOf(int value)
    {
        if (value == 0)
        {
            return encrCert;
        }
        if (value == 1)
        {
            return challengeResp;
        }

        throw new IllegalArgumentException("unknown value: " + value);
    }

    public ASN1Primitive toASN1Primitive()
    {
        return value;
    }
}
