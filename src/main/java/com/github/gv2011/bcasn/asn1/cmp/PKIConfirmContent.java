package com.github.gv2011.bcasn.asn1.cmp;

import com.github.gv2011.bcasn.asn1.ASN1Null;
import com.github.gv2011.bcasn.asn1.ASN1Object;
import com.github.gv2011.bcasn.asn1.ASN1Primitive;
import com.github.gv2011.bcasn.asn1.DERNull;

public class PKIConfirmContent
    extends ASN1Object
{
    private ASN1Null val;

    private PKIConfirmContent(ASN1Null val)
    {
        this.val = val;
    }

    public static PKIConfirmContent getInstance(Object o)
    {
        if (o == null || o instanceof PKIConfirmContent)
        {
            return (PKIConfirmContent)o;
        }

        if (o instanceof ASN1Null)
        {
            return new PKIConfirmContent((ASN1Null)o);
        }

        throw new IllegalArgumentException("Invalid object: " + o.getClass().getName());
    }

    public PKIConfirmContent()
    {
        val = DERNull.INSTANCE;
    }

    /**
     * <pre>
     * PKIConfirmContent ::= NULL
     * </pre>
     * @return a basic ASN.1 object representation.
     */
    public ASN1Primitive toASN1Primitive()
    {
        return val;
    }
}
