package com.github.gv2011.bcasn.asn1.eac;

import java.math.BigInteger;

import com.github.gv2011.bcasn.asn1.ASN1Object;
import com.github.gv2011.bcasn.asn1.ASN1OctetString;
import com.github.gv2011.bcasn.asn1.ASN1Primitive;
import com.github.gv2011.bcasn.asn1.ASN1TaggedObject;
import com.github.gv2011.bcasn.asn1.DEROctetString;
import com.github.gv2011.bcasn.asn1.DERTaggedObject;

public class UnsignedInteger
    extends ASN1Object
{
    private int tagNo;
    private BigInteger value;

    public UnsignedInteger(int tagNo, BigInteger value)
    {
        this.tagNo = tagNo;
        this.value = value;
    }

    private UnsignedInteger(ASN1TaggedObject obj)
    {
        this.tagNo = obj.getTagNo();
        this.value = new BigInteger(1, ASN1OctetString.getInstance(obj, false).getOctets());
    }

    public static UnsignedInteger getInstance(Object obj)
    {
        if (obj instanceof  UnsignedInteger)
        {
            return (UnsignedInteger)obj;
        }
        if (obj != null)
        {
            return new UnsignedInteger(ASN1TaggedObject.getInstance(obj));
        }

        return null;
    }

    private byte[] convertValue()
    {
        byte[] v = value.toByteArray();

        if (v[0] == 0)
        {
            byte[] tmp = new byte[v.length - 1];

            System.arraycopy(v, 1, tmp, 0, tmp.length);

            return tmp;
        }

        return v;
    }

    public int getTagNo()
    {
        return tagNo;
    }

    public BigInteger getValue()
    {
        return value;
    }

    public ASN1Primitive toASN1Primitive()
    {
        return new DERTaggedObject(false, tagNo, new DEROctetString(convertValue()));
    }
}
