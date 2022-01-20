package org.bouncycastle.oer.its.ieee1609dot2.basetypes;

import java.math.BigInteger;

import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;

public abstract class UintBase
    extends ASN1Object
{

    protected final BigInteger value;

    public UintBase(BigInteger value)
    {
        this.value = value;
        assertLimit();
    }

    public UintBase(int value)
    {
        this(BigInteger.valueOf(value));
    }

    public UintBase(long value)
    {
        this(BigInteger.valueOf(value));
    }

    protected UintBase(ASN1Integer integer)
    {
        this(integer.getValue());
    }


    public BigInteger getValue()
    {
        return value;
    }


    @Override
    public ASN1Primitive toASN1Primitive()
    {
        return new ASN1Integer(value);
    }

    protected abstract void assertLimit();
}
