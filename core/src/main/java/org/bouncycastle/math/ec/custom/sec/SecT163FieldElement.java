package org.bouncycastle.math.ec.custom.sec;

import java.math.BigInteger;

import org.bouncycastle.math.ec.ECFieldElement;
import org.bouncycastle.math.raw.Nat192;
import org.bouncycastle.util.Arrays;

public class SecT163FieldElement extends ECFieldElement.AbstractF2m
{
    protected long[] x;

    public SecT163FieldElement(BigInteger x)
    {
        if (x == null || x.signum() < 0 || x.bitLength() > 163)
        {
            throw new IllegalArgumentException("x value invalid for SecT163FieldElement");
        }

        this.x = SecT163Field.fromBigInteger(x);
    }

    public SecT163FieldElement()
    {
        this.x = Nat192.create64();
    }

    protected SecT163FieldElement(long[] x)
    {
        this.x = x;
    }

//    public int bitLength()
//    {
//        return x.degree();
//    }

    public boolean isOne()
    {
        return Nat192.isOne64(x);
    }

    public boolean isZero()
    {
        return Nat192.isZero64(x);
    }

    public boolean testBitZero()
    {
        return (x[0] & 1L) != 0L;
    }

    public BigInteger toBigInteger()
    {
        return Nat192.toBigInteger64(x);
    }

    public String getFieldName()
    {
        return "SecT163Field";
    }

    public int getFieldSize()
    {
        return 163;
    }

    public ECFieldElement add(ECFieldElement b)
    {
        long[] z = Nat192.create64();
        SecT163Field.add(x, ((SecT163FieldElement)b).x, z);
        return new SecT163FieldElement(z);
    }

    public ECFieldElement addOne()
    {
        long[] z = Nat192.create64();
        SecT163Field.addOne(x, z);
        return new SecT163FieldElement(z);
    }

    public ECFieldElement subtract(ECFieldElement b)
    {
        // Addition and subtraction are the same in F2m
        return add(b);
    }

    public ECFieldElement multiply(ECFieldElement b)
    {
        long[] z = Nat192.create64();
        SecT163Field.multiply(x, ((SecT163FieldElement)b).x, z);
        return new SecT163FieldElement(z);
    }

    public ECFieldElement multiplyMinusProduct(ECFieldElement b, ECFieldElement x, ECFieldElement y)
    {
        return multiplyPlusProduct(b, x, y);
    }

    public ECFieldElement multiplyPlusProduct(ECFieldElement b, ECFieldElement x, ECFieldElement y)
    {
        long[] ax = this.x, bx = ((SecT163FieldElement)b).x;
        long[] xx = ((SecT163FieldElement)x).x, yx = ((SecT163FieldElement)y).x;

        long[] tt = Nat192.createExt64();
        SecT163Field.multiplyAddToExt(ax, bx, tt);
        SecT163Field.multiplyAddToExt(xx, yx, tt);

        long[] z = Nat192.create64();
        SecT163Field.reduce(tt, z);
        return new SecT163FieldElement(z);
    }

    public ECFieldElement divide(ECFieldElement b)
    {
        return multiply(b.invert());
    }

    public ECFieldElement negate()
    {
        return this;
    }

    public ECFieldElement square()
    {
        long[] z = Nat192.create64();
        SecT163Field.square(x, z);
        return new SecT163FieldElement(z);
    }

    public ECFieldElement squareMinusProduct(ECFieldElement x, ECFieldElement y)
    {
        return squarePlusProduct(x, y);
    }

    public ECFieldElement squarePlusProduct(ECFieldElement x, ECFieldElement y)
    {
        long[] ax = this.x;
        long[] xx = ((SecT163FieldElement)x).x, yx = ((SecT163FieldElement)y).x;

        long[] tt = Nat192.createExt64();
        SecT163Field.squareAddToExt(ax, tt);
        SecT163Field.multiplyAddToExt(xx, yx, tt);

        long[] z = Nat192.create64();
        SecT163Field.reduce(tt, z);
        return new SecT163FieldElement(z);
    }

    public ECFieldElement squarePow(int pow)
    {
        if (pow < 1)
        {
            return this;
        }

        long[] z = Nat192.create64();
        SecT163Field.squareN(x, pow, z);
        return new SecT163FieldElement(z);
    }

    public ECFieldElement halfTrace()
    {
        long[] z = Nat192.create64();
        SecT163Field.halfTrace(x, z);
        return new SecT163FieldElement(z); 
    }

    public boolean hasFastTrace()
    {
        return true;
    }

    public int trace()
    {
        return SecT163Field.trace(x);
    }

    public ECFieldElement invert()
    {
        long[] z = Nat192.create64();
        SecT163Field.invert(x, z);
        return new SecT163FieldElement(z);
    }

    public ECFieldElement sqrt()
    {
        long[] z = Nat192.create64();
        SecT163Field.sqrt(x, z);
        return new SecT163FieldElement(z);
    }

    public int getRepresentation()
    {
        return ECFieldElement.F2m.PPB;
    }

    public int getM()
    {
        return 163;
    }

    public int getK1()
    {
        return 3;
    }

    public int getK2()
    {
        return 6;
    }

    public int getK3()
    {
        return 7;
    }

    public boolean equals(Object other)
    {
        if (other == this)
        {
            return true;
        }

        if (!(other instanceof SecT163FieldElement))
        {
            return false;
        }

        SecT163FieldElement o = (SecT163FieldElement)other;
        return Nat192.eq64(x, o.x);
    }

    public int hashCode()
    {
        return 163763 ^ Arrays.hashCode(x, 0, 3);
    }
}
