package org.bouncycastle.math.ec.custom.sec;

import java.math.BigInteger;

import org.bouncycastle.math.ec.ECFieldElement;
import org.bouncycastle.math.raw.Nat128;
import org.bouncycastle.util.Arrays;

public class SecT113FieldElement extends ECFieldElement.AbstractF2m
{
    protected long[] x;

    public SecT113FieldElement(BigInteger x)
    {
        if (x == null || x.signum() < 0 || x.bitLength() > 113)
        {
            throw new IllegalArgumentException("x value invalid for SecT113FieldElement");
        }

        this.x = SecT113Field.fromBigInteger(x);
    }

    public SecT113FieldElement()
    {
        this.x = Nat128.create64();
    }

    protected SecT113FieldElement(long[] x)
    {
        this.x = x;
    }

//    public int bitLength()
//    {
//        return x.degree();
//    }

    public boolean isOne()
    {
        return Nat128.isOne64(x);
    }

    public boolean isZero()
    {
        return Nat128.isZero64(x);
    }

    public boolean testBitZero()
    {
        return (x[0] & 1L) != 0L;
    }

    public BigInteger toBigInteger()
    {
        return Nat128.toBigInteger64(x);
    }

    public String getFieldName()
    {
        return "SecT113Field";
    }

    public int getFieldSize()
    {
        return 113;
    }

    public ECFieldElement add(ECFieldElement b)
    {
        long[] z = Nat128.create64();
        SecT113Field.add(x, ((SecT113FieldElement)b).x, z);
        return new SecT113FieldElement(z);
    }

    public ECFieldElement addOne()
    {
        long[] z = Nat128.create64();
        SecT113Field.addOne(x, z);
        return new SecT113FieldElement(z);
    }

    public ECFieldElement subtract(ECFieldElement b)
    {
        // Addition and subtraction are the same in F2m
        return add(b);
    }

    public ECFieldElement multiply(ECFieldElement b)
    {
        long[] z = Nat128.create64();
        SecT113Field.multiply(x, ((SecT113FieldElement)b).x, z);
        return new SecT113FieldElement(z);
    }

    public ECFieldElement multiplyMinusProduct(ECFieldElement b, ECFieldElement x, ECFieldElement y)
    {
        return multiplyPlusProduct(b, x, y);
    }

    public ECFieldElement multiplyPlusProduct(ECFieldElement b, ECFieldElement x, ECFieldElement y)
    {
        long[] ax = this.x, bx = ((SecT113FieldElement)b).x;
        long[] xx = ((SecT113FieldElement)x).x, yx = ((SecT113FieldElement)y).x;

        long[] tt = Nat128.createExt64();
        SecT113Field.multiplyAddToExt(ax, bx, tt);
        SecT113Field.multiplyAddToExt(xx, yx, tt);

        long[] z = Nat128.create64();
        SecT113Field.reduce(tt, z);
        return new SecT113FieldElement(z);
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
        long[] z = Nat128.create64();
        SecT113Field.square(x, z);
        return new SecT113FieldElement(z);
    }

    public ECFieldElement squareMinusProduct(ECFieldElement x, ECFieldElement y)
    {
        return squarePlusProduct(x, y);
    }

    public ECFieldElement squarePlusProduct(ECFieldElement x, ECFieldElement y)
    {
        long[] ax = this.x;
        long[] xx = ((SecT113FieldElement)x).x, yx = ((SecT113FieldElement)y).x;

        long[] tt = Nat128.createExt64();
        SecT113Field.squareAddToExt(ax, tt);
        SecT113Field.multiplyAddToExt(xx, yx, tt);

        long[] z = Nat128.create64();
        SecT113Field.reduce(tt, z);
        return new SecT113FieldElement(z);
    }

    public ECFieldElement squarePow(int pow)
    {
        if (pow < 1)
        {
            return this;
        }

        long[] z = Nat128.create64();
        SecT113Field.squareN(x, pow, z);
        return new SecT113FieldElement(z);
    }

    public ECFieldElement halfTrace()
    {
        long[] z = Nat128.create64();
        SecT113Field.halfTrace(x, z);
        return new SecT113FieldElement(z); 
    }

    public boolean hasFastTrace()
    {
        return true;
    }

    public int trace()
    {
        return SecT113Field.trace(x);
    }

    public ECFieldElement invert()
    {
        long[] z = Nat128.create64();
        SecT113Field.invert(x, z);
        return new SecT113FieldElement(z);
    }

    public ECFieldElement sqrt()
    {
        long[] z = Nat128.create64();
        SecT113Field.sqrt(x, z);
        return new SecT113FieldElement(z);
    }

    public int getRepresentation()
    {
        return ECFieldElement.F2m.TPB;
    }

    public int getM()
    {
        return 113;
    }

    public int getK1()
    {
        return 9;
    }

    public int getK2()
    {
        return 0;
    }

    public int getK3()
    {
        return 0;
    }

    public boolean equals(Object other)
    {
        if (other == this)
        {
            return true;
        }

        if (!(other instanceof SecT113FieldElement))
        {
            return false;
        }

        SecT113FieldElement o = (SecT113FieldElement)other;
        return Nat128.eq64(x, o.x);
    }

    public int hashCode()
    {
        return 113009 ^ Arrays.hashCode(x, 0, 2);
    }
}
