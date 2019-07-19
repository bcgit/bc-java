package org.bouncycastle.math.ec.custom.sec;

import java.math.BigInteger;

import org.bouncycastle.math.ec.ECFieldElement;
import org.bouncycastle.math.raw.Nat;
import org.bouncycastle.math.raw.Nat320;
import org.bouncycastle.util.Arrays;

public class SecT283FieldElement extends ECFieldElement.AbstractF2m
{
    protected long[] x;

    public SecT283FieldElement(BigInteger x)
    {
        if (x == null || x.signum() < 0 || x.bitLength() > 283)
        {
            throw new IllegalArgumentException("x value invalid for SecT283FieldElement");
        }

        this.x = SecT283Field.fromBigInteger(x);
    }

    public SecT283FieldElement()
    {
        this.x = Nat320.create64();
    }

    protected SecT283FieldElement(long[] x)
    {
        this.x = x;
    }

//    public int bitLength()
//    {
//        return x.degree();
//    }

    public boolean isOne()
    {
        return Nat320.isOne64(x);
    }

    public boolean isZero()
    {
        return Nat320.isZero64(x);
    }

    public boolean testBitZero()
    {
        return (x[0] & 1L) != 0L;
    }

    public BigInteger toBigInteger()
    {
        return Nat320.toBigInteger64(x);
    }

    public String getFieldName()
    {
        return "SecT283Field";
    }

    public int getFieldSize()
    {
        return 283;
    }

    public ECFieldElement add(ECFieldElement b)
    {
        long[] z = Nat320.create64();
        SecT283Field.add(x, ((SecT283FieldElement)b).x, z);
        return new SecT283FieldElement(z);
    }

    public ECFieldElement addOne()
    {
        long[] z = Nat320.create64();
        SecT283Field.addOne(x, z);
        return new SecT283FieldElement(z);
    }

    public ECFieldElement subtract(ECFieldElement b)
    {
        // Addition and subtraction are the same in F2m
        return add(b);
    }

    public ECFieldElement multiply(ECFieldElement b)
    {
        long[] z = Nat320.create64();
        SecT283Field.multiply(x, ((SecT283FieldElement)b).x, z);
        return new SecT283FieldElement(z);
    }

    public ECFieldElement multiplyMinusProduct(ECFieldElement b, ECFieldElement x, ECFieldElement y)
    {
        return multiplyPlusProduct(b, x, y);
    }

    public ECFieldElement multiplyPlusProduct(ECFieldElement b, ECFieldElement x, ECFieldElement y)
    {
        long[] ax = this.x, bx = ((SecT283FieldElement)b).x;
        long[] xx = ((SecT283FieldElement)x).x, yx = ((SecT283FieldElement)y).x;

        long[] tt = Nat.create64(9);
        SecT283Field.multiplyAddToExt(ax, bx, tt);
        SecT283Field.multiplyAddToExt(xx, yx, tt);

        long[] z = Nat320.create64();
        SecT283Field.reduce(tt, z);
        return new SecT283FieldElement(z);
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
        long[] z = Nat320.create64();
        SecT283Field.square(x, z);
        return new SecT283FieldElement(z);
    }

    public ECFieldElement squareMinusProduct(ECFieldElement x, ECFieldElement y)
    {
        return squarePlusProduct(x, y);
    }

    public ECFieldElement squarePlusProduct(ECFieldElement x, ECFieldElement y)
    {
        long[] ax = this.x;
        long[] xx = ((SecT283FieldElement)x).x, yx = ((SecT283FieldElement)y).x;

        long[] tt = Nat.create64(9);
        SecT283Field.squareAddToExt(ax, tt);
        SecT283Field.multiplyAddToExt(xx, yx, tt);

        long[] z = Nat320.create64();
        SecT283Field.reduce(tt, z);
        return new SecT283FieldElement(z);
    }

    public ECFieldElement squarePow(int pow)
    {
        if (pow < 1)
        {
            return this;
        }

        long[] z = Nat320.create64();
        SecT283Field.squareN(x, pow, z);
        return new SecT283FieldElement(z);
    }

    public ECFieldElement halfTrace()
    {
        long[] z = Nat320.create64();
        SecT283Field.halfTrace(x, z);
        return new SecT283FieldElement(z); 
    }

    public boolean hasFastTrace()
    {
        return true;
    }

    public int trace()
    {
        return SecT283Field.trace(x);
    }

    public ECFieldElement invert()
    {
        long[] z = Nat320.create64();
        SecT283Field.invert(x, z);
        return new SecT283FieldElement(z);
    }

    public ECFieldElement sqrt()
    {
        long[] z = Nat320.create64();
        SecT283Field.sqrt(x, z);
        return new SecT283FieldElement(z);
    }

    public int getRepresentation()
    {
        return ECFieldElement.F2m.PPB;
    }

    public int getM()
    {
        return 283;
    }

    public int getK1()
    {
        return 5;
    }

    public int getK2()
    {
        return 7;
    }

    public int getK3()
    {
        return 12;
    }

    public boolean equals(Object other)
    {
        if (other == this)
        {
            return true;
        }

        if (!(other instanceof SecT283FieldElement))
        {
            return false;
        }

        SecT283FieldElement o = (SecT283FieldElement)other;
        return Nat320.eq64(x, o.x);
    }

    public int hashCode()
    {
        return 2831275 ^ Arrays.hashCode(x, 0, 5);
    }
}
