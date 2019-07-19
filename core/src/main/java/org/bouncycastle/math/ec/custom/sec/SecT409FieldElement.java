package org.bouncycastle.math.ec.custom.sec;

import java.math.BigInteger;

import org.bouncycastle.math.ec.ECFieldElement;
import org.bouncycastle.math.raw.Nat;
import org.bouncycastle.math.raw.Nat448;
import org.bouncycastle.util.Arrays;

public class SecT409FieldElement extends ECFieldElement.AbstractF2m
{
    protected long[] x;

    public SecT409FieldElement(BigInteger x)
    {
        if (x == null || x.signum() < 0 || x.bitLength() > 409)
        {
            throw new IllegalArgumentException("x value invalid for SecT409FieldElement");
        }

        this.x = SecT409Field.fromBigInteger(x);
    }

    public SecT409FieldElement()
    {
        this.x = Nat448.create64();
    }

    protected SecT409FieldElement(long[] x)
    {
        this.x = x;
    }

//    public int bitLength()
//    {
//        return x.degree();
//    }

    public boolean isOne()
    {
        return Nat448.isOne64(x);
    }

    public boolean isZero()
    {
        return Nat448.isZero64(x);
    }

    public boolean testBitZero()
    {
        return (x[0] & 1L) != 0L;
    }

    public BigInteger toBigInteger()
    {
        return Nat448.toBigInteger64(x);
    }

    public String getFieldName()
    {
        return "SecT409Field";
    }

    public int getFieldSize()
    {
        return 409;
    }

    public ECFieldElement add(ECFieldElement b)
    {
        long[] z = Nat448.create64();
        SecT409Field.add(x, ((SecT409FieldElement)b).x, z);
        return new SecT409FieldElement(z);
    }

    public ECFieldElement addOne()
    {
        long[] z = Nat448.create64();
        SecT409Field.addOne(x, z);
        return new SecT409FieldElement(z);
    }

    public ECFieldElement subtract(ECFieldElement b)
    {
        // Addition and subtraction are the same in F2m
        return add(b);
    }

    public ECFieldElement multiply(ECFieldElement b)
    {
        long[] z = Nat448.create64();
        SecT409Field.multiply(x, ((SecT409FieldElement)b).x, z);
        return new SecT409FieldElement(z);
    }

    public ECFieldElement multiplyMinusProduct(ECFieldElement b, ECFieldElement x, ECFieldElement y)
    {
        return multiplyPlusProduct(b, x, y);
    }

    public ECFieldElement multiplyPlusProduct(ECFieldElement b, ECFieldElement x, ECFieldElement y)
    {
        long[] ax = this.x, bx = ((SecT409FieldElement)b).x;
        long[] xx = ((SecT409FieldElement)x).x, yx = ((SecT409FieldElement)y).x;

        long[] tt = Nat.create64(13);
        SecT409Field.multiplyAddToExt(ax, bx, tt);
        SecT409Field.multiplyAddToExt(xx, yx, tt);

        long[] z = Nat448.create64();
        SecT409Field.reduce(tt, z);
        return new SecT409FieldElement(z);
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
        long[] z = Nat448.create64();
        SecT409Field.square(x, z);
        return new SecT409FieldElement(z);
    }

    public ECFieldElement squareMinusProduct(ECFieldElement x, ECFieldElement y)
    {
        return squarePlusProduct(x, y);
    }

    public ECFieldElement squarePlusProduct(ECFieldElement x, ECFieldElement y)
    {
        long[] ax = this.x;
        long[] xx = ((SecT409FieldElement)x).x, yx = ((SecT409FieldElement)y).x;

        long[] tt = Nat.create64(13);
        SecT409Field.squareAddToExt(ax, tt);
        SecT409Field.multiplyAddToExt(xx, yx, tt);

        long[] z = Nat448.create64();
        SecT409Field.reduce(tt, z);
        return new SecT409FieldElement(z);
    }

    public ECFieldElement squarePow(int pow)
    {
        if (pow < 1)
        {
            return this;
        }

        long[] z = Nat448.create64();
        SecT409Field.squareN(x, pow, z);
        return new SecT409FieldElement(z);
    }

    public ECFieldElement halfTrace()
    {
        long[] z = Nat448.create64();
        SecT409Field.halfTrace(x, z);
        return new SecT409FieldElement(z); 
    }

    public boolean hasFastTrace()
    {
        return true;
    }

    public int trace()
    {
        return SecT409Field.trace(x);
    }

    public ECFieldElement invert()
    {
        long[] z = Nat448.create64();
        SecT409Field.invert(x, z);
        return new SecT409FieldElement(z);
    }

    public ECFieldElement sqrt()
    {
        long[] z = Nat448.create64();
        SecT409Field.sqrt(x, z);
        return new SecT409FieldElement(z);
    }

    public int getRepresentation()
    {
        return ECFieldElement.F2m.TPB;
    }

    public int getM()
    {
        return 409;
    }

    public int getK1()
    {
        return 87;
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

        if (!(other instanceof SecT409FieldElement))
        {
            return false;
        }

        SecT409FieldElement o = (SecT409FieldElement)other;
        return Nat448.eq64(x, o.x);
    }

    public int hashCode()
    {
        return 4090087 ^ Arrays.hashCode(x, 0, 7);
    }
}
