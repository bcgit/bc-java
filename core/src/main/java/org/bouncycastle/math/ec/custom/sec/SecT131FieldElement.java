package org.bouncycastle.math.ec.custom.sec;

import java.math.BigInteger;

import org.bouncycastle.math.ec.ECFieldElement;
import org.bouncycastle.math.raw.Nat;
import org.bouncycastle.math.raw.Nat192;
import org.bouncycastle.util.Arrays;

public class SecT131FieldElement extends ECFieldElement.AbstractF2m
{
    protected long[] x;

    public SecT131FieldElement(BigInteger x)
    {
        if (x == null || x.signum() < 0 || x.bitLength() > 131)
        {
            throw new IllegalArgumentException("x value invalid for SecT131FieldElement");
        }

        this.x = SecT131Field.fromBigInteger(x);
    }

    public SecT131FieldElement()
    {
        this.x = Nat192.create64();
    }

    protected SecT131FieldElement(long[] x)
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
        return "SecT131Field";
    }

    public int getFieldSize()
    {
        return 131;
    }

    public ECFieldElement add(ECFieldElement b)
    {
        long[] z = Nat192.create64();
        SecT131Field.add(x, ((SecT131FieldElement)b).x, z);
        return new SecT131FieldElement(z);
    }

    public ECFieldElement addOne()
    {
        long[] z = Nat192.create64();
        SecT131Field.addOne(x, z);
        return new SecT131FieldElement(z);
    }

    public ECFieldElement subtract(ECFieldElement b)
    {
        // Addition and subtraction are the same in F2m
        return add(b);
    }

    public ECFieldElement multiply(ECFieldElement b)
    {
        long[] z = Nat192.create64();
        SecT131Field.multiply(x, ((SecT131FieldElement)b).x, z);
        return new SecT131FieldElement(z);
    }

    public ECFieldElement multiplyMinusProduct(ECFieldElement b, ECFieldElement x, ECFieldElement y)
    {
        return multiplyPlusProduct(b, x, y);
    }

    public ECFieldElement multiplyPlusProduct(ECFieldElement b, ECFieldElement x, ECFieldElement y)
    {
        long[] ax = this.x, bx = ((SecT131FieldElement)b).x;
        long[] xx = ((SecT131FieldElement)x).x, yx = ((SecT131FieldElement)y).x;

        long[] tt = Nat.create64(5);
        SecT131Field.multiplyAddToExt(ax, bx, tt);
        SecT131Field.multiplyAddToExt(xx, yx, tt);

        long[] z = Nat192.create64();
        SecT131Field.reduce(tt, z);
        return new SecT131FieldElement(z);
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
        SecT131Field.square(x, z);
        return new SecT131FieldElement(z);
    }

    public ECFieldElement squareMinusProduct(ECFieldElement x, ECFieldElement y)
    {
        return squarePlusProduct(x, y);
    }

    public ECFieldElement squarePlusProduct(ECFieldElement x, ECFieldElement y)
    {
        long[] ax = this.x;
        long[] xx = ((SecT131FieldElement)x).x, yx = ((SecT131FieldElement)y).x;

        long[] tt = Nat.create64(5);
        SecT131Field.squareAddToExt(ax, tt);
        SecT131Field.multiplyAddToExt(xx, yx, tt);

        long[] z = Nat192.create64();
        SecT131Field.reduce(tt, z);
        return new SecT131FieldElement(z);
    }

    public ECFieldElement squarePow(int pow)
    {
        if (pow < 1)
        {
            return this;
        }

        long[] z = Nat192.create64();
        SecT131Field.squareN(x, pow, z);
        return new SecT131FieldElement(z);
    }

    public ECFieldElement halfTrace()
    {
        long[] z = Nat192.create64();
        SecT131Field.halfTrace(x, z);
        return new SecT131FieldElement(z); 
    }

    public boolean hasFastTrace()
    {
        return true;
    }

    public int trace()
    {
        return SecT131Field.trace(x);
    }

    public ECFieldElement invert()
    {
        long[] z = Nat192.create64();
        SecT131Field.invert(x, z);
        return new SecT131FieldElement(z);
    }

    public ECFieldElement sqrt()
    {
        long[] z = Nat192.create64();
        SecT131Field.sqrt(x, z);
        return new SecT131FieldElement(z);
    }

    public int getRepresentation()
    {
        return ECFieldElement.F2m.PPB;
    }

    public int getM()
    {
        return 131;
    }

    public int getK1()
    {
        return 2;
    }

    public int getK2()
    {
        return 3;
    }

    public int getK3()
    {
        return 8;
    }

    public boolean equals(Object other)
    {
        if (other == this)
        {
            return true;
        }

        if (!(other instanceof SecT131FieldElement))
        {
            return false;
        }

        SecT131FieldElement o = (SecT131FieldElement)other;
        return Nat192.eq64(x, o.x);
    }

    public int hashCode()
    {
        return 131832 ^ Arrays.hashCode(x, 0, 3);
    }
}
