package org.bouncycastle.math.ec.custom.sec;

import java.math.BigInteger;

import org.bouncycastle.math.ec.ECFieldElement;
import org.bouncycastle.math.raw.Nat256;
import org.bouncycastle.util.Arrays;

public class SecT233FieldElement extends ECFieldElement.AbstractF2m
{
    protected long[] x;

    public SecT233FieldElement(BigInteger x)
    {
        if (x == null || x.signum() < 0 || x.bitLength() > 233)
        {
            throw new IllegalArgumentException("x value invalid for SecT233FieldElement");
        }

        this.x = SecT233Field.fromBigInteger(x);
    }

    public SecT233FieldElement()
    {
        this.x = Nat256.create64();
    }

    protected SecT233FieldElement(long[] x)
    {
        this.x = x;
    }

//    public int bitLength()
//    {
//        return x.degree();
//    }

    public boolean isOne()
    {
        return Nat256.isOne64(x);
    }

    public boolean isZero()
    {
        return Nat256.isZero64(x);
    }

    public boolean testBitZero()
    {
        return (x[0] & 1L) != 0L;
    }

    public BigInteger toBigInteger()
    {
        return Nat256.toBigInteger64(x);
    }

    public String getFieldName()
    {
        return "SecT233Field";
    }

    public int getFieldSize()
    {
        return 233;
    }

    public ECFieldElement add(ECFieldElement b)
    {
        long[] z = Nat256.create64();
        SecT233Field.add(x, ((SecT233FieldElement)b).x, z);
        return new SecT233FieldElement(z);
    }

    public ECFieldElement addOne()
    {
        long[] z = Nat256.create64();
        SecT233Field.addOne(x, z);
        return new SecT233FieldElement(z);
    }

    public ECFieldElement subtract(ECFieldElement b)
    {
        // Addition and subtraction are the same in F2m
        return add(b);
    }

    public ECFieldElement multiply(ECFieldElement b)
    {
        long[] z = Nat256.create64();
        SecT233Field.multiply(x, ((SecT233FieldElement)b).x, z);
        return new SecT233FieldElement(z);
    }

    public ECFieldElement multiplyMinusProduct(ECFieldElement b, ECFieldElement x, ECFieldElement y)
    {
        return multiplyPlusProduct(b, x, y);
    }

    public ECFieldElement multiplyPlusProduct(ECFieldElement b, ECFieldElement x, ECFieldElement y)
    {
        long[] ax = this.x, bx = ((SecT233FieldElement)b).x;
        long[] xx = ((SecT233FieldElement)x).x, yx = ((SecT233FieldElement)y).x;

        long[] tt = Nat256.createExt64();
        SecT233Field.multiplyAddToExt(ax, bx, tt);
        SecT233Field.multiplyAddToExt(xx, yx, tt);

        long[] z = Nat256.create64();
        SecT233Field.reduce(tt, z);
        return new SecT233FieldElement(z);
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
        long[] z = Nat256.create64();
        SecT233Field.square(x, z);
        return new SecT233FieldElement(z);
    }

    public ECFieldElement squareMinusProduct(ECFieldElement x, ECFieldElement y)
    {
        return squarePlusProduct(x, y);
    }

    public ECFieldElement squarePlusProduct(ECFieldElement x, ECFieldElement y)
    {
        long[] ax = this.x;
        long[] xx = ((SecT233FieldElement)x).x, yx = ((SecT233FieldElement)y).x;

        long[] tt = Nat256.createExt64();
        SecT233Field.squareAddToExt(ax, tt);
        SecT233Field.multiplyAddToExt(xx, yx, tt);

        long[] z = Nat256.create64();
        SecT233Field.reduce(tt, z);
        return new SecT233FieldElement(z);
    }

    public ECFieldElement squarePow(int pow)
    {
        if (pow < 1)
        {
            return this;
        }

        long[] z = Nat256.create64();
        SecT233Field.squareN(x, pow, z);
        return new SecT233FieldElement(z);
    }

    public ECFieldElement halfTrace()
    {
        long[] z = Nat256.create64();
        SecT233Field.halfTrace(x, z);
        return new SecT233FieldElement(z); 
    }

    public boolean hasFastTrace()
    {
        return true;
    }

    public int trace()
    {
        return SecT233Field.trace(x);
    }

    public ECFieldElement invert()
    {
        long[] z = Nat256.create64();
        SecT233Field.invert(x, z);
        return new SecT233FieldElement(z);
    }

    public ECFieldElement sqrt()
    {
        long[] z = Nat256.create64();
        SecT233Field.sqrt(x, z);
        return new SecT233FieldElement(z);
    }

    public int getRepresentation()
    {
        return ECFieldElement.F2m.TPB;
    }

    public int getM()
    {
        return 233;
    }

    public int getK1()
    {
        return 74;
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

        if (!(other instanceof SecT233FieldElement))
        {
            return false;
        }

        SecT233FieldElement o = (SecT233FieldElement)other;
        return Nat256.eq64(x, o.x);
    }

    public int hashCode()
    {
        return 2330074 ^ Arrays.hashCode(x, 0, 4);
    }
}
