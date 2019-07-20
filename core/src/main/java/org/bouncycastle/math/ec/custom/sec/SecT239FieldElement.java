package org.bouncycastle.math.ec.custom.sec;

import java.math.BigInteger;

import org.bouncycastle.math.ec.ECFieldElement;
import org.bouncycastle.math.raw.Nat256;
import org.bouncycastle.util.Arrays;

public class SecT239FieldElement extends ECFieldElement.AbstractF2m
{
    protected long[] x;

    public SecT239FieldElement(BigInteger x)
    {
        if (x == null || x.signum() < 0 || x.bitLength() > 239)
        {
            throw new IllegalArgumentException("x value invalid for SecT239FieldElement");
        }

        this.x = SecT239Field.fromBigInteger(x);
    }

    public SecT239FieldElement()
    {
        this.x = Nat256.create64();
    }

    protected SecT239FieldElement(long[] x)
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
        return "SecT239Field";
    }

    public int getFieldSize()
    {
        return 239;
    }

    public ECFieldElement add(ECFieldElement b)
    {
        long[] z = Nat256.create64();
        SecT239Field.add(x, ((SecT239FieldElement)b).x, z);
        return new SecT239FieldElement(z);
    }

    public ECFieldElement addOne()
    {
        long[] z = Nat256.create64();
        SecT239Field.addOne(x, z);
        return new SecT239FieldElement(z);
    }

    public ECFieldElement subtract(ECFieldElement b)
    {
        // Addition and subtraction are the same in F2m
        return add(b);
    }

    public ECFieldElement multiply(ECFieldElement b)
    {
        long[] z = Nat256.create64();
        SecT239Field.multiply(x, ((SecT239FieldElement)b).x, z);
        return new SecT239FieldElement(z);
    }

    public ECFieldElement multiplyMinusProduct(ECFieldElement b, ECFieldElement x, ECFieldElement y)
    {
        return multiplyPlusProduct(b, x, y);
    }

    public ECFieldElement multiplyPlusProduct(ECFieldElement b, ECFieldElement x, ECFieldElement y)
    {
        long[] ax = this.x, bx = ((SecT239FieldElement)b).x;
        long[] xx = ((SecT239FieldElement)x).x, yx = ((SecT239FieldElement)y).x;

        long[] tt = Nat256.createExt64();
        SecT239Field.multiplyAddToExt(ax, bx, tt);
        SecT239Field.multiplyAddToExt(xx, yx, tt);

        long[] z = Nat256.create64();
        SecT239Field.reduce(tt, z);
        return new SecT239FieldElement(z);
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
        SecT239Field.square(x, z);
        return new SecT239FieldElement(z);
    }

    public ECFieldElement squareMinusProduct(ECFieldElement x, ECFieldElement y)
    {
        return squarePlusProduct(x, y);
    }

    public ECFieldElement squarePlusProduct(ECFieldElement x, ECFieldElement y)
    {
        long[] ax = this.x;
        long[] xx = ((SecT239FieldElement)x).x, yx = ((SecT239FieldElement)y).x;

        long[] tt = Nat256.createExt64();
        SecT239Field.squareAddToExt(ax, tt);
        SecT239Field.multiplyAddToExt(xx, yx, tt);

        long[] z = Nat256.create64();
        SecT239Field.reduce(tt, z);
        return new SecT239FieldElement(z);
    }

    public ECFieldElement squarePow(int pow)
    {
        if (pow < 1)
        {
            return this;
        }

        long[] z = Nat256.create64();
        SecT239Field.squareN(x, pow, z);
        return new SecT239FieldElement(z);
    }

    public ECFieldElement halfTrace()
    {
        long[] z = Nat256.create64();
        SecT239Field.halfTrace(x, z);
        return new SecT239FieldElement(z); 
    }

    public boolean hasFastTrace()
    {
        return true;
    }

    public int trace()
    {
        return SecT239Field.trace(x);
    }

    public ECFieldElement invert()
    {
        long[] z = Nat256.create64();
        SecT239Field.invert(x, z);
        return new SecT239FieldElement(z);
    }

    public ECFieldElement sqrt()
    {
        long[] z = Nat256.create64();
        SecT239Field.sqrt(x, z);
        return new SecT239FieldElement(z);
    }

    public int getRepresentation()
    {
        return ECFieldElement.F2m.TPB;
    }

    public int getM()
    {
        return 239;
    }

    public int getK1()
    {
        return 158;
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

        if (!(other instanceof SecT239FieldElement))
        {
            return false;
        }

        SecT239FieldElement o = (SecT239FieldElement)other;
        return Nat256.eq64(x, o.x);
    }

    public int hashCode()
    {
        return 23900158 ^ Arrays.hashCode(x, 0, 4);
    }
}
