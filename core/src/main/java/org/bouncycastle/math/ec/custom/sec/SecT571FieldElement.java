package org.bouncycastle.math.ec.custom.sec;

import java.math.BigInteger;

import org.bouncycastle.math.ec.ECFieldElement;
import org.bouncycastle.math.raw.Nat576;
import org.bouncycastle.util.Arrays;

public class SecT571FieldElement extends ECFieldElement.AbstractF2m
{
    protected long[] x;

    public SecT571FieldElement(BigInteger x)
    {
        if (x == null || x.signum() < 0 || x.bitLength() > 571)
        {
            throw new IllegalArgumentException("x value invalid for SecT571FieldElement");
        }

        this.x = SecT571Field.fromBigInteger(x);
    }

    public SecT571FieldElement()
    {
        this.x = Nat576.create64();
    }

    protected SecT571FieldElement(long[] x)
    {
        this.x = x;
    }

//    public int bitLength()
//    {
//        return x.degree();
//    }

    public boolean isOne()
    {
        return Nat576.isOne64(x);
    }

    public boolean isZero()
    {
        return Nat576.isZero64(x);
    }

    public boolean testBitZero()
    {
        return (x[0] & 1L) != 0L;
    }

    public BigInteger toBigInteger()
    {
        return Nat576.toBigInteger64(x);
    }

    public String getFieldName()
    {
        return "SecT571Field";
    }

    public int getFieldSize()
    {
        return 571;
    }

    public ECFieldElement add(ECFieldElement b)
    {
        long[] z = Nat576.create64();
        SecT571Field.add(x, ((SecT571FieldElement)b).x, z);
        return new SecT571FieldElement(z);
    }

    public ECFieldElement addOne()
    {
        long[] z = Nat576.create64();
        SecT571Field.addOne(x, z);
        return new SecT571FieldElement(z);
    }

    public ECFieldElement subtract(ECFieldElement b)
    {
        // Addition and subtraction are the same in F2m
        return add(b);
    }

    public ECFieldElement multiply(ECFieldElement b)
    {
        long[] z = Nat576.create64();
        SecT571Field.multiply(x, ((SecT571FieldElement)b).x, z);
        return new SecT571FieldElement(z);
    }

    public ECFieldElement multiplyMinusProduct(ECFieldElement b, ECFieldElement x, ECFieldElement y)
    {
        return multiplyPlusProduct(b, x, y);
    }

    public ECFieldElement multiplyPlusProduct(ECFieldElement b, ECFieldElement x, ECFieldElement y)
    {
        long[] ax = this.x, bx = ((SecT571FieldElement)b).x;
        long[] xx = ((SecT571FieldElement)x).x, yx = ((SecT571FieldElement)y).x;

        long[] tt = Nat576.createExt64();
        SecT571Field.multiplyAddToExt(ax, bx, tt);
        SecT571Field.multiplyAddToExt(xx, yx, tt);

        long[] z = Nat576.create64();
        SecT571Field.reduce(tt, z);
        return new SecT571FieldElement(z);
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
        long[] z = Nat576.create64();
        SecT571Field.square(x, z);
        return new SecT571FieldElement(z);
    }

    public ECFieldElement squareMinusProduct(ECFieldElement x, ECFieldElement y)
    {
        return squarePlusProduct(x, y);
    }

    public ECFieldElement squarePlusProduct(ECFieldElement x, ECFieldElement y)
    {
        long[] ax = this.x;
        long[] xx = ((SecT571FieldElement)x).x, yx = ((SecT571FieldElement)y).x;

        long[] tt = Nat576.createExt64();
        SecT571Field.squareAddToExt(ax, tt);
        SecT571Field.multiplyAddToExt(xx, yx, tt);

        long[] z = Nat576.create64();
        SecT571Field.reduce(tt, z);
        return new SecT571FieldElement(z);
    }

    public ECFieldElement squarePow(int pow)
    {
        if (pow < 1)
        {
            return this;
        }

        long[] z = Nat576.create64();
        SecT571Field.squareN(x, pow, z);
        return new SecT571FieldElement(z);
    }

    public ECFieldElement halfTrace()
    {
        long[] z = Nat576.create64();
        SecT571Field.halfTrace(x, z);
        return new SecT571FieldElement(z); 
    }

    public boolean hasFastTrace()
    {
        return true;
    }

    public int trace()
    {
        return SecT571Field.trace(x);
    }

    public ECFieldElement invert()
    {
        long[] z = Nat576.create64();
        SecT571Field.invert(x, z);
        return new SecT571FieldElement(z);
    }

    public ECFieldElement sqrt()
    {
        long[] z = Nat576.create64();
        SecT571Field.sqrt(x, z);
        return new SecT571FieldElement(z);
    }

    public int getRepresentation()
    {
        return ECFieldElement.F2m.PPB;
    }

    public int getM()
    {
        return 571;
    }

    public int getK1()
    {
        return 2;
    }

    public int getK2()
    {
        return 5;
    }

    public int getK3()
    {
        return 10;
    }

    public boolean equals(Object other)
    {
        if (other == this)
        {
            return true;
        }

        if (!(other instanceof SecT571FieldElement))
        {
            return false;
        }

        SecT571FieldElement o = (SecT571FieldElement)other;
        return Nat576.eq64(x, o.x);
    }

    public int hashCode()
    {
        return 5711052 ^ Arrays.hashCode(x, 0, 9);
    }
}
