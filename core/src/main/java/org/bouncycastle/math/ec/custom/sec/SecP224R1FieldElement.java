package org.bouncycastle.math.ec.custom.sec;

import java.math.BigInteger;

import org.bouncycastle.math.ec.ECFieldElement;
import org.bouncycastle.math.ec.Mod;
import org.bouncycastle.util.Arrays;

public class SecP224R1FieldElement extends ECFieldElement
{
    public static final BigInteger Q = SecP224R1Curve.q;

    protected int[] x;

    public SecP224R1FieldElement(BigInteger x)
    {
        if (x == null || x.signum() < 0 || x.compareTo(Q) >= 0)
        {
            throw new IllegalArgumentException("x value invalid for SecP224R1FieldElement");
        }

        this.x = SecP224R1Field.fromBigInteger(x);
    }

    public SecP224R1FieldElement()
    {
        this.x = Nat224.create();
    }

    protected SecP224R1FieldElement(int[] x)
    {
        this.x = x;
    }

    public boolean isZero()
    {
        return Nat224.isZero(x);
    }

    public boolean isOne()
    {
        return Nat224.isOne(x);
    }

    public boolean testBitZero()
    {
        return Nat224.getBit(x, 0) == 1;
    }

    public BigInteger toBigInteger()
    {
        return Nat224.toBigInteger(x);
    }

    public String getFieldName()
    {
        return "SecP224R1Field";
    }

    public int getFieldSize()
    {
        return Q.bitLength();
    }

    public ECFieldElement add(ECFieldElement b)
    {
        int[] z = Nat224.create();
        SecP224R1Field.add(x, ((SecP224R1FieldElement)b).x, z);
        return new SecP224R1FieldElement(z);
    }

    public ECFieldElement addOne()
    {
        int[] z = Nat224.create();
        SecP224R1Field.addOne(x, z);
        return new SecP224R1FieldElement(z);
    }

    public ECFieldElement subtract(ECFieldElement b)
    {
        int[] z = Nat224.create();
        SecP224R1Field.subtract(x, ((SecP224R1FieldElement)b).x, z);
        return new SecP224R1FieldElement(z);
    }

    public ECFieldElement multiply(ECFieldElement b)
    {
        int[] z = Nat224.create();
        SecP224R1Field.multiply(x, ((SecP224R1FieldElement)b).x, z);
        return new SecP224R1FieldElement(z);
    }

    public ECFieldElement divide(ECFieldElement b)
    {
//        return multiply(b.invert());
        int[] z = Nat224.create();
        Mod.invert(SecP224R1Field.P, ((SecP224R1FieldElement)b).x, z);
        SecP224R1Field.multiply(z, x, z);
        return new SecP224R1FieldElement(z);
    }

    public ECFieldElement negate()
    {
        int[] z = Nat224.create();
        SecP224R1Field.negate(x, z);
        return new SecP224R1FieldElement(z);
    }

    public ECFieldElement square()
    {
        int[] z = Nat224.create();
        SecP224R1Field.square(x, z);
        return new SecP224R1FieldElement(z);
    }

    public ECFieldElement invert()
    {
//        return new SecP224R1FieldElement(toBigInteger().modInverse(Q));
        int[] z = Nat224.create();
        Mod.invert(SecP224R1Field.P, x, z);
        return new SecP224R1FieldElement(z);
    }

    /**
     * return a sqrt root - the routine verifies that the calculation returns the right value - if
     * none exists it returns null.
     */
    public ECFieldElement sqrt()
    {
        ECFieldElement root = new ECFieldElement.Fp(Q, toBigInteger()).sqrt();
        return root == null ? null : new SecP224R1FieldElement(root.toBigInteger());
    }

    public boolean equals(Object other)
    {
        if (other == this)
        {
            return true;
        }

        if (!(other instanceof SecP224R1FieldElement))
        {
            return false;
        }

        SecP224R1FieldElement o = (SecP224R1FieldElement)other;
        return Arrays.areEqual(x, o.x);
    }

    public int hashCode()
    {
        return Q.hashCode() ^ Arrays.hashCode(x);
    }
}
