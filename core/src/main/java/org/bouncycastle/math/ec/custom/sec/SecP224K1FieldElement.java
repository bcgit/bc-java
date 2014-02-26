package org.bouncycastle.math.ec.custom.sec;

import java.math.BigInteger;

import org.bouncycastle.math.ec.ECFieldElement;
import org.bouncycastle.math.ec.Mod;
import org.bouncycastle.util.Arrays;

public class SecP224K1FieldElement extends ECFieldElement
{
    public static final BigInteger Q = SecP224K1Curve.q;

    protected int[] x;

    public SecP224K1FieldElement(BigInteger x)
    {
        if (x == null || x.signum() < 0 || x.compareTo(Q) >= 0)
        {
            throw new IllegalArgumentException("x value invalid for SecP224K1FieldElement");
        }

        this.x = SecP224K1Field.fromBigInteger(x);
    }

    public SecP224K1FieldElement()
    {
        this.x = Nat224.create();
    }

    protected SecP224K1FieldElement(int[] x)
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
        return "SecP224K1Field";
    }

    public int getFieldSize()
    {
        return Q.bitLength();
    }

    public ECFieldElement add(ECFieldElement b)
    {
        int[] z = Nat224.create();
        SecP224K1Field.add(x, ((SecP224K1FieldElement)b).x, z);
        return new SecP224K1FieldElement(z);
    }

    public ECFieldElement addOne()
    {
        int[] z = Nat224.create();
        SecP224K1Field.addOne(x, z);
        return new SecP224K1FieldElement(z);
    }

    public ECFieldElement subtract(ECFieldElement b)
    {
        int[] z = Nat224.create();
        SecP224K1Field.subtract(x, ((SecP224K1FieldElement)b).x, z);
        return new SecP224K1FieldElement(z);
    }

    public ECFieldElement multiply(ECFieldElement b)
    {
        int[] z = Nat224.create();
        SecP224K1Field.multiply(x, ((SecP224K1FieldElement)b).x, z);
        return new SecP224K1FieldElement(z);
    }

    public ECFieldElement divide(ECFieldElement b)
    {
//        return multiply(b.invert());
        int[] z = Nat224.create();
        Mod.invert(SecP224K1Field.P, ((SecP224K1FieldElement)b).x, z);
        SecP224K1Field.multiply(z, x, z);
        return new SecP224K1FieldElement(z);
    }

    public ECFieldElement negate()
    {
        int[] z = Nat224.create();
        SecP224K1Field.negate(x, z);
        return new SecP224K1FieldElement(z);
    }

    public ECFieldElement square()
    {
        int[] z = Nat224.create();
        SecP224K1Field.square(x, z);
        return new SecP224K1FieldElement(z);
    }

    public ECFieldElement invert()
    {
//        return new SecP224K1FieldElement(toBigInteger().modInverse(Q));
        int[] z = Nat224.create();
        Mod.invert(SecP224K1Field.P, x, z);
        return new SecP224K1FieldElement(z);
    }

    // D.1.4 91
    /**
     * return a sqrt root - the routine verifies that the calculation returns the right value - if
     * none exists it returns null.
     */
    public ECFieldElement sqrt()
    {
        ECFieldElement root = new ECFieldElement.Fp(Q, toBigInteger()).sqrt();
        return root == null ? null : new SecP224K1FieldElement(root.toBigInteger());
    }

    public boolean equals(Object other)
    {
        if (other == this)
        {
            return true;
        }

        if (!(other instanceof SecP224K1FieldElement))
        {
            return false;
        }

        SecP224K1FieldElement o = (SecP224K1FieldElement)other;
        return Arrays.areEqual(x, o.x);
    }

    public int hashCode()
    {
        return Q.hashCode() ^ Arrays.hashCode(x);
    }
}
