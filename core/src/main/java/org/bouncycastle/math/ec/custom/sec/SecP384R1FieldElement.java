package org.bouncycastle.math.ec.custom.sec;

import java.math.BigInteger;

import org.bouncycastle.math.ec.ECFieldElement;
import org.bouncycastle.math.ec.Mod;
import org.bouncycastle.math.ec.Nat;
import org.bouncycastle.util.Arrays;

public class SecP384R1FieldElement extends ECFieldElement
{
    public static final BigInteger Q = SecP384R1Curve.q;

    protected int[] x;

    public SecP384R1FieldElement(BigInteger x)
    {
        if (x == null || x.signum() < 0 || x.compareTo(Q) >= 0)
        {
            throw new IllegalArgumentException("x value invalid for SecP384R1FieldElement");
        }

        this.x = SecP384R1Field.fromBigInteger(x);
    }

    public SecP384R1FieldElement()
    {
        this.x = Nat.create(12);
    }

    protected SecP384R1FieldElement(int[] x)
    {
        this.x = x;
    }

    public boolean isZero()
    {
        return Nat.isZero(12, x);
    }

    public boolean isOne()
    {
        return Nat.isOne(12, x);
    }

    public boolean testBitZero()
    {
        return Nat.getBit(x, 0) == 1;
    }

    public BigInteger toBigInteger()
    {
        return Nat.toBigInteger(12, x);
    }

    public String getFieldName()
    {
        return "SecP384R1Field";
    }

    public int getFieldSize()
    {
        return Q.bitLength();
    }

    public ECFieldElement add(ECFieldElement b)
    {
        int[] z = Nat.create(12);
        SecP384R1Field.add(x, ((SecP384R1FieldElement)b).x, z);
        return new SecP384R1FieldElement(z);
    }

    public ECFieldElement addOne()
    {
        int[] z = Nat.create(12);
        SecP384R1Field.addOne(x, z);
        return new SecP384R1FieldElement(z);
    }

    public ECFieldElement subtract(ECFieldElement b)
    {
        int[] z = Nat.create(12);
        SecP384R1Field.subtract(x, ((SecP384R1FieldElement)b).x, z);
        return new SecP384R1FieldElement(z);
    }

    public ECFieldElement multiply(ECFieldElement b)
    {
        int[] z = Nat.create(12);
        SecP384R1Field.multiply(x, ((SecP384R1FieldElement)b).x, z);
        return new SecP384R1FieldElement(z);
    }

    public ECFieldElement divide(ECFieldElement b)
    {
//        return multiply(b.invert());
        int[] z = Nat.create(12);
        Mod.invert(SecP384R1Field.P, ((SecP384R1FieldElement)b).x, z);
        SecP384R1Field.multiply(z, x, z);
        return new SecP384R1FieldElement(z);
    }

    public ECFieldElement negate()
    {
        int[] z = Nat.create(12);
        SecP384R1Field.negate(x, z);
        return new SecP384R1FieldElement(z);
    }

    public ECFieldElement square()
    {
        int[] z = Nat.create(12);
        SecP384R1Field.square(x, z);
        return new SecP384R1FieldElement(z);
    }

    public ECFieldElement invert()
    {
//        return new SecP384R1FieldElement(toBigInteger().modInverse(Q));
        int[] z = Nat.create(12);
        Mod.invert(SecP384R1Field.P, x, z);
        return new SecP384R1FieldElement(z);
    }

    /**
     * return a sqrt root - the routine verifies that the calculation returns the right value - if
     * none exists it returns null.
     */
    public ECFieldElement sqrt()
    {
        ECFieldElement root = new ECFieldElement.Fp(Q, toBigInteger()).sqrt();
        return root == null ? null : new SecP384R1FieldElement(root.toBigInteger());

//        // Raise this element to the exponent 2^254 - 2^222 + 2^190 + 2^94
//
//        int[] x1 = this.x;
//        if (Nat384.isZero(x1) || Nat384.isOne(x1))
//        {
//            return this;
//        }
//
//        int[] t1 = Nat.create(12);
//        int[] t2 = Nat.create(12);
//
//        SecP384R1Field.square(x1, t1);
//        SecP384R1Field.multiply(t1, x1, t1);
//
//        SecP384R1Field.squareN(t1, 2, t2);
//        SecP384R1Field.multiply(t2, t1, t2);
//
//        SecP384R1Field.squareN(t2, 4, t1);
//        SecP384R1Field.multiply(t1, t2, t1);
//
//        SecP384R1Field.squareN(t1, 8, t2);
//        SecP384R1Field.multiply(t2, t1, t2);
//
//        SecP384R1Field.squareN(t2, 16, t1);
//        SecP384R1Field.multiply(t1, t2, t1);
//
//        SecP384R1Field.squareN(t1, 32, t1);
//        SecP384R1Field.multiply(t1, x1, t1);
//
//        SecP384R1Field.squareN(t1, 96, t1);
//        SecP384R1Field.multiply(t1, x1, t1);
//
//        SecP384R1Field.squareN(t1, 94, t1);
//        SecP384R1Field.square(t1, t2);
//
//        return Arrays.areEqual(x1, t2) ? new SecP384R1FieldElement(t1) : null;
    }

    public boolean equals(Object other)
    {
        if (other == this)
        {
            return true;
        }

        if (!(other instanceof SecP384R1FieldElement))
        {
            return false;
        }

        SecP384R1FieldElement o = (SecP384R1FieldElement)other;
        return Arrays.areEqual(x, o.x);
    }

    public int hashCode()
    {
        return Q.hashCode() ^ Arrays.hashCode(x);
    }
}
