package org.bouncycastle.math.ec.custom.sec;

import java.math.BigInteger;

import org.bouncycastle.math.ec.ECFieldElement;
import org.bouncycastle.math.raw.Nat160;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;

public class SecP160R1FieldElement extends ECFieldElement.AbstractFp
{
    public static final BigInteger Q = new BigInteger(1,
        Hex.decodeStrict("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF7FFFFFFF"));

    protected int[] x;

    public SecP160R1FieldElement(BigInteger x)
    {
        if (x == null || x.signum() < 0 || x.compareTo(Q) >= 0)
        {
            throw new IllegalArgumentException("x value invalid for SecP160R1FieldElement");
        }

        this.x = SecP160R1Field.fromBigInteger(x);
    }

    public SecP160R1FieldElement()
    {
        this.x = Nat160.create();
    }

    protected SecP160R1FieldElement(int[] x)
    {
        this.x = x;
    }

    public boolean isZero()
    {
        return Nat160.isZero(x);
    }

    public boolean isOne()
    {
        return Nat160.isOne(x);
    }

    public boolean testBitZero()
    {
        return Nat160.getBit(x, 0) == 1;
    }

    public BigInteger toBigInteger()
    {
        return Nat160.toBigInteger(x);
    }

    public String getFieldName()
    {
        return "SecP160R1Field";
    }

    public int getFieldSize()
    {
        return Q.bitLength();
    }

    public ECFieldElement add(ECFieldElement b)
    {
        int[] z = Nat160.create();
        SecP160R1Field.add(x, ((SecP160R1FieldElement)b).x, z);
        return new SecP160R1FieldElement(z);
    }

    public ECFieldElement addOne()
    {
        int[] z = Nat160.create();
        SecP160R1Field.addOne(x, z);
        return new SecP160R1FieldElement(z);
    }

    public ECFieldElement subtract(ECFieldElement b)
    {
        int[] z = Nat160.create();
        SecP160R1Field.subtract(x, ((SecP160R1FieldElement)b).x, z);
        return new SecP160R1FieldElement(z);
    }

    public ECFieldElement multiply(ECFieldElement b)
    {
        int[] z = Nat160.create();
        SecP160R1Field.multiply(x, ((SecP160R1FieldElement)b).x, z);
        return new SecP160R1FieldElement(z);
    }

    public ECFieldElement divide(ECFieldElement b)
    {
//        return multiply(b.invert());
        int[] z = Nat160.create();
        SecP160R1Field.inv(((SecP160R1FieldElement)b).x, z);
        SecP160R1Field.multiply(z, x, z);
        return new SecP160R1FieldElement(z);
    }

    public ECFieldElement negate()
    {
        int[] z = Nat160.create();
        SecP160R1Field.negate(x, z);
        return new SecP160R1FieldElement(z);
    }

    public ECFieldElement square()
    {
        int[] z = Nat160.create();
        SecP160R1Field.square(x, z);
        return new SecP160R1FieldElement(z);
    }

    public ECFieldElement invert()
    {
//        return new SecP160R1FieldElement(toBigInteger().modInverse(Q));
        int[] z = Nat160.create();
        SecP160R1Field.inv(x, z);
        return new SecP160R1FieldElement(z);
    }

    // D.1.4 91
    /**
     * return a sqrt root - the routine verifies that the calculation returns the right value - if
     * none exists it returns null.
     */
    public ECFieldElement sqrt()
    {
        /*
         * Raise this element to the exponent 2^158 - 2^29
         *
         * Breaking up the exponent's binary representation into "repunits", we get:
         *     { 129 1s } { 29 0s }
         *
         * Therefore we need an addition chain containing 129 (the length of the repunit) We use:
         *     1, 2, 4, 8, 16, 32, 64, 128, [129]
         */

        int[] x1 = this.x;
        if (Nat160.isZero(x1) || Nat160.isOne(x1))
        {
            return this;
        }

        int[] x2 = Nat160.create();
        SecP160R1Field.square(x1, x2);
        SecP160R1Field.multiply(x2, x1, x2);
        int[] x4 = Nat160.create();
        SecP160R1Field.squareN(x2, 2, x4);
        SecP160R1Field.multiply(x4, x2, x4);
        int[] x8 = x2;
        SecP160R1Field.squareN(x4, 4, x8);
        SecP160R1Field.multiply(x8, x4, x8);
        int[] x16 = x4;
        SecP160R1Field.squareN(x8, 8, x16);
        SecP160R1Field.multiply(x16, x8, x16);
        int[] x32 = x8;
        SecP160R1Field.squareN(x16, 16, x32);
        SecP160R1Field.multiply(x32, x16, x32);
        int[] x64 = x16;
        SecP160R1Field.squareN(x32, 32, x64);
        SecP160R1Field.multiply(x64, x32, x64);
        int[] x128 = x32;
        SecP160R1Field.squareN(x64, 64, x128);
        SecP160R1Field.multiply(x128, x64, x128);
        int[] x129 = x64;
        SecP160R1Field.square(x128, x129);
        SecP160R1Field.multiply(x129, x1, x129);

        int[] t1 = x129;
        SecP160R1Field.squareN(t1, 29, t1);

        int[] t2 = x128;
        SecP160R1Field.square(t1, t2);

        return Nat160.eq(x1, t2) ? new SecP160R1FieldElement(t1) : null;
    }

    public boolean equals(Object other)
    {
        if (other == this)
        {
            return true;
        }

        if (!(other instanceof SecP160R1FieldElement))
        {
            return false;
        }

        SecP160R1FieldElement o = (SecP160R1FieldElement)other;
        return Nat160.eq(x, o.x);
    }

    public int hashCode()
    {
        return Q.hashCode() ^ Arrays.hashCode(x, 0, 5);
    }
}
