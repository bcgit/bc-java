package org.bouncycastle.math.ec.custom.sec;

import java.math.BigInteger;

import org.bouncycastle.math.ec.ECFieldElement;
import org.bouncycastle.util.Arrays;

public class SecP256K1FieldElement extends ECFieldElement
{
    public static final BigInteger Q = SecP256K1Curve.q;
    public static final BigInteger Qr = SecP256K1Curve.r;

    protected int[] x;

    public SecP256K1FieldElement(BigInteger x)
    {
        if (x == null || x.signum() < 0 || x.compareTo(Q) >= 0)
        {
            throw new IllegalArgumentException("x value invalid in FEp256k1 field element");
        }

        this.x = SecP256K1Field.fromBigInteger(x);
    }

    protected SecP256K1FieldElement(int[] x)
    {
        this.x = x;
    }

    public boolean isZero()
    {
        return SecP256K1Field.isZero(x);
    }

    public boolean isOne()
    {
        return SecP256K1Field.isOne(x);
    }

    public boolean testBitZero()
    {
        return SecP256K1Field.testBit(x, 0);
    }

    public BigInteger toBigInteger()
    {
        return SecP256K1Field.toBigInteger(x);
    }

    public String getFieldName()
    {
        return "FEp256k1";
    }

    public int getFieldSize()
    {
        return Q.bitLength();
    }

    public BigInteger getQ()
    {
        return Q;
    }

    public ECFieldElement add(ECFieldElement b)
    {
        int[] z = SecP256K1Field.create();
        SecP256K1Field.add(x, ((SecP256K1FieldElement)b).x, z);
        return new SecP256K1FieldElement(z);
    }

    public ECFieldElement addOne()
    {
        int[] z = SecP256K1Field.create();
        SecP256K1Field.addOne(x, z);
        return new SecP256K1FieldElement(z);
    }

    public ECFieldElement subtract(ECFieldElement b)
    {
        int[] z = SecP256K1Field.create();
        SecP256K1Field.subtract(x, ((SecP256K1FieldElement)b).x, z);
        return new SecP256K1FieldElement(z);
    }

    public ECFieldElement multiply(ECFieldElement b)
    {
        int[] z = SecP256K1Field.create();
        SecP256K1Field.multiply(x, ((SecP256K1FieldElement)b).x, z);
        return new SecP256K1FieldElement(z);
    }

    public ECFieldElement divide(ECFieldElement b)
    {
        int[] y = SecP256K1Field.fromBigInteger(b.invert().toBigInteger());
        int[] z = SecP256K1Field.create();
        SecP256K1Field.multiply(x, y, z);
        return new SecP256K1FieldElement(z);
    }

    public ECFieldElement negate()
    {
        int[] z = SecP256K1Field.create();
        SecP256K1Field.negate(x, z);
        return new SecP256K1FieldElement(z);
    }

    public ECFieldElement square()
    {
        int[] z = SecP256K1Field.create();
        SecP256K1Field.square(x, z);
        return new SecP256K1FieldElement(z);
    }

    public ECFieldElement invert()
    {
        return new SecP256K1FieldElement(toBigInteger().modInverse(Q));
    }

    // D.1.4 91
    /**
     * return a sqrt root - the routine verifies that the calculation returns the right value - if
     * none exists it returns null.
     */
    public ECFieldElement sqrt()
    {
        ECFieldElement root = new ECFieldElement.Fp(Q, toBigInteger()).sqrt();
        return root == null ? null : new SecP256K1FieldElement(root.toBigInteger());
    }

    public boolean equals(Object other)
    {
        if (other == this)
        {
            return true;
        }

        if (!(other instanceof SecP256K1FieldElement))
        {
            return false;
        }

        SecP256K1FieldElement o = (SecP256K1FieldElement)other;
        return Arrays.areEqual(x, o.x);
    }

    public int hashCode()
    {
        return Q.hashCode() ^ Arrays.hashCode(x);
    }
}
