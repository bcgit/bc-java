package org.bouncycastle.math.ec.custom.gm;

import java.math.BigInteger;

import org.bouncycastle.math.ec.ECFieldElement;
import org.bouncycastle.math.raw.Nat256;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;

/**
 * Element of the SM9 G1 base field F_q, held in Montgomery form (see
 * {@link SM9P256V1Field}).
 */
public class SM9P256V1FieldElement extends ECFieldElement.AbstractFp
{
    public static final BigInteger Q = new BigInteger(1,
        Hex.decodeStrict("B640000002A3A6F1D603AB4FF58EC74521F2934B1A7AEEDBE56F9B27E351457D"));

    protected int[] x;   // Montgomery representation

    public SM9P256V1FieldElement(BigInteger x)
    {
        if (x == null || x.signum() < 0 || x.compareTo(Q) >= 0)
        {
            throw new IllegalArgumentException("x value invalid for SM9P256V1FieldElement");
        }

        this.x = SM9P256V1Field.fromBigInteger(x);
    }

    public SM9P256V1FieldElement()
    {
        this.x = Nat256.create();
    }

    protected SM9P256V1FieldElement(int[] x)
    {
        this.x = x;
    }

    public boolean isZero()
    {
        return Nat256.isZero(x);   // a*R == 0 iff a == 0
    }

    public boolean isOne()
    {
        return Nat256.eq(x, SM9P256V1Field.ONE);   // Montgomery one is R mod q, not 1
    }

    public boolean testBitZero()
    {
        return toBigInteger().testBit(0);   // parity of the value, not of its Montgomery form
    }

    public BigInteger toBigInteger()
    {
        return SM9P256V1Field.toBigInteger(x);
    }

    public String getFieldName()
    {
        return "SM9P256V1Field";
    }

    public int getFieldSize()
    {
        return Q.bitLength();
    }

    public ECFieldElement add(ECFieldElement b)
    {
        int[] z = Nat256.create();
        SM9P256V1Field.add(x, ((SM9P256V1FieldElement)b).x, z);
        return new SM9P256V1FieldElement(z);
    }

    public ECFieldElement addOne()
    {
        int[] z = Nat256.create();
        SM9P256V1Field.add(x, SM9P256V1Field.ONE, z);
        return new SM9P256V1FieldElement(z);
    }

    public ECFieldElement subtract(ECFieldElement b)
    {
        int[] z = Nat256.create();
        SM9P256V1Field.subtract(x, ((SM9P256V1FieldElement)b).x, z);
        return new SM9P256V1FieldElement(z);
    }

    public ECFieldElement multiply(ECFieldElement b)
    {
        int[] z = Nat256.create();
        SM9P256V1Field.multiply(x, ((SM9P256V1FieldElement)b).x, z);
        return new SM9P256V1FieldElement(z);
    }

    public ECFieldElement divide(ECFieldElement b)
    {
        int[] z = Nat256.create();
        SM9P256V1Field.inv(((SM9P256V1FieldElement)b).x, z);
        SM9P256V1Field.multiply(z, x, z);
        return new SM9P256V1FieldElement(z);
    }

    public ECFieldElement negate()
    {
        int[] z = Nat256.create();
        SM9P256V1Field.negate(x, z);
        return new SM9P256V1FieldElement(z);
    }

    public ECFieldElement square()
    {
        int[] z = Nat256.create();
        SM9P256V1Field.square(x, z);
        return new SM9P256V1FieldElement(z);
    }

    public ECFieldElement invert()
    {
        int[] z = Nat256.create();
        SM9P256V1Field.inv(x, z);
        return new SM9P256V1FieldElement(z);
    }

    /**
     * SM9 G1 uses only the uncompressed point encoding (0x04 || x || y), so square
     * roots (needed only for compressed-point decoding) are not implemented for this
     * internal curve. The SM9 prime is q = 1 mod 4, which would require Tonelli-Shanks
     * rather than the simple exponent used by SM2. Returns null (no root available).
     */
    public ECFieldElement sqrt()
    {
        return null;
    }

    public boolean equals(Object other)
    {
        if (other == this)
        {
            return true;
        }
        if (!(other instanceof SM9P256V1FieldElement))
        {
            return false;
        }
        SM9P256V1FieldElement o = (SM9P256V1FieldElement)other;
        return Nat256.eq(x, o.x);
    }

    public int hashCode()
    {
        return Q.hashCode() ^ Arrays.hashCode(x, 0, 8);
    }
}
