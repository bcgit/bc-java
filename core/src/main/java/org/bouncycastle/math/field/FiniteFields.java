package org.bouncycastle.math.field;

import java.math.BigInteger;

public abstract class FiniteFields
{
    static final FiniteField GF_2 = new PrimeField(BigInteger.valueOf(2));
    static final FiniteField GF_3 = new PrimeField(BigInteger.valueOf(3));

    public static PolynomialExtensionField getBinaryExtensionField(int[] exponents)
    {
        return new GenericPolynomialExtensionField(GF_2, new GF2Polynomial(exponents));
    }

    public static FiniteField getPrimeField(BigInteger characteristic)
    {
        characteristic = characteristic.abs();

        int bitLength = characteristic.bitLength();
        if (bitLength < 3)
        {
            if (bitLength < 2)
            {
                throw new IllegalArgumentException("'characteristic' must be >= 2");
            }

            switch (characteristic.intValue())
            {
            case 2:
                return GF_2;
            case 3:
                return GF_3;
            }
        }

        return new PrimeField(characteristic);
    }
}
