package org.bouncycastle.math.ec.custom.sec.test;

import java.math.BigInteger;
import java.security.SecureRandom;

import org.bouncycastle.asn1.sec.SECObjectIdentifiers;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.ec.CustomNamedCurves;
import org.bouncycastle.math.ec.ECFieldElement;
import org.bouncycastle.math.raw.Nat;

import junit.framework.TestCase;

public class SecP384R1FieldTest extends TestCase
{
    private static final SecureRandom RANDOM = new SecureRandom();

    private static final X9ECParameters DP = CustomNamedCurves
        .getByOID(SECObjectIdentifiers.secp384r1);
    private static final BigInteger Q = DP.getCurve().getField().getCharacteristic();

    public void testMultiply1()
    {
        int COUNT = 1000;

        for (int i = 0; i < COUNT; ++i)
        {
            ECFieldElement x = generateMultiplyInput_Random();
            ECFieldElement y = generateMultiplyInput_Random();

            BigInteger X = x.toBigInteger(), Y = y.toBigInteger();
            BigInteger R = X.multiply(Y).mod(Q);

            ECFieldElement z = x.multiply(y);
            BigInteger Z = z.toBigInteger();

            assertEquals(R, Z);
        }
    }

    public void testMultiply2()
    {
        int COUNT = 100;
        ECFieldElement[] inputs = new ECFieldElement[COUNT];
        BigInteger[] INPUTS = new BigInteger[COUNT];

        for (int i = 0; i < inputs.length; ++i)
        {
            inputs[i] = generateMultiplyInput_Random();
            INPUTS[i] = inputs[i].toBigInteger();
        }

        for (int j = 0; j < inputs.length; ++j)
        {
            for (int k = 0; k < inputs.length; ++k)
            {
                BigInteger R = INPUTS[j].multiply(INPUTS[k]).mod(Q);

                ECFieldElement z = inputs[j].multiply(inputs[k]);
                BigInteger Z = z.toBigInteger();

                assertEquals(R, Z);
            }
        }
    }

    public void testSquare()
    {
        int COUNT = 1000;

        for (int i = 0; i < COUNT; ++i)
        {
            ECFieldElement x = generateMultiplyInput_Random();

            BigInteger X = x.toBigInteger();
            BigInteger R = X.multiply(X).mod(Q);

            ECFieldElement z = x.square();
            BigInteger Z = z.toBigInteger();

            assertEquals(R, Z);
        }
    }

    public void testSquare_CarryBug()
    {
        int COUNT = 100;

        for (int i = 0; i < COUNT; ++i)
        {
            ECFieldElement x = generateSquareInput_CarryBug();

            BigInteger X = x.toBigInteger();
            BigInteger R = X.multiply(X).mod(Q);

            ECFieldElement z = x.square();
            BigInteger Z = z.toBigInteger();

            assertEquals(R, Z);
        }
    }

    /*
     * Based on another example input demonstrating the carry propagation bug in Nat192.square, as
     * reported by Joseph Friel on dev-crypto.
     */
    public void testSquare_CarryBug_Reported()
    {
        ECFieldElement x = fe(new BigInteger("2fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd", 16));

        BigInteger X = x.toBigInteger();
        BigInteger R = X.multiply(X).mod(Q);

        ECFieldElement z = x.square();
        BigInteger Z = z.toBigInteger();

        assertEquals(R, Z);
    }

    private ECFieldElement fe(BigInteger x)
    {
        return DP.getCurve().fromBigInteger(x);
    }

    private ECFieldElement generateMultiplyInput_Random()
    {
        return fe(new BigInteger(DP.getCurve().getFieldSize() + 32, RANDOM).mod(Q));
    }

    private ECFieldElement generateSquareInput_CarryBug()
    {
        int[] x = Nat.create(12);
        x[0] = RANDOM.nextInt() >>> 1;
        x[6] = 2;
        x[10] = -1 << 16;
        x[11] = -1;

        return fe(Nat.toBigInteger(12, x));
    }
}
