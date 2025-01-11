package org.bouncycastle.crypto.agreement.test;

import java.math.BigInteger;

import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.agreement.ecjpake.ECJPAKECurve;

import junit.framework.TestCase;


public class ECJPAKECurveTest
    extends TestCase
{

    public void testConstruction()
        throws CryptoException
    {
        //a
        BigInteger a = new BigInteger("ffffffff00000001000000000000000000000000fffffffffffffffffffffffc", 16);
        //b
        BigInteger b = new BigInteger("5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b", 16);
        //q
        BigInteger q = new BigInteger("ffffffff00000001000000000000000000000000ffffffffffffffffffffffff", 16);
        //n
        BigInteger n = new BigInteger("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551", 16);
        //h
        BigInteger h = BigInteger.ONE;
        //g_x
        BigInteger g_x = new BigInteger("6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296", 16);
        BigInteger g_y = new BigInteger("4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5", 16);

//        ECCurve.Fp curve = new ECCurve.Fp(q, a, b, n, h);
//        ECPoint g = curve.createPoint(
//            new BigInteger("6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296", 16),
//            new BigInteger("4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5", 16)
//        );

        // q not prime
        try
        {
            new ECJPAKECurve(BigInteger.valueOf(15), a, b, n, h, g_x, g_y);
            fail();
        }
        catch (IllegalArgumentException e)
        {
            // pass
        }

        // a is not in the field [0,q-1]
        try
        {
            new ECJPAKECurve(q, BigInteger.valueOf(-1), b, n, h, g_x, g_y);
            fail();
        }
        catch (IllegalArgumentException e)
        {
            // pass
        }

        // b is not in the field [0,q-1]
        try
        {
            new ECJPAKECurve(q, a, BigInteger.valueOf(-1), n, h, g_x, g_y);
            fail();
        }
        catch (IllegalArgumentException e)
        {
            // pass
        }

        // Discriminant is zero
        try
        {
            new ECJPAKECurve(q, q.subtract(BigInteger.valueOf(3)), BigInteger.valueOf(2), n, h, g_x, g_y);
            fail();
        }
        catch (IllegalArgumentException e)
        {
            // pass
        }

        // n is not prime
        try
        {
            new ECJPAKECurve(q, a, b, BigInteger.valueOf(15), h, g_x, g_y);
            fail();
        }
        catch (IllegalArgumentException e)
        {
            // pass
        }

        // G is not on the curve
        try
        {
            new ECJPAKECurve(q, a, b, n, h, BigInteger.valueOf(2), BigInteger.valueOf(3));
            fail();
        }
        catch (IllegalArgumentException e)
        {
            // pass
        }

        // should work
        new ECJPAKECurve(q, a, b, n, h, g_x, g_y);
    }
}
