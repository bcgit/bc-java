package org.example;

import java.math.BigInteger;

import org.bouncycastle.crypto.CryptoException;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;


public class Owl_CurveTest
{
    @Test
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

        //q not prime
        assertThrows(IllegalArgumentException.class, () ->
            new Owl_Curve(BigInteger.valueOf(15), a, b, n, h, g_x, g_y)
        );

        //a not in field [0,q-1]
        assertThrows(IllegalArgumentException.class, () ->
            new Owl_Curve(q, BigInteger.valueOf(-1), b, n, h, g_x, g_y)
        );

        //b not in field [0,q-1]
        assertThrows(IllegalArgumentException.class, () ->
            new Owl_Curve(q, a, BigInteger.valueOf(-1), n, h, g_x, g_y)
        );

        //Discriminant is zero
        assertThrows(IllegalArgumentException.class, () ->
            new Owl_Curve(q, q.subtract(BigInteger.valueOf(3)), BigInteger.valueOf(2), n, h, g_x, g_y)
        );

        //n not prime
        assertThrows(IllegalArgumentException.class, () ->
            new Owl_Curve(q, a, b, BigInteger.valueOf(15), h, g_x, g_y)
        );

        //G not on the curve
        assertThrows(IllegalArgumentException.class, () ->
            new Owl_Curve(q, a, b, n, h, BigInteger.valueOf(2), BigInteger.valueOf(3))
        );

        //Should succeed
        assertDoesNotThrow(() ->
            new Owl_Curve(q, a, b, n, h, g_x, g_y)
        );
    }
}