package org.bouncycastle.crypto.agreement.test;

import java.math.BigInteger;

import junit.framework.TestCase;
import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.agreement.jpake.JPAKEPrimeOrderGroup;

public class JPAKEPrimeOrderGroupTest
    extends TestCase
{

    public void testConstruction()
        throws CryptoException
    {
        // p-1 not evenly divisible by q
        try
        {
            new JPAKEPrimeOrderGroup(BigInteger.valueOf(7), BigInteger.valueOf(5), BigInteger.valueOf(6));
            fail();
        }
        catch (IllegalArgumentException e)
        {
            // pass
        }

        // g < 2
        try
        {
            new JPAKEPrimeOrderGroup(BigInteger.valueOf(11), BigInteger.valueOf(5), BigInteger.valueOf(1));
            fail();
        }
        catch (IllegalArgumentException e)
        {
            // pass
        }

        // g > p-1
        try
        {
            new JPAKEPrimeOrderGroup(BigInteger.valueOf(11), BigInteger.valueOf(5), BigInteger.valueOf(11));
            fail();
        }
        catch (IllegalArgumentException e)
        {
            // pass
        }

        // g^q mod p not equal 1
        try
        {
            new JPAKEPrimeOrderGroup(BigInteger.valueOf(11), BigInteger.valueOf(5), BigInteger.valueOf(6));
            fail();
        }
        catch (IllegalArgumentException e)
        {
            // pass
        }

        // p not prime
        try
        {
            new JPAKEPrimeOrderGroup(BigInteger.valueOf(15), BigInteger.valueOf(2), BigInteger.valueOf(4));
            fail();
        }
        catch (IllegalArgumentException e)
        {
            // pass
        }

        // q not prime
        try
        {
            new JPAKEPrimeOrderGroup(BigInteger.valueOf(7), BigInteger.valueOf(6), BigInteger.valueOf(3));
            fail();
        }
        catch (IllegalArgumentException e)
        {
            // pass
        }

        // should succeed
        new JPAKEPrimeOrderGroup(BigInteger.valueOf(7), BigInteger.valueOf(3), BigInteger.valueOf(4));
    }
}
