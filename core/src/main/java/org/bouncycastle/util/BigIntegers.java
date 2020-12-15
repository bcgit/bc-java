package org.bouncycastle.util;

import java.math.BigInteger;
import java.security.SecureRandom;

import org.bouncycastle.math.raw.Mod;
import org.bouncycastle.math.raw.Nat;

/**
 * BigInteger utilities.
 */
public final class BigIntegers
{
    public static final BigInteger ZERO = BigInteger.valueOf(0);
    public static final BigInteger ONE = BigInteger.valueOf(1);
    public static final BigInteger TWO = BigInteger.valueOf(2);

    private static final BigInteger THREE = BigInteger.valueOf(3);

    private static final int MAX_ITERATIONS = 1000;

    /**
     * Return the passed in value as an unsigned byte array.
     * 
     * @param value the value to be converted.
     * @return a byte array without a leading zero byte if present in the signed encoding.
     */
    public static byte[] asUnsignedByteArray(
        BigInteger value)
    {
        byte[] bytes = value.toByteArray();
        
        if (bytes[0] == 0 && bytes.length != 1)
        {
            byte[] tmp = new byte[bytes.length - 1];
            
            System.arraycopy(bytes, 1, tmp, 0, tmp.length);
            
            return tmp;
        }
        
        return bytes;
    }

    /**
     * Return the passed in value as an unsigned byte array of the specified length, padded with
     * leading zeros as necessary..
     *
     * @param length
     *            the fixed length of the result
     * @param value
     *            the value to be converted.
     * @return a byte array padded to a fixed length with leading zeros.
     */
    public static byte[] asUnsignedByteArray(int length, BigInteger value)
    {
        byte[] bytes = value.toByteArray();
        if (bytes.length == length)
        {
            return bytes;
        }

        int start = (bytes[0] == 0 && bytes.length != 1) ? 1 : 0;
        int count = bytes.length - start;

        if (count > length)
        {
            throw new IllegalArgumentException("standard length exceeded for value");
        }

        byte[] tmp = new byte[length];
        System.arraycopy(bytes, start, tmp, tmp.length - count, count);
        return tmp;
    }

    /**
     * Write the passed in value as unsigned bytes to the specified buffer range, padded with
     * leading zeros as necessary.
     *
     * @param value
     *            the value to be converted.
     * @param buf
     *            the buffer to which the value is written.
     * @param off
     *            the start offset in array <code>buf</code> at which the data is written.
     * @param len
     *            the fixed length of data written (possibly padded with leading zeros).
     */
    public static void asUnsignedByteArray(BigInteger value, byte[] buf, int off, int len)
    {
        byte[] bytes = value.toByteArray();
        if (bytes.length == len)
        {
            System.arraycopy(bytes, 0, buf, off, len);
            return;
        }

        int start = (bytes[0] == 0 && bytes.length != 1) ? 1 : 0;
        int count = bytes.length - start;

        if (count > len)
        {
            throw new IllegalArgumentException("standard length exceeded for value");
        }

        int padLen = len - count;
        Arrays.fill(buf,  off, off + padLen, (byte)0x00);
        System.arraycopy(bytes, start, buf, off + padLen, count);
    }

    /**
     * Return a random BigInteger not less than 'min' and not greater than 'max'
     * 
     * @param min the least value that may be generated
     * @param max the greatest value that may be generated
     * @param random the source of randomness
     * @return a random BigInteger value in the range [min,max]
     */
    public static BigInteger createRandomInRange(
        BigInteger      min,
        BigInteger      max,
        SecureRandom    random)
    {
        int cmp = min.compareTo(max);
        if (cmp >= 0)
        {
            if (cmp > 0)
            {
                throw new IllegalArgumentException("'min' may not be greater than 'max'");
            }

            return min;
        }

        if (min.bitLength() > max.bitLength() / 2)
        {
            return createRandomInRange(ZERO, max.subtract(min), random).add(min);
        }

        for (int i = 0; i < MAX_ITERATIONS; ++i)
        {
            BigInteger x = createRandomBigInteger(max.bitLength(), random);
            if (x.compareTo(min) >= 0 && x.compareTo(max) <= 0)
            {
                return x;
            }
        }

        // fall back to a faster (restricted) method
        return createRandomBigInteger(max.subtract(min).bitLength() - 1, random).add(min);
    }

    public static BigInteger fromUnsignedByteArray(byte[] buf)
    {
        return new BigInteger(1, buf);
    }

    public static BigInteger fromUnsignedByteArray(byte[] buf, int off, int length)
    {
        byte[] mag = buf;
        if (off != 0 || length != buf.length)
        {
            mag = new byte[length];
            System.arraycopy(buf, off, mag, 0, length);
        }
        return new BigInteger(1, mag);
    }

    public static int intValueExact(BigInteger x)
    {
        // Since Java 1.8 could use BigInteger.intValueExact instead
        if (x.bitLength() > 31)
        {
            throw new ArithmeticException("BigInteger out of int range");
        }

        return x.intValue(); 
    }

    public static long longValueExact(BigInteger x)
    {
        // Since Java 1.8 could use BigInteger.longValueExact instead
        if (x.bitLength() > 63)
        {
            throw new ArithmeticException("BigInteger out of long range");
        }

        return x.longValue(); 
    }

    public static BigInteger modOddInverse(BigInteger M, BigInteger X)
    {
        if (!M.testBit(0))
        {
            throw new IllegalArgumentException("'M' must be odd");
        }
        if (M.signum() != 1)
        {
            throw new ArithmeticException("BigInteger: modulus not positive");
        }
        if (X.signum() < 0 || X.compareTo(M) >= 0)
        {
            X = X.mod(M);
        }

        int bits = M.bitLength();
        int[] m = Nat.fromBigInteger(bits, M);
        int[] x = Nat.fromBigInteger(bits, X);
        int len = m.length;
        int[] z = Nat.create(len);
        if (0 == Mod.modOddInverse(m, x, z))
        {
            throw new ArithmeticException("BigInteger not invertible.");
        }
        return Nat.toBigInteger(len, z);
    }

    public static BigInteger modOddInverseVar(BigInteger M, BigInteger X)
    {
        if (!M.testBit(0))
        {
            throw new IllegalArgumentException("'M' must be odd");
        }
        if (M.signum() != 1)
        {
            throw new ArithmeticException("BigInteger: modulus not positive");
        }
        if (M.equals(ONE))
        {
            return ZERO;
        }
        if (X.signum() < 0 || X.compareTo(M) >= 0)
        {
            X = X.mod(M);
        }
        if (X.equals(ONE))
        {
            return ONE;
        }

        int bits = M.bitLength();
        int[] m = Nat.fromBigInteger(bits, M);
        int[] x = Nat.fromBigInteger(bits, X);
        int len = m.length;
        int[] z = Nat.create(len);
        if (!Mod.modOddInverseVar(m, x, z))
        {
            throw new ArithmeticException("BigInteger not invertible.");
        }
        return Nat.toBigInteger(len, z);
    }

    public static int getUnsignedByteLength(BigInteger n)
    {
        if (n.equals(ZERO))
        {
            return 1;
        }

        return (n.bitLength() + 7) / 8;
    }

    /**
     * Return a positive BigInteger in the range of 0 to 2**bitLength - 1.
     *
     * @param bitLength maximum bit length for the generated BigInteger.
     * @param random a source of randomness.
     * @return a positive BigInteger
     */
    public static BigInteger createRandomBigInteger(int bitLength, SecureRandom random)
    {
        return new BigInteger(1, createRandom(bitLength, random));
    }

    // Hexadecimal value of the product of the 131 smallest odd primes from 3 to 743
    private static final BigInteger SMALL_PRIMES_PRODUCT = new BigInteger(
              "8138e8a0fcf3a4e84a771d40fd305d7f4aa59306d7251de54d98af8fe95729a1f"
            + "73d893fa424cd2edc8636a6c3285e022b0e3866a565ae8108eed8591cd4fe8d2"
            + "ce86165a978d719ebf647f362d33fca29cd179fb42401cbaf3df0c614056f9c8"
            + "f3cfd51e474afb6bc6974f78db8aba8e9e517fded658591ab7502bd41849462f",
        16);
    private static final int MAX_SMALL = BigInteger.valueOf(743).bitLength(); // bitlength of 743 * 743

    /**
     * Return a prime number candidate of the specified bit length.
     *
     * @param bitLength bit length for the generated BigInteger.
     * @param random a source of randomness.
     * @return a positive BigInteger of numBits length
     */
    public static BigInteger createRandomPrime(int bitLength, int certainty, SecureRandom random)
    {
        if (bitLength < 2)
        {
            throw new IllegalArgumentException("bitLength < 2");
        }

        BigInteger rv;

        if (bitLength == 2)
        {
            return (random.nextInt() < 0) ? TWO : THREE;
        }

        do
        {
            byte[] base = createRandom(bitLength, random);

            int xBits = 8 * base.length - bitLength;
            byte lead = (byte)(1 << (7 - xBits));

            // ensure top and bottom bit set
            base[0] |= lead;
            base[base.length - 1] |= 0x01;

            rv = new BigInteger(1, base);
            if (bitLength > MAX_SMALL)
            {
                while (!rv.gcd(SMALL_PRIMES_PRODUCT).equals(ONE))
                {
                    rv = rv.add(TWO);
                }
            }
        }
        while (!rv.isProbablePrime(certainty));

        return rv;
    }

    private static byte[] createRandom(int bitLength, SecureRandom random)
        throws IllegalArgumentException
    {
        if (bitLength < 1)
        {
            throw new IllegalArgumentException("bitLength must be at least 1");
        }

        int nBytes = (bitLength + 7) / 8;

        byte[] rv = new byte[nBytes];

        random.nextBytes(rv);

        // strip off any excess bits in the MSB
        int xBits = 8 * nBytes - bitLength;
        rv[0] &= (byte)(255 >>> xBits);

        return rv;
    }
}
