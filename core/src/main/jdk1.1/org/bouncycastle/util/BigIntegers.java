package org.bouncycastle.util;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Map;
import java.util.HashMap;

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
     * @param length the fixed length of the result
     * @param value  the value to be converted.
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
     * @param value the value to be converted.
     * @param buf   the buffer to which the value is written.
     * @param off   the start offset in array <code>buf</code> at which the data is written.
     * @param len   the fixed length of data written (possibly padded with leading zeros).
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
        Arrays.fill(buf, off, off + padLen, (byte)0x00);
        System.arraycopy(bytes, start, buf, off + padLen, count);
    }


    /**
     * Return a random BigInteger not less than 'min' and not greater than 'max'
     *
     * @param min    the least value that may be generated
     * @param max    the greatest value that may be generated
     * @param random the source of randomness
     * @return a random BigInteger value in the range [min,max]
     */
    public static BigInteger createRandomInRange(
        BigInteger min,
        BigInteger max,
        SecureRandom random)
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

    public static byte byteValueExact(BigInteger x)
    {
        // Since Java 1.8 could use BigInteger.byteValueExact instead
        if (x.bitLength() > 7)
        {
            throw new ArithmeticException("BigInteger out of int range");
        }

        return x.byteValue();
    }

    public static short shortValueExact(BigInteger x)
    {
        // Since Java 1.8 could use BigInteger.shortValueExact instead
        if (x.bitLength() > 15)
        {
            throw new ArithmeticException("BigInteger out of int range");
        }

        return x.shortValue();
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

    /**
     * Return (X + Y) mod M for X and Y already in the range [0, M). The sum is formed at a fixed
     * width and reduced by subtracting M unconditionally and then keeping or discarding the result
     * with a mask, so neither the running time nor the memory access pattern depends on the values.
     * <p>
     * Use this rather than {@code X.add(Y).mod(M)} when either operand is secret. A reduction
     * short-circuits when the value it is given is already less than the modulus, so a sum that
     * crosses the top of M is distinguishable from one that does not. Where the other operand is
     * public that difference is a threshold predicate on the secret one, and a public operand the
     * caller does not control turns repeated observations into a search over the secret.
     * </p>
     *
     * @param M the modulus, which must be positive.
     * @param X a value in the range [0, M).
     * @param Y a value in the range [0, M).
     * @return (X + Y) mod M.
     */
    public static BigInteger modAdd(BigInteger M, BigInteger X, BigInteger Y)
    {
        if (M.signum() != 1)
        {
            throw new ArithmeticException("BigInteger: modulus not positive");
        }
        if (X.signum() < 0 || X.compareTo(M) >= 0 || Y.signum() < 0 || Y.compareTo(M) >= 0)
        {
            throw new IllegalArgumentException("'X' and 'Y' must be in the range [0, M)");
        }

        // the extra bit of width means X + Y, which is less than 2M, cannot carry out of the top
        // word, so one conditional subtraction of M is enough to reduce it
        int bits = M.bitLength() + 1;
        int[] m = Nat.fromBigInteger(bits, M);
        int len = m.length;
        int[] x = Nat.fromBigInteger(bits, X);
        int[] y = Nat.fromBigInteger(bits, Y);
        int[] z = Nat.create(len);
        int[] t = Nat.create(len);

        Nat.add(len, x, y, z);
        int borrow = Nat.sub(len, z, m, t);     // t = z - M, borrow non-zero exactly when z < M
        Nat.cmov(len, ~borrow, t, 0, z, 0);     // keep t unless the subtraction went negative

        return Nat.toBigInteger(len, z);
    }

    /**
     * Return (X * Y) mod M for an odd M and X, Y already in the range [0, M), by Montgomery
     * multiplication over a fixed number of words. Every loop runs a value-independent number of
     * times and no index depends on the operands.
     * <p>
     * Use this rather than {@code X.multiply(Y).mod(M)} when either operand is secret. The product
     * is up to twice the width of M, so the reduction is a real division rather than the single
     * conditional subtraction {@link #modAdd(BigInteger, BigInteger, BigInteger)} needs, and how
     * much work it does depends on the quotient - which is to say on the operands.
     * </p><p>
     * The quantity derived from M alone (R squared mod M, where R is 2 raised to the width of M
     * rounded up to a word boundary) is computed with BigInteger, since M is the public modulus.
     * </p>
     *
     * @param M the modulus, which must be odd and positive.
     * @param X a value in the range [0, M).
     * @param Y a value in the range [0, M).
     * @return (X * Y) mod M.
     */
    public static BigInteger modMult(BigInteger M, BigInteger X, BigInteger Y)
    {
        if (!M.testBit(0))
        {
            throw new IllegalArgumentException("'M' must be odd");
        }
        if (M.signum() != 1)
        {
            throw new ArithmeticException("BigInteger: modulus not positive");
        }
        if (X.signum() < 0 || X.compareTo(M) >= 0 || Y.signum() < 0 || Y.compareTo(M) >= 0)
        {
            throw new IllegalArgumentException("'X' and 'Y' must be in the range [0, M)");
        }

        int bits = M.bitLength();
        int[] m = Nat.fromBigInteger(bits, M);
        int len = m.length;

        // R is 2^(32*len), which exceeds M, so R and the odd M are coprime and Montgomery form
        // exists. R^2 mod M depends only on the public modulus.
        // NOTE: base caches r2 and mDash across calls behind a volatile reference; this overlay
        // recomputes them each call, since the pre-Java-5 memory model cannot safely publish the
        // immutable holder that cache relies on.
        BigInteger r2 = ONE.shiftLeft(len << 6).mod(M);

        int mDash = -Mod.inverse32(m[0]);       // -M^-1 mod 2^32, the CIOS reduction multiplier

        // the first product leaves X*Y*R^-1, the second multiplies by R^2*R^-1 to undo it
        int[] z = montgomeryMultiply(len, Nat.fromBigInteger(bits, X), Nat.fromBigInteger(bits, Y), m, mDash);

        z = montgomeryMultiply(len, z, Nat.fromBigInteger(bits, r2), m, mDash);

        return Nat.toBigInteger(len, z);
    }

    /**
     * Coarsely-integrated operand scanning: returns X * Y * R^-1 mod M in [0, M) for X, Y in
     * [0, M). The accumulator carries two words of headroom above M so that every carry is
     * absorbed by a fixed sequence of adds rather than by a ripple whose length would depend on
     * the values.
     */
    private static int[] montgomeryMultiply(int len, int[] x, int[] y, int[] m, int mDash)
    {
        int[] t = new int[len + 2];

        for (int i = 0; i < len; ++i)
        {
            // t += x * y[i]
            long c = Nat.mulWordAddTo(len, y[i], x, 0, t, 0) & 0xFFFFFFFFL;
            c += t[len] & 0xFFFFFFFFL;
            t[len] = (int)c;
            t[len + 1] = (int)(c >>> 32);

            // t += (t[0] * -M^-1) * M, which clears the bottom word, then t >>= 32
            c = Nat.mulWordAddTo(len, t[0] * mDash, m, 0, t, 0) & 0xFFFFFFFFL;
            c += t[len] & 0xFFFFFFFFL;
            t[len] = (int)c;
            t[len + 1] += (int)(c >>> 32);

            System.arraycopy(t, 1, t, 0, len + 1);
            t[len + 1] = 0;
        }

        // t is below 2M and so occupies len+1 words: subtract M once if it is there to take
        int[] s = Nat.create(len);
        int top = t[len];
        int borrow = Nat.sub(len, t, m, s);

        // take s = t - M when the top word is set, or when the subtraction did not go negative
        Nat.cmov(len, ((top | -top) >> 31) | ~borrow, s, 0, t, 0);

        return t;
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
     * @param random    a source of randomness.
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
     * @param random    a source of randomness.
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

    public static boolean modOddIsCoprime(BigInteger M, BigInteger X)
    {
        if (!M.testBit(0))
        {
            throw new IllegalArgumentException("'M' must be odd");
        }
        if (M.signum() != 1)
        {
            throw new ArithmeticException("BigInteger: modulus not positive");
        }
        if (X.signum() < 0 || X.bitLength() > M.bitLength())
        {
            X = X.mod(M);
        }

        int bits = M.bitLength();
        int[] m = Nat.fromBigInteger(bits, M);
        int[] x = Nat.fromBigInteger(bits, X);
        return 0 != Mod.modOddIsCoprime(m, x);
    }

    public static boolean modOddIsCoprimeVar(BigInteger M, BigInteger X)
    {
        if (!M.testBit(0))
        {
            throw new IllegalArgumentException("'M' must be odd");
        }
        if (M.signum() != 1)
        {
            throw new ArithmeticException("BigInteger: modulus not positive");
        }
        if (X.signum() < 0 || X.bitLength() > M.bitLength())
        {
            X = X.mod(M);
        }
        if (X.equals(ONE))
        {
            return true;
        }

        int bits = M.bitLength();
        int[] m = Nat.fromBigInteger(bits, M);
        int[] x = Nat.fromBigInteger(bits, X);
        return Mod.modOddIsCoprimeVar(m, x);
    }
    public static class Cache
    {
        private final Map values = new HashMap();
        private final BigInteger[] preserve = new BigInteger[8];

        private int preserveCounter = 0;

        public synchronized void add(BigInteger value)
        {
            values.put(value, Boolean.TRUE);
            preserve[preserveCounter] = value;
            preserveCounter = (preserveCounter + 1) % preserve.length;
        }

        public synchronized boolean contains(BigInteger value)
        {
            return values.containsKey(value);
        }

        public synchronized int size()
        {
            return values.size();
        }

        public synchronized void clear()
        {
            values.clear();
            for (int i = 0; i != preserve.length; i++)
            {
                preserve[i] = null;
            }
        }
    }
}
