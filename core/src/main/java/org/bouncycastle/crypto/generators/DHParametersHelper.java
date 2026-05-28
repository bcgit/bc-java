package org.bouncycastle.crypto.generators;

import java.math.BigInteger;
import java.security.SecureRandom;

import org.bouncycastle.math.ec.WNafUtil;
import org.bouncycastle.util.BigIntegers;

class DHParametersHelper
{
//    private static final BigInteger ONE = BigInteger.valueOf(1);
    private static final BigInteger TWO = BigInteger.valueOf(2);
    private static final BigInteger TWELVE = BigInteger.valueOf(12);
    private static final BigInteger TWENTY_FOUR = BigInteger.valueOf(24);

    /*
     * Finds a pair of prime BigInteger's {p, q: p = 2q + 1}
     * 
     * (see: Handbook of Applied Cryptography 4.86)
     *
     * If forGenerator2 is true, the returned p will also have 2 as a quadratic residue.
     */
    static BigInteger[] generateSafePrimes(int bitLength, int certainty, SecureRandom random, boolean forGenerator2)
    {
        if (bitLength < 64)
        {
            throw new IllegalArgumentException("size < 64");
        }

        int lowBitsSet = 0x03;
        int inc3 = 4;
        BigInteger step = TWELVE;

        if (forGenerator2)
        {
            // When selecting p,q so that g == 2 will generate the order q subgroup, we want p === 7 mod 8
            lowBitsSet = 0x07;
            inc3 = -8;
            step = TWENTY_FOUR;
        }

        int minWeight = bitLength >>> 2;
        int byteLength = (bitLength + 7) / 8;
        int extraBits = byteLength * 8 - bitLength;

        byte[] bytes = new byte[byteLength];

        for (;;)
        {
            random.nextBytes(bytes);

            // strip off excess bits, set MSB and LSB
            bytes[0] = (byte)((bytes[0] & (0xFF >>> extraBits)) | (0x80 >>> extraBits));
            bytes[bytes.length - 1] |= lowBitsSet;

            BigInteger p = new BigInteger(1, bytes);

            // Check p mod 3
            int pMod3 = BigIntegers.intValueExact(p.mod(BigInteger.valueOf(3)));
            if (pMod3 != 2)
            {
                // Result will be p === 11 mod 12 (forGenerator2 => p === 23 mod 24)
                p = p.add(BigInteger.valueOf((2 - pMod3) * inc3));
            }

            int count = 0;
            while (++count <= 256 && p.bitLength() == bitLength)
            {
                // Check for small factors in p and q simultaneously
                if (!hasAnySmallFactorsSafe(p))
                {
                    if (!BigIntegers.hasAnySmallFactors(p))
                    {
                        BigInteger q = p.shiftRight(1);
                        if (!BigIntegers.hasAnySmallFactors(q))
                        {
                            // NOTE: Pocklington criterion: Fermat test suffices to prove p prime given q is prime
                            if (TWO.modPow(p, p).equals(TWO))
                            {
                                if (q.isProbablePrime(certainty))
                                {
                                    /*
                                     * Require a minimum weight of the NAF representation, since low-weight primes may
                                     * be weak against a version of the number-field-sieve for the
                                     * discrete-logarithm-problem.
                                     * 
                                     * See "The number field sieve for integers of low weight", Oliver Schirokauer.
                                     */
                                    if (WNafUtil.getNafWeight(p) >= minWeight)
                                    {
                                        return new BigInteger[]{ p, q };
                                    }
                                }
                            }

                            // Start from a new random value
                            break;
                        }
                    }
                }

                p = p.add(step);
            }
        }
    }

    private static boolean hasAnySmallFactorsSafe(BigInteger x)
    {
        /*
         * Bundle trial divisors into ~32-bit moduli then use fast tests on the ~32-bit remainders.
         * We check for remainders: 0 => n|p, 1 => n|((p-1)/2)
         */

        int m = 5 * 7 * 11 * 13 * 17 * 19 * 23 * 29;
        int r = BigIntegers.intValueExact(x.mod(BigInteger.valueOf(m)));
        if ((r % 5) < 2 || (r % 7) < 2 || (r % 11) < 2 || (r % 13) < 2 || (r % 17) < 2 || (r % 19) < 2 || (r % 23) < 2
            || (r % 29) < 2)
        {
            return true;
        }

        m = 31 * 37 * 41 * 43 * 47;
        r = BigIntegers.intValueExact(x.mod(BigInteger.valueOf(m)));
        if ((r % 31) < 2 || (r % 37) < 2 || (r % 41) < 2 || (r % 43) < 2 || (r % 47) < 2)
        {
            return true;
        }

        m = 53 * 59 * 61 * 67 * 71;
        r = BigIntegers.intValueExact(x.mod(BigInteger.valueOf(m)));
        if ((r % 53) < 2 || (r % 59) < 2 || (r % 61) < 2 || (r % 67) < 2 || (r % 71) < 2)
        {
            return true;
        }

        return false;
    }

//    /*
//     * Select a high order element of the multiplicative group Zp*
//     * 
//     * p and q must be s.t. p = 2*q + 1, where p and q are prime (see generateSafePrimes)
//     */
//    static BigInteger selectGenerator(BigInteger p, BigInteger q, SecureRandom random)
//    {
//        BigInteger pMinusTwo = p.subtract(TWO);
//        BigInteger g;
//
//        /*
//         * (see: Handbook of Applied Cryptography 4.80)
//         */
////        do
////        {
////            g = BigIntegers.createRandomInRange(TWO, pMinusTwo, random);
////        }
////        while (g.modPow(TWO, p).equals(ONE) || g.modPow(q, p).equals(ONE));
//
//
//        /*
//         * RFC 2631 2.2.1.2 (and see: Handbook of Applied Cryptography 4.81)
//         */
//        do
//        {
//            BigInteger h = BigIntegers.createRandomInRange(TWO, pMinusTwo, random);
//
//            g = h.modPow(TWO, p);
//        }
//        while (g.equals(ONE));
//
//
//        return g;
//    }
}
