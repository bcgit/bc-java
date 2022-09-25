package org.bouncycastle.crypto.util;

import java.math.BigInteger;

import org.bouncycastle.util.BigIntegers;

/**
 * Utility class to convert decimal numbers (BigInteger) into a number in the base provided and the other way round.
 * <p>For an application of this see the FPE parameter classes.</p>
 */
public class RadixConverter
{

    /*
    The conversions in this class are more complex than the standard ways of converting between basis because we want to improve the performance by limiting the
    operations on BigInteger which are not very efficient.
    The general idea is to perform math operations on primitive long as much as we can and just work with BigInteger when necessary.
    Converting between basis uses the fact that a number in base 'B' have a unique representation in polynomial form.

    num = ... + r8B^8 + r7B^7 + r6B^6 + r5B^5 + r4B^4 + r3B^3 + r2B^2 + r1B + r0

    We can compute how many digits in base 'B' can fit in a long. For example, for a radix R=2^16 the number of digits 'n' that we can fit into a long is the
    max 'n' that still satisfies: R^n < Long.MAX_VALUE (i.e. 2^63 -1). In this case 'n' is 3. To convert 'num' from its decimal representation to base 'B'
    representation we can write down 'num' in a polynomial form of B^3:

    num = (((...)B^3 + r8B^2 + r7B + r6)B^3 + r5B^2 + r4B + r3)B^3 + (r2B^2 + r1B + r0)

    B^3 would be our intermediate base. We can convert numbers in base B^3 while operating on primitive long.
    To convert a decimal num to its representation in base B we can first build its B^3 representation and then figure out the digits in base B from the single
    digit in base B^3. num % B^3 gives us a single digit in base B^3 which corresponds to a group of 3 digits in base B.

    An equivalent way of writing the polynomial form of num would be:

    num = (...)B^9 + (r8B^8 + r7B^7 + r6B^6)B^6 + (r5B^5 + r4B^4 + r3)B^3 + (r2B^2 + r1B + r0)

    In this form it becomes clear that to obtain 'num' from a sequence of digits, one can group the digits in group of 3 and compute the corresponding decimal
    number for the group in base B. We can then multiply the decimal numbers by the corresponding power of B^3 and sum up the result to obtain the decimal
    representation of num in base B,
     */
    private static final double LOG_LONG_MAX_VALUE = Math.log(Long.MAX_VALUE);
    private static final int DEFAULT_POWERS_TO_CACHE = 10;
    // the max number of digits in base 'radix' that fits in a long
    private int digitsGroupLength;
    // the total number of digits combination in a group. radix ^ digitsGroupLength
    private BigInteger digitsGroupSpaceSize;
    private int radix;
    private BigInteger[] digitsGroupSpacePowers;

    /**
     * @param radix                the radix to use for base conversions
     * @param numberOfCachedPowers number of intermediate base powers to precompute and cache.
     */
    public RadixConverter(int radix, int numberOfCachedPowers)
    {
        this.radix = radix;
        // solves radix^n < Long.MAX_VALUE to find n (maxDigitsFitsInLong)
        this.digitsGroupLength = (int)Math.floor(LOG_LONG_MAX_VALUE / Math.log(radix));
        this.digitsGroupSpaceSize = BigInteger.valueOf(radix).pow(digitsGroupLength);
        this.digitsGroupSpacePowers = precomputeDigitsGroupPowers(numberOfCachedPowers, digitsGroupSpaceSize);
    }

    /**
     * @param radix the radix to use for base conversions.
     */
    public RadixConverter(int radix)
    {
        this(radix, DEFAULT_POWERS_TO_CACHE);
    }

    public int getRadix()
    {
        return radix;
    }

    public void toEncoding(BigInteger number, int messageLength, short[] out)
    {
        if (number.signum() < 0)
        {
            throw new IllegalArgumentException();
        }
        // convert number into its representation in base 'radix'.
        // writes leading '0' if the messageLength is greater than the number of digits required to encode in base 'radix'
        int digitIndex = messageLength - 1;
        do
        {
            if (number.equals(BigIntegers.ZERO))
            {
                out[digitIndex--] = 0;
                continue;
            }
            BigInteger[] quotientAndRemainder = number.divideAndRemainder(digitsGroupSpaceSize);
            number = quotientAndRemainder[0];
            digitIndex = toEncoding(quotientAndRemainder[1].longValue(), digitIndex, out);
        }
        while (digitIndex >= 0);
        if (number.signum() != 0)
        {
            throw new IllegalArgumentException();
        }
    }

    private int toEncoding(long number, int digitIndex, short[] out)
    {
        for (int i = 0; i < digitsGroupLength && digitIndex >= 0; i++)
        {
            if (number == 0)
            {
                out[digitIndex--] = 0;
                continue;
            }
            out[digitIndex--] = (short)(number % radix);
            number = number / radix;
        }
        if (number != 0)
        {
            throw new IllegalStateException("Failed to convert decimal number");
        }
        return digitIndex;
    }

    public BigInteger fromEncoding(short[] digits)
    {
        // from a sequence of digits in base 'radix' to a decimal number
        // iterate through groups of digits right to left
        // digitsGroupLength = 2;  digits: [22, 45, 11, 31, 24]
        // groups are, in order of iteration: [31, 24], [45, 11], [22]
        BigInteger currentGroupCardinality = BigIntegers.ONE;
        BigInteger res = null;
        int indexGroup = 0;
        int numberOfDigits = digits.length;
        for (int groupStartDigitIndex = numberOfDigits - digitsGroupLength;
             groupStartDigitIndex > -digitsGroupLength;
             groupStartDigitIndex = groupStartDigitIndex - digitsGroupLength)
        {
            int actualDigitsInGroup = digitsGroupLength;
            if (groupStartDigitIndex < 0)
            {
                // last group might contain fewer digits so adjust offsets
                actualDigitsInGroup = digitsGroupLength + groupStartDigitIndex;
                groupStartDigitIndex = 0;
            }
            int groupEndDigitIndex = Math.min(groupStartDigitIndex + actualDigitsInGroup, numberOfDigits);
            long groupInBaseRadix = fromEncoding(groupStartDigitIndex, groupEndDigitIndex, digits);
            BigInteger bigInteger = BigInteger.valueOf(groupInBaseRadix);
            if (indexGroup == 0)
            {
                res = bigInteger;
            }
            else
            {
                currentGroupCardinality =
                    indexGroup <= digitsGroupSpacePowers.length
                        ? digitsGroupSpacePowers[indexGroup - 1]
                        : currentGroupCardinality.multiply(digitsGroupSpaceSize);
                res = res.add(bigInteger.multiply(currentGroupCardinality));
            }
            indexGroup++;
        }
        return res;
    }

    public int getDigitsGroupLength()
    {
        return digitsGroupLength;
    }

    private long fromEncoding(int groupStartDigitIndex, int groupEndDigitIndex, short[] digits)
    {
        long decimalNumber = 0;
        for (int digitIndex = groupStartDigitIndex; digitIndex < groupEndDigitIndex; digitIndex++)
        {
            decimalNumber = (decimalNumber * radix) + (digits[digitIndex] & 0xFFFF);
        }
        return decimalNumber;
    }

    private BigInteger[] precomputeDigitsGroupPowers(int numberOfCachedPowers, BigInteger digitsGroupSpaceSize)
    {
        BigInteger[] cachedPowers = new BigInteger[numberOfCachedPowers];
        BigInteger currentPower = digitsGroupSpaceSize;
        for (int i = 0; i < numberOfCachedPowers; i++)
        {
            cachedPowers[i] = currentPower;
            currentPower = currentPower.multiply(digitsGroupSpaceSize);
        }
        return cachedPowers;
    }
}
