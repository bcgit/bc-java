package org.bouncycastle.crypto.test;

import java.math.BigInteger;
import java.util.Arrays;

import org.bouncycastle.crypto.util.RadixConverter;
import org.bouncycastle.util.test.SimpleTest;

public class RadixConverterTest extends SimpleTest
{

    public void performTest() throws Exception
    {
        testBaseConversionSingleDigit();
        testBaseConversionLeadingZeros();
        testBaseConversionMultipleDigitsInRadixRepresentation();
        testBaseConversionDecimalNumberLargerThanMaxLong();
        testBaseConversionLargeDecimalNumberLeadingZerosInDigitGroup();
        testBaseConversionLargeDecimalNumberGroupWithAllZeros();
        testBaseConversionZero();
        testBaseConversionNoPowersCached();
        testBaseConversionSomePowersCached();
    }

    void testBaseConversionSingleDigit()
    {
        RadixConversionArgument arg =
                RadixConversionArgument.builder().setRadix(33).setNumberOfDigits(1).setDecimalNumber(new BigInteger("3")).setDigits(new short[]{3}).build();
        runTest(arg, new RadixConverter(arg.getRadix()));
    }

    void testBaseConversionLeadingZeros()
    {
        RadixConversionArgument arg =
                RadixConversionArgument.builder()
                        .setRadix(33)
                        .setNumberOfDigits(3)
                        .setDecimalNumber(new BigInteger("3"))
                        .setDigits(new short[]{0, 0, 3})
                        .build();
        runTest(arg, new RadixConverter(arg.getRadix()));
    }

    void testBaseConversionMultipleDigitsInRadixRepresentation()
    {
        int radix = 33;
        RadixConversionArgument arg =
                RadixConversionArgument.builder()
                        .setRadix(radix)
                        .setNumberOfDigits(3)
                        .setDecimalNumber(decimalInPolynomialForm(radix, new int[] { 1, 0}))
                        .setDigits(new short[]{0, 1, 0})
                        .build();
        runTest(arg, new RadixConverter(arg.getRadix()));

        arg =
                RadixConversionArgument.builder()
                        .setRadix(radix)
                        .setNumberOfDigits(3)
                        .setDecimalNumber(decimalInPolynomialForm(radix, new int[] { 1, 1}))
                        .setDigits(new short[]{0, 1, 1})
                        .build();
        runTest(arg, new RadixConverter(arg.getRadix()));

        arg =
                RadixConversionArgument.builder()
                        .setRadix(radix)
                        .setNumberOfDigits(3)
                        .setDecimalNumber(decimalInPolynomialForm(radix, new int[] { 22, 13, 4 }))
                        .setDigits(new short[]{22, 13, 4})
                        .build();
        runTest(arg, new RadixConverter(arg.getRadix()));
    }

    void testBaseConversionDecimalNumberLargerThanMaxLong()
    {
        // 7 digits in base 251 is the max number that fits in a long
        int radix = 251;
        RadixConversionArgument arg =
                RadixConversionArgument.builder()
                        .setRadix(radix)
                        .setNumberOfDigits(21)
                        .setDecimalNumber(decimalInPolynomialForm(radix, new int[] { 234, 33, 0, 45, 125, 98, 12, 34, 100, 77, 211, 9, 3, 123, 96, 55, 23, 44, 98}))
                        // two leading zero because we are asking a message length 21 when the number can be encoded in 19 bytes
                        .setDigits(new short[]{0, 0, 234, 33, 0, 45, 125, 98, 12, 34, 100, 77, 211, 9, 3, 123, 96, 55, 23, 44, 98})
                        .build();
        RadixConverter radixConverter = new RadixConverter(arg.getRadix());
        checkAtLeastNDigitGroupsForTestCase(3, arg, radixConverter);
        runTest(arg, radixConverter);
    }

    void testBaseConversionLargeDecimalNumberLeadingZerosInDigitGroup()
    {
        // 7 digits in base 251 is the max number that fits in a long
        int radix = 251;
        RadixConversionArgument arg =
                RadixConversionArgument.builder()
                        .setRadix(radix)
                        .setNumberOfDigits(19)
                        .setDecimalNumber(decimalInPolynomialForm(radix, new int[] { 234, 33, 2, 45, 125, 0, 12, 34, 100, 77, 211, 9, 0, 0, 96, 55, 23, 44, 98 }))
                        .setDigits(new short[]{234, 33, 2, 45, 125, 0, 12, 34, 100, 77, 211, 9, 0, 0, 96, 55, 23, 44, 98})
                        .build();
        RadixConverter radixConverter = new RadixConverter(arg.getRadix());
        checkAtLeastNDigitGroupsForTestCase(3, arg, radixConverter);
        runTest(arg, radixConverter);
    }

    void testBaseConversionLargeDecimalNumberGroupWithAllZeros()
    {
        // 7 digits in base 251 is the max number that fits in a long
        int radix = 251;
        BigInteger decimalNumber = decimalInPolynomialForm(radix, new int[] { 125, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 });
        RadixConversionArgument arg =
                RadixConversionArgument.builder()
                        .setRadix(radix)
                        .setNumberOfDigits(17)
                        .setDecimalNumber(decimalNumber)
                        // two leading zeros because message length is 17 but number is encoded in 15 bytes
                        .setDigits(new short[]{0, 0, 125, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0})
                        .build();
        RadixConverter radixConverter = new RadixConverter(arg.getRadix());
        checkAtLeastNDigitGroupsForTestCase(3, arg, radixConverter);
        runTest(arg, radixConverter);
    }

    void testBaseConversionZero()
    {
        // 7 digits in base 251 is the max number that fits in a long
        int radix = 251;
        RadixConversionArgument arg =
                RadixConversionArgument.builder()
                        .setRadix(radix)
                        .setNumberOfDigits(9)
                        .setDecimalNumber(BigInteger.ZERO)
                        .setDigits(new short[]{0, 0, 0, 0, 0, 0, 0, 0, 0})
                        .build();
        RadixConverter radixConverter = new RadixConverter(arg.getRadix());
        checkAtLeastNDigitGroupsForTestCase(2, arg, radixConverter);
        runTest(arg, radixConverter);
    }

    void testBaseConversionNoPowersCached()
    {
        // 7 digits in base 251 is the max number that fits in a long
        int radix = 251;
        RadixConversionArgument arg =
                RadixConversionArgument.builder()
                        .setRadix(radix)
                        .setNumberOfDigits(15)
                        .setDecimalNumber(decimalInPolynomialForm(radix, new int[] { 6, 200, 78, 9, 53, 90, 178, 213, 154, 65, 127, 99, 22, 13, 4 }))
                        .setDigits(new short[]{6, 200, 78, 9, 53, 90, 178, 213, 154, 65, 127, 99, 22, 13, 4})
                        .build();
        RadixConverter radixConverter = new RadixConverter(arg.getRadix(), 0);
        checkAtLeastNDigitGroupsForTestCase(3, arg, radixConverter);
        runTest(arg, radixConverter);
    }

    void testBaseConversionSomePowersCached()
    {
        // 4 digits in base 32000 is the max number that fits in a long
        int radix = 32000;
        RadixConversionArgument arg =
                RadixConversionArgument.builder()
                        .setRadix(radix)
                        .setNumberOfDigits(19)
                        .setDecimalNumber(decimalInPolynomialForm(radix, new int[] { 2756, 1111, 965, 0, 6, 200, 78, 9, 53, 90, 178, 213, 154, 65, 127, 99, 22, 13, 4 }))
                        .setDigits(new short[]{2756, 1111, 965, 0, 6, 200, 78, 9, 53, 90, 178, 213, 154, 65, 127, 99, 22, 13, 4})
                        .build();
        // 2 powers cached - radix^4, (radix^4)^2
        RadixConverter radixConverter = new RadixConverter(arg.getRadix(), 2);
        checkAtLeastNDigitGroupsForTestCase(5, arg, radixConverter);
        runTest(arg, radixConverter);
    }

    private void runTest(RadixConversionArgument arg, RadixConverter radixConverter)
    {
        short[] digits = new short[arg.getDigits().length];
        radixConverter.toEncoding(arg.getDecimalNumber(), arg.getNumberOfDigits(), digits);
        isTrue("digits in base " + arg.getRadix() + " and expected digits are different.\nActual digits: [" + arrayToString(digits) +"]\nExpected digits: ["+ arrayToString(arg.getDigits()) +"]",
                Arrays.equals(digits, arg.getDigits()));
        BigInteger number = radixConverter.fromEncoding(digits);
        isEquals(number + " and " + arg.getDecimalNumber() + " are different", number, arg.getDecimalNumber());
    }

    private String arrayToString(short[] array)
    {
        StringBuffer sb = new StringBuffer(array.length);
        for (int i = 0; i != array.length; i++)
        {
            short el = array[i];
            sb.append(el).append(", ");
        }
        String str = sb.toString();
        return str.length() == 0 ? str : str.substring(0, str.length() - 1);
    }

    private BigInteger decimalInPolynomialForm(int radix, int[] coefficients)
    {
        BigInteger r = BigInteger.valueOf(radix);
        BigInteger result = BigInteger.ZERO;
        for (int i = 0; i < coefficients.length; i++)
        {
            int coefficient = coefficients[i];
            int exponent = coefficients.length - i - 1;
            result = result.add(BigInteger.valueOf(coefficient).multiply(r.pow(exponent)));
        }
        return result;
    }

    private void checkAtLeastNDigitGroupsForTestCase(int atLeastDigitGroups, RadixConversionArgument arg, RadixConverter radixConverter)
    {
        int groupLength = radixConverter.getDigitsGroupLength();
        int minDigits = (groupLength * (atLeastDigitGroups - 1)) + 1;
        isTrue("test case is for large numbers. The number must have at least " + minDigits + " digits so that at least "+atLeastDigitGroups+" digits groups of length "+groupLength+" are found in it. Found "+arg.getDigits().length+" digits",
                arg.getDigits().length >= minDigits);
    }

    public String getName()
    {
        return "RadixConverterTest";
    }

    public static void main(String[] args)
    {
        runTest(new RadixConverterTest());
    }

    private static class RadixConversionArgument
    {

        private final BigInteger decimalNumber;
        private final int radix;
        private final int numberOfDigits;
        private final short[] digits;

        private RadixConversionArgument(BigInteger decimalNumber, int radix, int numberOfDigits, short[] digits)
        {
            this.decimalNumber = decimalNumber;
            this.radix = radix;
            this.numberOfDigits = numberOfDigits;
            this.digits = digits;
        }

        public BigInteger getDecimalNumber()
        {
            return decimalNumber;
        }

        public int getRadix()
        {
            return radix;
        }

        public int getNumberOfDigits()
        {
            return numberOfDigits;
        }

        public short[] getDigits()
        {
            return digits;
        }

        static RadixConversionArgumentBuilder builder()
        {
            return new RadixConversionArgumentBuilder();
        }

        static class RadixConversionArgumentBuilder
        {

            private BigInteger decimalNumber;
            private int radix;
            private int numberOfDigits;
            private short[] digits;

            RadixConversionArgumentBuilder setDecimalNumber(BigInteger decimalNumber)
            {
                this.decimalNumber = decimalNumber;
                return this;
            }

            RadixConversionArgumentBuilder setRadix(int radix)
            {
                this.radix = radix;
                return this;
            }

            RadixConversionArgumentBuilder setNumberOfDigits(int numberOfDigits)
            {
                this.numberOfDigits = numberOfDigits;
                return this;
            }

            RadixConversionArgumentBuilder setDigits(short[] digits)
            {
                this.digits = digits;
                return this;
            }

            RadixConversionArgument build()
            {
                return new RadixConversionArgument(decimalNumber, radix, numberOfDigits, digits);
            }
        }
    }
}
