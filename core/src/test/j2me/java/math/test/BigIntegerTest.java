package java.math.test;

import java.math.BigInteger;
import java.security.SecureRandom;
import org.bouncycastle.util.test.*;

public class BigIntegerTest
    extends SimpleTest
{
    private static BigInteger VALUE1 = new BigInteger("1234");
    private static BigInteger VALUE2 = new BigInteger("1234567890");
    private static BigInteger VALUE3 = new BigInteger("12345678901234567890123");

    private static BigInteger zero = BigInteger.ZERO;
    private static BigInteger one = BigInteger.ONE;
    private static BigInteger two = BigInteger.valueOf(2);

    public String getName()
    {
        return "BigInteger";
    }

    private void clearBitTest()
    {
        BigInteger value = VALUE1.clearBit(3);
        BigInteger result = new BigInteger("1234");
        
        if (!value.equals(result))
        {
            fail("clearBit - expected: " + result + " got: " + value);
        }
        
        value = VALUE2.clearBit(3);
        result = new BigInteger("1234567890");
        
        if (!value.equals(result))
        {
            fail("clearBit - expected: " + result + " got: " + value);
        }
        
        value = VALUE3.clearBit(3);
        result = new BigInteger("12345678901234567890115");
        
        if (!value.equals(result))
        {
            fail("clearBit - expected: " + result + " got: " + value);
        }
        
        value = VALUE2.clearBit(55);
        result = new BigInteger("1234567890");
        
        if (!value.equals(result))
        {
            fail("clearBit - expected: " + result + " got: " + value);
        }
        
        value = VALUE3.clearBit(55);
        result = new BigInteger("12345642872437548926155");
        
        if (!value.equals(result))
        {
            fail("clearBit - expected: " + result + " got: " + value);
        }
    }
    
    private void flipBitTest()
    {
        BigInteger value = VALUE1.flipBit(3);
        BigInteger result = new BigInteger("1242");
        
        if (!value.equals(result))
        {
            fail("flipBit - expected: " + result + " got: " + value);
        }
        
        value = VALUE2.flipBit(3);
        result = new BigInteger("1234567898");
        
        if (!value.equals(result))
        {
            fail("flipBit - expected: " + result + " got: " + value);
        }
        
        value = VALUE3.flipBit(3);
        result = new BigInteger("12345678901234567890115");
        
        if (!value.equals(result))
        {
            fail("flipBit - expected: " + result + " got: " + value);
        }
        
        value = VALUE2.flipBit(55);
        result = new BigInteger("36028798253531858");
        
        if (!value.equals(result))
        {
            fail("flipBit - expected: " + result + " got: " + value);
        }
        
        value = VALUE3.flipBit(55);
        result = new BigInteger("12345642872437548926155");
        
        if (!value.equals(result))
        {
            fail("flipBit - expected: " + result + " got: " + value);
        }
    }
    
    private void setBitTest()
    {
        BigInteger value = VALUE1.setBit(3);
        BigInteger result = new BigInteger("1242");
        
        if (!value.equals(result))
        {
            fail("setBit - expected: " + result + " got: " + value);
        }
        
        value = VALUE2.setBit(3);
        result = new BigInteger("1234567898");
        
        if (!value.equals(result))
        {
            fail("setBit - expected: " + result + " got: " + value);
        }
        
        value = VALUE3.setBit(3);
        result = new BigInteger("12345678901234567890123");
        
        if (!value.equals(result))
        {
            fail("setBit - expected: " + result + " got: " + value);
        }
        
        value = VALUE2.setBit(55);
        result = new BigInteger("36028798253531858");
        
        if (!value.equals(result))
        {
            fail("setBit - expected: " + result + " got: " + value);
        }
        
        value = VALUE3.setBit(55);
        result = new BigInteger("12345678901234567890123");
        
        if (!value.equals(result))
        {
            fail("setBit - expected: " + result + " got: " + value);
        }
    }

    private void testDivideAndRemainder()
    {
        SecureRandom random = new SecureRandom();

        BigInteger n = new BigInteger(48, random);
        BigInteger[] qr = n.divideAndRemainder(n);
        if (!qr[0].equals(one) || !qr[1].equals(zero))
        {
            fail("testDivideAndRemainder - expected: 1/0 got: " + qr[0] + "/" + qr[1]);
        }
        qr = n.divideAndRemainder(one);
        if (!qr[0].equals(n) || !qr[1].equals(zero))
        {
            fail("testDivideAndRemainder - expected: " + n + "/0 got: " + qr[0] + "/" + qr[1]);
        }

        for (int rep = 0; rep < 10; ++rep)
        {
            BigInteger a = new BigInteger(100 - rep, 0, random);
            BigInteger b = new BigInteger(100 + rep, 0, random);
            BigInteger c = new BigInteger(10 + rep, 0, random);
            BigInteger d = a.multiply(b).add(c);
            BigInteger[] es = d.divideAndRemainder(a);

            if (!es[0].equals(b) || !es[1].equals(c))
            {
                fail("testDivideAndRemainder - expected: " + b + "/" + c + " got: " + qr[0] + "/" + qr[1]);
            }
        }
    }

    private void testModInverse()
    {
        SecureRandom random = new SecureRandom();

        for (int i = 0; i < 10; ++i)
        {
            BigInteger p = BigInteger.probablePrime(64, random);
            BigInteger q = new BigInteger(63, random).add(one);
            BigInteger inv = q.modInverse(p);
            BigInteger inv2 = inv.modInverse(p);

            if (!q.equals(inv2))
            {
                fail("testModInverse failed symmetry test");
            }
            BigInteger check = q.multiply(inv).mod(p); 
            if (!one.equals(check))
            {
                fail("testModInverse - expected: 1  got: " + check);
            }
        }

        // ModInverse for powers of 2
        for (int i = 1; i <= 128; ++i)
        {
            BigInteger m = one.shiftLeft(i);
            BigInteger d = new BigInteger(i, random).setBit(0);
            BigInteger x = d.modInverse(m);
            BigInteger check = x.multiply(d).mod(m);
            if (!one.equals(check))
            {
                fail("testModInverse - expected: 1  got: " + check);
            }
        }
    }

    private void testNegate()
    {
        if (!zero.equals(zero.negate()))
        {
            fail("zero - negate falied");
        }
        if (!one.equals(one.negate().negate()))
        {
            fail("one - negate falied");
        }
        if (!two.equals(two.negate().negate()))
        {
            fail("two - negate falied");
        }
    }

    private void testNot()
    {
        for (int i = -10; i <= 10; ++i)
        {
            if(!BigInteger.valueOf(~i).equals(
                     BigInteger.valueOf(i).not()))
            {
                fail("Problem: ~" + i + " should be " + ~i);
            }
        }
    }

    private void testOr()
    {
        for (int i = -10; i <= 10; ++i)
        {
            for (int j = -10; j <= 10; ++j)
            {
                if (!BigInteger.valueOf(i | j).equals(
                    BigInteger.valueOf(i).or(BigInteger.valueOf(j))))
                {
                    fail("Problem: " + i + " OR " + j + " should be " + (i | j));
                }
            }
        }
    }

    public void testPow()
    {
        if (!one.equals(zero.pow(0)))
        {
            fail("one pow equals failed");
        }
        if (!zero.equals(zero.pow(123)))
        {
            fail("zero pow equals failed");
        }
        if (!one.equals(one.pow(0)))
        {
            fail("one one equals failed");
        }
        if (!one.equals(one.pow(123)))
        {
            fail("1 123 equals failed");
        }

        if (!two.pow(147).equals(one.shiftLeft(147)))
        {
            fail("2 pow failed");
        }
        if (!one.shiftLeft(7).pow(11).equals(one.shiftLeft(77)))
        {
            fail("pow 2 pow failed");
        }

        BigInteger n = new BigInteger("1234567890987654321");
        BigInteger result = one;

        for (int i = 0; i < 10; ++i)
        {
            try
            {
                BigInteger.valueOf(i).pow(-1);
                fail("expected ArithmeticException");
            }
            catch (ArithmeticException e) {}

            if (!result.equals(n.pow(i)))
            {
                fail("mod pow equals failed");
            }

            result = result.multiply(n);
        }
    }

    public void testToString()
    {
        SecureRandom random = new SecureRandom();
        int trials = 256;

        BigInteger[] tests = new BigInteger[trials];
        for (int i = 0; i < trials; ++i)
        {
            int len = random.nextInt(i + 1);
            tests[i] = new BigInteger(len, random);
        }

        for (int radix = Character.MIN_RADIX; radix <= Character.MAX_RADIX; ++radix)
        {
            for (int i = 0; i < trials; ++i)
            {
                BigInteger n1 = tests[i];
                String s = n1.toString(radix);
                BigInteger n2 = new BigInteger(s, radix);
                if (!n1.equals(n2))
                {
                    fail("testToStringRadix - radix:" + radix + ", n1:" + n1.toString(16) + ", n2:" + n2.toString(16));
                }
            }
        }
    }

    private void xorTest()
    {
        BigInteger value = VALUE1.xor(VALUE2);
        BigInteger result = new BigInteger("1234568704");
        
        if (!value.equals(result))
        {
            fail("xor - expected: " + result + " got: " + value);
        }
        
        value = VALUE1.xor(VALUE3);
        result = new BigInteger("12345678901234567888921");
        
        if (!value.equals(result))
        {
            fail("xor - expected: " + result + " got: " + value);
        }
        
        value = VALUE3.xor(VALUE1);
        result = new BigInteger("12345678901234567888921");
        
        if (!value.equals(result))
        {
            fail("xor - expected: " + result + " got: " + value);
        }
        
        value = VALUE2.xor(new BigInteger("-1"));
        result = new BigInteger("-1234567891");
        
        if (!value.equals(result))
        {
            fail("xor - expected: " + result + " got: " + value);
        }
        
        value = VALUE3.xor(VALUE3);
        result = new BigInteger("0");
        
        if (!value.equals(result))
        {
            fail("xor - expected: " + result + " got: " + value);
        }
    }
    
    public void performTest()
    {
        clearBitTest();
        
        flipBitTest();
        
        setBitTest();

        testDivideAndRemainder();
        testModInverse();
        testNegate();
        testNot();
        testOr();
        testPow();
        testToString();
        
        xorTest();
        
        BigInteger n1, n2, r1;

    // test division where the difference in bit length of the dividend and divisor is 32 bits 
        n1 = new BigInteger("54975581388");
        n2 = new BigInteger("10");
        r1 = n1.divide(n2);
        if (!r1.toString(10).equals("5497558138"))
        {
                fail("BigInteger: failed Divide Test");
        }

        // two's complement test
        byte[] zeroBytes = BigInteger.ZERO.toByteArray();
        byte[] oneBytes = BigInteger.ONE.toByteArray();
        byte[] minusOneBytes = BigInteger.ONE.negate().toByteArray();
    
        BigInteger zero = new BigInteger(zeroBytes);
        if (!zero.equals(BigInteger.ZERO))
        {
            fail("Failed constructing zero");
        }

        BigInteger one = new BigInteger(oneBytes);
        if (!one.equals(BigInteger.ONE))
        {
            fail("Failed constructing one");
        }

        BigInteger minusOne = new BigInteger(minusOneBytes);
        if (!minusOne.equals(BigInteger.ONE.negate()))
        {
            fail("Failed constructing minus one");
        }
    
        SecureRandom random = new SecureRandom();
        byte[] randomBytes = new byte[100];
        for (int i=0; i < 100; i++)
        {
            random.nextBytes(randomBytes);
            BigInteger bcInt = new BigInteger(randomBytes);
            BigInteger bcInt2 = new BigInteger(bcInt.toByteArray());
            if (!bcInt.equals(bcInt2))
            {
                fail("Failed constructing random value " + i);
            }
            
//            java.math.BigInteger jdkInt = new java.math.BigInteger(randomBytes);
//            byte[] bcBytes = bcInt.toByteArray();
//            byte[] jdkBytes = jdkInt.toByteArray();
//            if (!arrayEquals(bcBytes, jdkBytes))
//            {
//                fail(""Failed constructing random value " + i);
//            }
        }
    }

    public static void main(
        String[]    args)
    {
        runTest(new BigIntegerTest());
    }
}

