package org.bouncycastle.mls.test;

import junit.framework.TestCase;
import junit.framework.TestSuite;
import org.bouncycastle.PrintTestResult;
import org.bouncycastle.mls.codec.Encoder;
import org.bouncycastle.mls.codec.MLSField;
import org.bouncycastle.util.encoders.Hex;

import java.util.Arrays;
import java.util.List;

import static org.junit.Assert.assertArrayEquals;

public class CodecTest
    extends TestCase
{
    private final boolean valBool = true;
    private final String encBool = "01";
    private final byte valUint8 = 0x11;
    private final String encUint8 = "11";
    private final short valUint16 = 0x2222;
    private final String encUint16 = "2222";
    private final int valUint32 = 0x44444444;
    private final String encUint32 = "44444444";
    private final long valUint64 = 0x8888888888888888L;
    private final String encUint64 = "8888888888888888";
    private final short[] valArray = {1, 2, 3, 4};
    private final String encArray = "0001000200030004";
    private final List<Integer> valList = Arrays.asList(5, 6, 7, 8);
    private final String encList = "1000000005000000060000000700000008";

    public static class ExampleStruct {
        @MLSField(order=1)
        public short a;

        @MLSField(order=2, length=4)
        public int[] b;

        @MLSField(order=3, optional=true)
        public Byte c;

        @MLSField(order=4)
        public List<Byte> d;

        public ExampleStruct(short aIn, int[] bIn, Byte cIn, List<Byte> dIn) {
            a = aIn;
            b = bIn;
            c = cIn;
            d = dIn;
        }
    }

    private final ExampleStruct valStruct = new ExampleStruct((short) 0x1111,
            new int[] { 0x22222222, 0x33333333, 0x44444444, 0x55555555 },
            (byte) 0x66,
            Arrays.asList((byte) 0x77, (byte) 0x88));
    private final String encStruct = "1111222222223333333344444444555555550166027788";

    public static class ExampleOptional {
        @MLSField(order=1, optional=true)
        public final Integer value;

        public ExampleOptional() {
            value = null;
        }

        public ExampleOptional(int valueIn) {
            value = valueIn;
        }
    }
    private final ExampleOptional valOptional = new ExampleOptional(0x12345678);
    private final String encOptional = "0112345678";
    private final ExampleOptional valOptionalNull = new ExampleOptional();
    private final String encOptionalNull = "00";

    private <T> void doEncodeTest(T val, String hexExpected) throws Exception {
        byte[] expected = Hex.decode(hexExpected);
        Encoder enc = new Encoder();
        enc.encode(val);
        byte[] actual = enc.toByteArray();
        assertArrayEquals(actual, expected);
    }

    public void testEncode() throws Exception {
        doEncodeTest(valBool, encBool);
        doEncodeTest(valUint8, encUint8);
        doEncodeTest(valUint16, encUint16);
        doEncodeTest(valUint32, encUint32);
        doEncodeTest(valUint64, encUint64);
        doEncodeTest(valArray, encArray);
        doEncodeTest(valList, encList);
        doEncodeTest(valStruct, encStruct);
        doEncodeTest(valOptional, encOptional);
        doEncodeTest(valOptionalNull, encOptionalNull);
    }

    public static TestSuite suite()
    {
        return new TestSuite(CodecTest.class);
    }

    public static void main(String[] args)
    {
        PrintTestResult.printResult(junit.textui.TestRunner.run(suite()));
    }
}
