package org.bouncycastle.mls.test;

import junit.framework.TestCase;
import junit.framework.TestSuite;
import org.bouncycastle.PrintTestResult;
import org.bouncycastle.mls.codec.*;
import org.bouncycastle.util.encoders.Hex;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;

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

    public static class ExampleStruct implements MLSInputStream.Readable, MLSOutputStream.Writable {
        public short a;
        public Integer[] b;
        public Byte c;
        public ArrayList<Byte> d;
        public byte[] e;

        public ExampleStruct(short a, Integer[] b, Byte c, ArrayList<Byte> d, byte[] e) {
            this.a = a;
            this.b = b;
            this.c = c;
            this.d = d;
            this.e = e;
        }

        @SuppressWarnings("unused")
        public ExampleStruct(MLSInputStream stream) throws IOException {
            this.a = (short) stream.read(short.class);
            this.b = (Integer[]) stream.readArray(Integer.class, 4);
            this.c = (byte) stream.readOptional(byte.class);

            this.d = new ArrayList<>();
            stream.readList(this.d, byte.class);

            this.
                    e = stream.readOpaque();
        }

        @Override
        public void writeTo(MLSOutputStream stream) throws IOException {
            stream.write(this.a);
            stream.writeArray(this.b);
            stream.writeOptional(this.c);
            stream.writeList(this.d);
            stream.writeOpaque(this.e);
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;
            ExampleStruct that = (ExampleStruct) o;
            return a == that.a && Arrays.equals(b, that.b) && c.equals(that.c) && d.equals(that.d);
        }
    }

    private final ExampleStruct valStruct = new ExampleStruct((short) 0x1111,
            new Integer[] { 0x22222222, 0x33333333, 0x44444444, 0x55555555 },
            (byte) 0x66,
            new ArrayList<>(Arrays.asList((byte) 0x77, (byte) 0x88)),
            new byte[] {(byte) 0x99, (byte) 0x99, (byte) 0x99, (byte) 0x99});
    private final String encStruct = "11112222222233333333444444445555555501660277880499999999";

    protected <T> void doWriteTest(T val, String hexExpected) throws Exception {
        byte[] actual = MLSOutputStream.encode(val);
        String hexActual = Hex.toHexString(actual);
        assertEquals(hexActual, hexExpected);
    }

    public void testWrite() throws Exception {
        doWriteTest(valBool, encBool);
        doWriteTest(valUint8, encUint8);
        doWriteTest(valUint16, encUint16);
        doWriteTest(valUint32, encUint32);
        doWriteTest(valUint64, encUint64);
        doWriteTest(valStruct, encStruct);
    }

    protected <T> void doReadTest(String hexEncoded, T expected) throws Exception {
        byte[] encoded = Hex.decode(hexEncoded);
        @SuppressWarnings("unchecked")
        T actual = (T) MLSInputStream.decode(encoded, expected.getClass());
        assertEquals(actual, expected);
    }

    public void testRead() throws Exception {
        doReadTest(encBool, valBool);
        doReadTest(encUint8, valUint8);
        doReadTest(encUint16, valUint16);
        doReadTest(encUint32, valUint32);
        doReadTest(encUint64, valUint64);
        doReadTest(encStruct, valStruct);
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
