package org.bouncycastle.util.encoders.test;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Base32;
import org.bouncycastle.util.encoders.Base32Encoder;
import org.bouncycastle.util.encoders.DecoderException;
import org.bouncycastle.util.encoders.Encoder;
import org.bouncycastle.util.encoders.Hex;

public class Base32Test
    extends AbstractCoderTest
{
    // from rfc 4648
    String v1 = "";
    String r1 = "";

    String v2 = "f";
    String r2 = "MY======";

    String v3 = "fo";
    String r3 = "MZXQ====";

    String v4 = "foo";
    String r4 = "MZXW6===";

    String v5 = "foob";
    String r5 = "MZXW6YQ=";

    String v6 = "fooba";
    String r6 = "MZXW6YTB";

    String v7 = "foobar";
    String r7 = "MZXW6YTBOI======";

    String v8 = "The quick brown fox jumped over the lazy dog.";
    String r8 = "KRUGKIDROVUWG2ZAMJZG653OEBTG66BANJ2W24DFMQQG65TFOIQHI2DFEBWGC6TZEBSG6ZZO";

    String v9 = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
    String r9 = "MFRGGZDFMZTWQ2LKNNWG23TPOBYXE43UOV3HO6DZPJAUEQ2EIVDEOSCJJJFUYTKOJ5IFCUSTKRKVMV2YLFNA====";

    byte[] v10 = Hex.decode("FF 62 63 FF 65 66 67 68 69 6a 6b 6c 6d 6e 6f 70 71 72 73 74 75 76 77 FA 79 7a 41 FF 43 44 45 46 47 48 49 4a FF 4c 4d 4e 4f 50 51 52 53 54 55 56 57 58 59 5a");
    String r10 = "75RGH73FMZTWQ2LKNNWG23TPOBYXE43UOV3HP6TZPJA76Q2EIVDEOSCJJL7UYTKOJ5IFCUSTKRKVMV2YLFNA====";

    private static final String invalid1 = "%ZXXOIDJOMQHI2DFEB2GS3LFEBTG64RAMFWGY===";
    private static final String invalid2 = "J%XXOIDJOMQHI2DFEB2GS3LFEBTG64RAMFWGY===";
    private static final String invalid3 = "JZ%XOIDJOMQHI2DFEB2GS3LFEBTG64RAMFWGY====";
    private static final String invalid4 = "JZX%OIDJOMQHI2DFEB2GS3LFEBTG64RAMFWGY===";
    private static final String invalid5 = "JZXX%IDJOMQHI2DFEB2GS3LFEBTG64RAMFWGY===";
    private static final String invalid6 = "JZXXO%DJOMQHI2DFEB2GS3LFEBTG64RAMFWGY===";
    private static final String invalid7 = "JZXXOIDJOMQHI2DFEB2GS3LFEBTG64RAMFWGY==";
    private static final String invalid8 = "JZXXOIDJOMQHI2DFEB2GS3LFEBTG64RAMFWGY==%";
    private static final String invalid9 = "JZXXOIDJOMQHI2DFEB2GS3LFEBTG64RAMFWGY%==";
    private static final String invalida = "JZXXOIDJO=======";
    private static final String invalidb = "JZXXOIDJO======";
    private static final String invalidc = "JZXXOIDJO====";
    private static final String invalidd = "JZXXOIDJO=====";
    private static final String invalide = "JZXXOIDJO===";
    private static final String invalidf = "DAXFSKJDQSBTYW";
    private static final String invalidg = "M";

    public Base32Test(
        String    name)
    {
        super(name);
    }
    
    protected void setUp()
    {
        super.setUp();
        enc = new Base32Encoder();
    }

    public void testSamples()
        throws IOException
    {
        assertTrue(Arrays.areEqual(Strings.toByteArray(r1), Base32.encode(Strings.toByteArray(v1))));
        assertTrue(Arrays.areEqual(Strings.toByteArray(r2), Base32.encode(Strings.toByteArray(v2))));
        assertTrue(Arrays.areEqual(Strings.toByteArray(r3), Base32.encode(Strings.toByteArray(v3))));
        assertTrue(Arrays.areEqual(Strings.toByteArray(r4), Base32.encode(Strings.toByteArray(v4))));
        assertTrue(Arrays.areEqual(Strings.toByteArray(r5), Base32.encode(Strings.toByteArray(v5))));
        assertTrue(Arrays.areEqual(Strings.toByteArray(r6), Base32.encode(Strings.toByteArray(v6))));
        assertTrue(Arrays.areEqual(Strings.toByteArray(r7), Base32.encode(Strings.toByteArray(v7))));
        assertTrue(Arrays.areEqual(Strings.toByteArray(r8), Base32.encode(Strings.toByteArray(v8))));
        assertTrue(Arrays.areEqual(Strings.toByteArray(r9), Base32.encode(Strings.toByteArray(v9))));
        assertTrue(Arrays.areEqual(Strings.toByteArray(r10), Base32.encode(v10)));

        assertTrue(Arrays.areEqual(Strings.toByteArray(v1), Base32.decode(r1)));
        assertTrue(Arrays.areEqual(Strings.toByteArray(v2), Base32.decode(r2)));
        assertTrue(Arrays.areEqual(Strings.toByteArray(v3), Base32.decode(r3)));
        assertTrue(Arrays.areEqual(Strings.toByteArray(v4), Base32.decode(r4)));
        assertTrue(Arrays.areEqual(Strings.toByteArray(v5), Base32.decode(r5)));
        assertTrue(Arrays.areEqual(Strings.toByteArray(v6), Base32.decode(r6)));
        assertTrue(Arrays.areEqual(Strings.toByteArray(v7), Base32.decode(r7)));
        assertTrue(Arrays.areEqual(Strings.toByteArray(v8), Base32.decode(r8)));
        assertTrue(Arrays.areEqual(Strings.toByteArray(v9), Base32.decode(r9)));
        assertTrue(Arrays.areEqual(v10, Base32.decode(r10)));

        Base32Encoder b32Encoder = new Base32Encoder();

        lengthCheck(b32Encoder, r1, v1);
        lengthCheck(b32Encoder, r2, v2);
        lengthCheck(b32Encoder, r3, v3);
        lengthCheck(b32Encoder, r4, v4);
        lengthCheck(b32Encoder, r5, v5);
        lengthCheck(b32Encoder, r6, v6);
        lengthCheck(b32Encoder, r7, v7);
        lengthCheck(b32Encoder, r8, v8);
        lengthCheck(b32Encoder, r9, v9);
    }

    private void lengthCheck(Encoder encoder, String r, String v)
    {
        assertEquals(r.length(), encoder.getEncodedLength(v.length()));
        assertEquals(((v.length() + 4) / 5) * 5, encoder.getMaxDecodedLength(r.length()));
    }

    public void testInvalidInput()
        throws IOException
    {
        String[] invalid = new String[] {
            invalid1, invalid2, invalid3, invalid4, invalid5, invalid6, invalid7, invalid8,
            invalid9, invalida, invalidb, invalidc, invalidd, invalide, invalidf, invalidg };

        for (int i = 0; i != invalid.length; i++)
        {
            invalidTest(invalid[i]);
            invalidTest(Strings.toByteArray(invalid[i]));
        }
    }

    public void testWithWhitespace()
        throws Exception
    {
        String data = "ORSXG5DTORZG" + "\r\n" + "               " + "S3TH";

        assertTrue(Arrays.areEqual(Strings.toByteArray("teststring"), Base32.decode(data)));

        byte[] bData = Strings.toByteArray(data);
        assertTrue(Arrays.areEqual(Strings.toByteArray("teststring"), Base32.decode(bData)));

        ByteArrayOutputStream bOut = new ByteArrayOutputStream();

        Base32.decode(Arrays.concatenate(new byte[4], bData), 4, bData.length, bOut);

        assertTrue(Arrays.areEqual(Strings.toByteArray("teststring"), bOut.toByteArray()));
    }

    public void testWithSpecificAlphabet()
        throws Exception
    {
        // try base 32 hex
        Base32Encoder b32Encoder = new Base32Encoder(
            Strings.toByteArray("0123456789ABCDEFGHIJKLMNOPQRSTUV"), (byte)'=');

        byte[] v1 = Strings.toByteArray("Now is the time for all");
        byte[] r1 = Strings.toByteArray("9PNNE839ECG78Q3541Q6IRB541J6USH0C5M6O===");

        ByteArrayOutputStream bOut = new ByteArrayOutputStream(b32Encoder.getEncodedLength(v1.length));

        b32Encoder.encode(v1, 0, v1.length, bOut);

        assertEquals(((v1.length + 4) / 5) * 5, b32Encoder.getMaxDecodedLength(r1.length));
        assertEquals(bOut.toByteArray().length, b32Encoder.getEncodedLength(v1.length));
        assertTrue(Arrays.areEqual(bOut.toByteArray(), r1));

        bOut = new ByteArrayOutputStream(b32Encoder.getMaxDecodedLength(r1.length));

        b32Encoder.decode(r1, 0, r1.length, bOut);

        assertTrue(Arrays.areEqual(bOut.toByteArray(), v1));
    }

    private void invalidTest(String data)
    {
        try
        {
            Base32.decode(data);
        }
        catch (DecoderException e)
        {
            return;
        }

        fail("invalid String data parsed");
    }

    private void invalidTest(byte[] data)
    {
        try
        {
            Base32.decode(data);
        }
        catch (DecoderException e)
        {
            return;
        }

        fail("invalid byte data parsed");
    }

    protected char paddingChar()
    {
        return '=';
    }

    protected boolean isEncodedChar(char c)
    {
        return "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567".indexOf(c) >= 0;
    }
}
