package org.bouncycastle.util.encoders.test;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Arrays;
import java.util.Random;

import junit.framework.TestCase;

import org.bouncycastle.util.encoders.Encoder;

public abstract class AbstractCoderTest extends TestCase
{

    private static final int[] SIZES_TO_CHECK = {64, 128, 1024, 1025, 1026, 2048,
        2049, 2050, 4096, 4097, 4098, 8192, 8193, 8194};
    
    protected Encoder enc;
    private Random r;

    AbstractCoderTest(
        String    name)
    {
        super(name);
    }
    
    protected void setUp()
    {
        r = new Random();
    }

    private void checkArrayOfSize(int size) 
        throws IOException
    {
        byte[] original = new byte[size];
        r.nextBytes(original);
        
        ByteArrayOutputStream    bOut = new ByteArrayOutputStream();
        enc.encode(original, 0, original.length, bOut);
        
        byte[] encoded = bOut.toByteArray();

        assertTrue(encoded.length > original.length);
        assertTrue(encoded.length <= (original.length * 2));
        checkEncoding(encoded);
        checkSimpleDecode(original, encoded);
        checkStringDecode(original, encoded);
        checkOutputStreamDecode(original, encoded);
        
        int    offset = r.nextInt(20);
        byte[] offsetEncoded = new byte[offset + encoded.length];
        System.arraycopy(encoded, 0, offsetEncoded, offset, encoded.length);
        checkOffsetDecode(original, offsetEncoded, offset, encoded.length);
        
        offset = r.nextInt(20);
        byte[] offsetOriginal = new byte[offset + original.length];
        System.arraycopy(original, 0, offsetOriginal, offset, original.length);
        checkOffsetEncode(original, offsetOriginal, offset, original.length);
        
        byte[] encodedWithSpace = addWhitespace(encoded);
        checkSimpleDecode(original, encodedWithSpace);
        checkStringDecode(original, encodedWithSpace);
        checkOutputStreamDecode(original, encodedWithSpace);
    }

    public void testEncode()
        throws IOException
    {
        for (int i = 0; i < SIZES_TO_CHECK.length; i++)
        {
            checkArrayOfSize(SIZES_TO_CHECK[i]);
        }
    }

    private void checkEncoding(byte[] encoded)
    {
        String encString = convertBytesToString(encoded);
        for (int i = 0; i < encString.length(); i++)
        {
            char c = encString.charAt(i);
            if (c == paddingChar())
            {
                // should only be padding at end of string
                assertTrue(i > encString.length() - 3);
                continue;
            }
            else if (isEncodedChar(c))
            {
                continue;
            }
            fail("Unexpected encoded character " + c);
        }
    }

    private void checkOutputStreamDecode(byte[] original, byte[] encoded)
    {
        String encString = convertBytesToString(encoded);
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        try
        {
            assertEquals(original.length, enc.decode(encString, out));
            assertTrue(Arrays.equals(original, out.toByteArray()));
        }
        catch (IOException e)
        {
            fail("This shouldn't happen");
        }
    }

    private void checkSimpleDecode(byte[] original, byte[] encoded) 
        throws IOException
    {
        ByteArrayOutputStream    bOut = new ByteArrayOutputStream();
        enc.decode(encoded, 0, encoded.length, bOut);

        assertTrue(Arrays.equals(original, bOut.toByteArray()));
    }
    
    private void checkOffsetEncode(byte[] original, byte[] offsetOriginal, int off, int length) 
        throws IOException
    {
        ByteArrayOutputStream    bOut = new ByteArrayOutputStream();
        
        enc.encode(offsetOriginal, off, length, bOut);
        
        byte[] encoded = bOut.toByteArray();
        
        bOut.reset();
        
        enc.decode(encoded, 0, encoded.length, bOut);

        assertTrue(Arrays.equals(original, bOut.toByteArray()));
    }
    
    private void checkOffsetDecode(byte[] original, byte[] encoded, int off, int length) 
        throws IOException
    {
        ByteArrayOutputStream    bOut = new ByteArrayOutputStream();
        enc.decode(encoded, off, length, bOut);

        assertTrue(Arrays.equals(original, bOut.toByteArray()));
    }
    
    private void checkStringDecode(byte[] original, byte[] encoded) 
        throws IOException
    {
        String encString = convertBytesToString(encoded);
        ByteArrayOutputStream    bOut = new ByteArrayOutputStream();
        enc.decode(encString, bOut);
        assertTrue(Arrays.equals(original, bOut.toByteArray()));
    }

    private byte[] addWhitespace(byte[] encoded)
    {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        addSpace(out);
        for (int i = 0; i < encoded.length - 5; i++)
        {
            out.write(encoded, i, 1);
            if (r.nextInt(100) < 5)
            {
                addSpace(out);
            }
        }
        for (int i = encoded.length - 5; i < encoded.length; i++)
        {
            out.write(encoded, i, 1);
        }
        addSpace(out);
        return out.toByteArray();
    }

    private void addSpace(ByteArrayOutputStream out)
    {
        do
        {
            switch (r.nextInt(3))
            {
                case 0 :
                    out.write((int) '\n');
                    break;
                case 1 :
                    out.write((int) '\r');
                    break;
                case 2 :
                    out.write((int) '\t');
                    break;
                case 3 :
                    out.write((int) ' ');
                    break;
            }
        } while (r.nextBoolean());
    }

    private String convertBytesToString(byte[] encoded)
    {
        StringBuffer    b = new StringBuffer();
        
        for (int i = 0; i != encoded.length; i++)
        {
            b.append((char)(encoded[i] & 0xff));
        }
        
        return b.toString();
    }

    abstract protected char paddingChar();

    abstract protected boolean isEncodedChar(char c);

}
