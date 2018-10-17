package org.bouncycastle.util.encoders.test;

import java.security.SecureRandom;

import org.bouncycastle.util.encoders.UTF8;
import org.bouncycastle.util.test.SimpleTest;

public class UTF8Test
    extends SimpleTest
{
    private static SecureRandom R = new SecureRandom();

    public String getName()
    {
        return "UTF8";
    }

    public static void main(String[] args)
    {
        runTest(new UTF8Test());
    }

    public void performTest() throws Exception
    {
        for (int i = 0; i < 1000; ++i)
        {
            testBadPrefix2();
            testBadPrefix4();
            testBadSuffix_E0();
            testBadSuffix_ED();
            testBadSuffix_F0();
            testBadSuffix_F4();
            testIncomplete2_1();
            testIncomplete3_1();
            testIncomplete3_2();
            testIncomplete4_1();
            testIncomplete4_2();
            testIncomplete4_3();
            testLeadingSuffix();
            testTruncated2_1();
            testTruncated3_1();
            testTruncated3_2();
            testTruncated4_1();
            testTruncated4_2();
            testTruncated4_3();
            testValid1();
            testValid2();
            testValid3();
            testValid4();
        }
    }

    private void testBadPrefix2()
    {
        byte[] utf8 = new byte[2];
        char[] utf16 = new char[1];

        for (int i = 0x00; i < 0x02; ++i)
        {
            utf8[0] = (byte)(0xC0 | i);
            utf8[1] = randomSuffix();
            utf16[0] = (char)0;

            int result = UTF8.transcodeToUTF16(utf8, utf16);

            isEquals("testBadPrefix2", result, -1);
        }
    }

    private void testBadPrefix4()
    {
        byte[] utf8 = new byte[4];
        char[] utf16 = new char[2];

        for (int i = 0x05; i < 0x0F; ++i)
        {
            utf8[0] = (byte)(0xF0 | i);
            utf8[1] = randomSuffix();
            utf8[2] = randomSuffix();
            utf8[3] = randomSuffix();
            utf16[0] = (char)0;
            utf16[1] = (char)0;

            int result = UTF8.transcodeToUTF16(utf8, utf16);

            isEquals("testBadPrefix4", result, -1);
        }
        
    }

    private void testBadSuffix_E0()
    {
        byte[] utf8 = new byte[3];
        char[] utf16 = new char[1];

        utf8[0] = (byte)0xE0;
        utf8[1] = randomSuffix();
        utf8[2] = randomSuffix();
        utf16[0] = (char)0;

        utf8[1] &= 0x9F;

        int result = UTF8.transcodeToUTF16(utf8, utf16);

        isEquals("testBadSuffix_E0", result, -1);
    }

    private void testBadSuffix_ED()
    {
        byte[] utf8 = new byte[3];
        char[] utf16 = new char[1];

        utf8[0] = (byte)0xED;
        utf8[1] = randomSuffix();
        utf8[2] = randomSuffix();
        utf16[0] = (char)0;

        utf8[1] |= 0x20; 

        int result = UTF8.transcodeToUTF16(utf8, utf16);

        isEquals("testBadSuffix_ED", result, -1);
    }

    private void testBadSuffix_F0()
    {
        byte[] utf8 = new byte[4];
        char[] utf16 = new char[2];

        utf8[0] = (byte)0xF0;
        utf8[1] = randomSuffix();
        utf8[2] = randomSuffix();
        utf8[3] = randomSuffix();
        utf16[0] = (char)0;
        utf16[1] = (char)0;

        utf8[1] &= 0x8F;

        int result = UTF8.transcodeToUTF16(utf8, utf16);

        isEquals("testBadSuffix_F0", result, -1);
    }

    private void testBadSuffix_F4()
    {
        byte[] utf8 = new byte[4];
        char[] utf16 = new char[2];

        utf8[0] = (byte)0xF4;
        utf8[1] = randomSuffix();
        utf8[2] = randomSuffix();
        utf8[3] = randomSuffix();
        utf16[0] = (char)0;
        utf16[1] = (char)0;

        utf8[1] |= 0x10 << (R.nextInt() & 1);

        int result = UTF8.transcodeToUTF16(utf8, utf16);

        isEquals("testBadSuffix_F4", result, -1);
    }

    private void testIncomplete2_1()
    {
        byte[] utf8 = new byte[2];
        char[] utf16 = new char[1];

        for (int i = 0x02; i < 0x20; ++i)
        {
            utf8[0] = (byte)(0xC0 | i);
            utf8[1] = randomPrefix();
            utf16[0] = (char)0xFFFF;

            int result = UTF8.transcodeToUTF16(utf8, utf16);

            isEquals("testIncomplete2_1", result, -1);
        }
    }

    private void testIncomplete3_1()
    {
        byte[] utf8 = new byte[3];
        char[] utf16 = new char[1];

        for (int i = 0x00; i < 0x10; ++i)
        {
            utf8[0] = (byte)(0xE0 | i);
            utf8[1] = randomPrefix();
            utf8[2] = randomSuffix();
            utf16[0] = (char)0xFFFF;

            int result = UTF8.transcodeToUTF16(utf8, utf16);

            isEquals("testIncomplete3_1", result, -1);
        }
    }

    private void testIncomplete3_2()
    {
        byte[] utf8 = new byte[3];
        char[] utf16 = new char[1];

        for (int i = 0x00; i < 0x10; ++i)
        {
            utf8[0] = (byte)(0xE0 | i);
            utf8[1] = randomSuffix();
            utf8[2] = randomPrefix();
            utf16[0] = (char)0;

            if (i == 0x00)
            {
                utf8[1] |= 0x20; 
            }
            else if (i == 0x0D)
            {
                utf8[1] &= 0x9F;
            }

            int result = UTF8.transcodeToUTF16(utf8, utf16);

            isEquals("testIncomplete3_2", result, -1);
        }
        
    }

    private void testIncomplete4_1()
    {
        byte[] utf8 = new byte[4];
        char[] utf16 = new char[2];

        for (int i = 0x00; i < 0x05; ++i)
        {
            utf8[0] = (byte)(0xF0 | i);
            utf8[1] = randomPrefix();
            utf8[2] = randomSuffix();
            utf8[3] = randomSuffix();
            utf16[0] = (char)0;
            utf16[1] = (char)0;

            int result = UTF8.transcodeToUTF16(utf8, utf16);

            isEquals("testIncomplete4_1", result, -1);
        }
    }
    
    private void testIncomplete4_2()
    {
        byte[] utf8 = new byte[4];
        char[] utf16 = new char[2];

        for (int i = 0x00; i < 0x05; ++i)
        {
            utf8[0] = (byte)(0xF0 | i);
            utf8[1] = randomSuffix();
            utf8[2] = randomPrefix();
            utf8[3] = randomSuffix();
            utf16[0] = (char)0;
            utf16[1] = (char)0;

            if (i == 0x00)
            {
                utf8[1] |= 0x10 << (R.nextInt() & 1);
            }
            else if (i == 0x04)
            {
                utf8[1] &= 0x8F;
            }

            int result = UTF8.transcodeToUTF16(utf8, utf16);

            isEquals("testIncomplete4_2", result, -1);
        }
    }
    
    private void testIncomplete4_3()
    {
        byte[] utf8 = new byte[4];
        char[] utf16 = new char[2];

        for (int i = 0x00; i < 0x05; ++i)
        {
            utf8[0] = (byte)(0xF0 | i);
            utf8[1] = randomSuffix();
            utf8[2] = randomSuffix();
            utf8[3] = randomPrefix();
            utf16[0] = (char)0;
            utf16[1] = (char)0;

            if (i == 0x00)
            {
                utf8[1] |= 0x10 << (R.nextInt() & 1);
            }
            else if (i == 0x04)
            {
                utf8[1] &= 0x8F;
            }

            int result = UTF8.transcodeToUTF16(utf8, utf16);

            isEquals("testIncomplete4_3", result, -1);
        }
    }

    private void testLeadingSuffix()
    {
        byte[] utf8 = new byte[4];
        char[] utf16 = new char[4];

        for (int i = 0x80; i < 0xC0; ++i)
        {
            utf8[0] = (byte)i;
            utf8[1] = randomSuffix();
            utf8[2] = randomSuffix();
            utf8[3] = randomSuffix();

            int result = UTF8.transcodeToUTF16(utf8, utf16);

            isEquals("testLeadingSuffix", result, -1);
        }
    }

    private void testTruncated2_1()
    {
        byte[] utf8 = new byte[1];
        char[] utf16 = new char[1];

        for (int i = 0x02; i < 0x20; ++i)
        {
            utf8[0] = (byte)(0xC0 | i);
            utf16[0] = (char)0xFFFF;

            int result = UTF8.transcodeToUTF16(utf8, utf16);

            isEquals("testTruncated2_1", result, -1);
        }
    }

    private void testTruncated3_1()
    {
        byte[] utf8 = new byte[1];
        char[] utf16 = new char[1];

        for (int i = 0x00; i < 0x10; ++i)
        {
            utf8[0] = (byte)(0xE0 | i);
            utf16[0] = (char)0xFFFF;

            int result = UTF8.transcodeToUTF16(utf8, utf16);

            isEquals("testTruncated3_1", result, -1);
        }
    }

    private void testTruncated3_2()
    {
        byte[] utf8 = new byte[2];
        char[] utf16 = new char[1];

        for (int i = 0x00; i < 0x10; ++i)
        {
            utf8[0] = (byte)(0xE0 | i);
            utf8[1] = randomSuffix();
            utf16[0] = (char)0;

            if (i == 0x00)
            {
                utf8[1] |= 0x20; 
            }
            else if (i == 0x0D)
            {
                utf8[1] &= 0x9F;
            }

            int result = UTF8.transcodeToUTF16(utf8, utf16);

            isEquals("testTruncated3_2", result, -1);
        }
        
    }

    private void testTruncated4_1()
    {
        byte[] utf8 = new byte[1];
        char[] utf16 = new char[2];

        for (int i = 0x00; i < 0x05; ++i)
        {
            utf8[0] = (byte)(0xF0 | i);
            utf16[0] = (char)0;
            utf16[1] = (char)0;

            int result = UTF8.transcodeToUTF16(utf8, utf16);

            isEquals("testTruncated4_1", result, -1);
        }
    }
    
    private void testTruncated4_2()
    {
        byte[] utf8 = new byte[2];
        char[] utf16 = new char[2];

        for (int i = 0x00; i < 0x05; ++i)
        {
            utf8[0] = (byte)(0xF0 | i);
            utf8[1] = randomSuffix();
            utf16[0] = (char)0;
            utf16[1] = (char)0;

            if (i == 0x00)
            {
                utf8[1] |= 0x10 << (R.nextInt() & 1);
            }
            else if (i == 0x04)
            {
                utf8[1] &= 0x8F;
            }

            int result = UTF8.transcodeToUTF16(utf8, utf16);

            isEquals("testTruncated4_2", result, -1);
        }
    }
    
    private void testTruncated4_3()
    {
        byte[] utf8 = new byte[3];
        char[] utf16 = new char[2];

        for (int i = 0x00; i < 0x05; ++i)
        {
            utf8[0] = (byte)(0xF0 | i);
            utf8[1] = randomSuffix();
            utf8[2] = randomSuffix();
            utf16[0] = (char)0;
            utf16[1] = (char)0;

            if (i == 0x00)
            {
                utf8[1] |= 0x10 << (R.nextInt() & 1);
            }
            else if (i == 0x04)
            {
                utf8[1] &= 0x8F;
            }

            int result = UTF8.transcodeToUTF16(utf8, utf16);

            isEquals("testTruncated4_3", result, -1);
        }
    }

    private void testValid1()
    {
        byte[] utf8 = new byte[1];
        char[] utf16 = new char[1];

        for (int i = 0x00; i < 0x80; ++i)
        {
            utf8[0] = (byte)i;
            utf16[0] = (char)0xFFFF;

            int result = UTF8.transcodeToUTF16(utf8, utf16);

            isEquals("testValid1.Result", result, 1);
            isEquals("testValid1.Value", utf16[0], i);
        }
    }

    private void testValid2()
    {
        byte[] utf8 = new byte[2];
        char[] utf16 = new char[1];

        for (int i = 0x02; i < 0x20; ++i)
        {
            utf8[0] = (byte)(0xC0 | i);
            utf8[1] = randomSuffix();
            utf16[0] = (char)0;

            int result = UTF8.transcodeToUTF16(utf8, utf16);

            isEquals("testValid2.Result", result, 1);
            isEquals("testValid2.Value", utf16[0], (i << 6) | (utf8[1] & 0x3F));
        }
    }

    private void testValid3()
    {
        byte[] utf8 = new byte[3];
        char[] utf16 = new char[1];

        for (int i = 0x00; i < 0x10; ++i)
        {
            utf8[0] = (byte)(0xE0 | i);
            utf8[1] = randomSuffix();
            utf8[2] = randomSuffix();
            utf16[0] = (char)0;

            if (i == 0x00)
            {
                utf8[1] |= 0x20; 
            }
            else if (i == 0x0D)
            {
                utf8[1] &= 0x9F;
            }

            int result = UTF8.transcodeToUTF16(utf8, utf16);

            isEquals("testValid3.Result", result, 1);
            isEquals("testValid3.Value", utf16[0], (i << 12) | ((utf8[1] & 0x3F) << 6) | (utf8[2] & 0x3F));
        }
    }

    private void testValid4()
    {
        byte[] utf8 = new byte[4];
        char[] utf16 = new char[2];

        for (int i = 0x00; i < 0x05; ++i)
        {
            utf8[0] = (byte)(0xF0 | i);
            utf8[1] = randomSuffix();
            utf8[2] = randomSuffix();
            utf8[3] = randomSuffix();
            utf16[0] = (char)0;
            utf16[1] = (char)0;

            if (i == 0x00)
            {
                utf8[1] |= 0x10 << (R.nextInt() & 1);
            }
            else if (i == 0x04)
            {
                utf8[1] &= 0x8F;
            }

            int result = UTF8.transcodeToUTF16(utf8, utf16);

            isEquals("testValid4.Result", result, 2);
            isEquals("testValid4.Value",
                ((utf16[0] - 0xD7C0) << 10) | (utf16[1] - 0xDC00),
                (i << 18) | ((utf8[1] & 0x3F) << 12) | ((utf8[2] & 0x3F) << 6) | (utf8[3] & 0x3F));
        }
    }

    private byte randomInRange(byte lo, byte hi)
    {
        int a = lo & 0xFF, b = hi & 0xFF, d = b - a;

        return (byte)(lo + ((R.nextInt() >>> 1) % d));
    }

    private byte randomPrefix()
    {
        switch ((R.nextInt() & 3) + 1)
        {
        case 2:
            return randomInRange((byte)0xC2, (byte)0xE0);
        case 3:
            return randomInRange((byte)0xE0, (byte)0xF0);
        case 4:
            return randomInRange((byte)0xF0, (byte)0xF6);
        default:
            return (byte)(R.nextInt() & 0x7F);
        }
    }

    private byte randomSuffix()
    {
        return (byte)((R.nextInt() >>> 26) | 0x80);
    }
}
