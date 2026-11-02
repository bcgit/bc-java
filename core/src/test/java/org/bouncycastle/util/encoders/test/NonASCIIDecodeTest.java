package org.bouncycastle.util.encoders.test;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

import junit.framework.TestCase;
import org.bouncycastle.util.encoders.Base32Encoder;
import org.bouncycastle.util.encoders.Base64Encoder;
import org.bouncycastle.util.encoders.DecoderException;
import org.bouncycastle.util.encoders.Encoder;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.encoders.HexEncoder;
import org.bouncycastle.util.encoders.UrlBase64Encoder;

/**
 * A non-ASCII character, or a byte with the top bit set, is an invalid character for the
 * Base64, URL-safe Base64, Base32 and Hex decoders, reported as such rather than indexing past
 * the end of the decoding table.
 */
public class NonASCIIDecodeTest
    extends TestCase
{
    private static final char[] BAD = { 'é', 'ÿ', '中', '￿' };

    public void testBase64()
    {
        // a bad character in a middle block and in the final block
        checkEncoder(new Base64Encoder(), new String[]{ "dGVz?GluZw==", "dGVzdGluZ?==", "dGVzdGlu?w==" });
    }

    public void testUrlBase64()
    {
        checkEncoder(new UrlBase64Encoder(), new String[]{ "dGVz?GluZw..", "dGVzdGluZ?.." });
    }

    public void testBase32()
    {
        checkEncoder(new Base32Encoder(), new String[]{ "ORSX?5DJNZTVQWK2", "ORSXG5DJNZTVQWK?", "ORSXG5DJNZ?A====" });
    }

    public void testHex()
    {
        checkEncoder(new HexEncoder(), new String[]{ "01?203", "0102?3" });

        for (int i = 0; i != BAD.length; i++)
        {
            try
            {
                Hex.decodeStrict("0102" + BAD[i] + "3");
                fail("decodeStrict accepted " + Integer.toHexString(BAD[i]));
            }
            catch (DecoderException e)
            {
                assertTrue(e.getCause() instanceof IOException);
            }
        }
    }

    private void checkEncoder(Encoder encoder, String[] templates)
    {
        for (int t = 0; t != templates.length; t++)
        {
            for (int i = 0; i != BAD.length; i++)
            {
                String data = templates[t].replace('?', BAD[i]);

                try
                {
                    encoder.decode(data, new ByteArrayOutputStream());
                    fail("String accepted: " + templates[t] + " with " + Integer.toHexString(BAD[i]));
                }
                catch (IOException e)
                {
                    // expected
                }

                // the same data as bytes, where the bad character becomes a byte with the top bit set
                if ((BAD[i] & 0x80) == 0)
                {
                    continue;
                }

                byte[] bytes = new byte[data.length()];
                for (int j = 0; j != bytes.length; j++)
                {
                    bytes[j] = (byte)data.charAt(j);
                }

                try
                {
                    encoder.decode(bytes, 0, bytes.length, new ByteArrayOutputStream());
                    fail("bytes accepted: " + templates[t] + " with " + Integer.toHexString(BAD[i] & 0xff));
                }
                catch (IOException e)
                {
                    // expected
                }
            }
        }
    }
}
