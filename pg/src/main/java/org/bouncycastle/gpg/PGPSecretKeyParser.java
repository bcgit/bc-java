package org.bouncycastle.gpg;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;

import org.bouncycastle.openpgp.OpenedPGPKeyData;
import org.bouncycastle.openpgp.PGPExtendedKeyHeader;
import org.bouncycastle.util.Strings;

public class PGPSecretKeyParser
{


    /**
     * Test if the stream supports extended
     *
     * @param inputStream
     * @return
     * @throws IOException
     */
    public static boolean isExtendedSExpression(InputStream inputStream)
        throws IOException
    {
        if (!inputStream.markSupported())
        {
            throw new IOException("input stream must support mark");
        }
        inputStream.mark(1);
        int c = inputStream.read();
        inputStream.reset();

        return c != '(';
    }

    private static int lastIndexOfWhitespace(String str)
    {
        if (str.length() == 0)
        {
            return -1;
        }
        for (int t = str.length() - 1; t >= 0; t--)
        {
            char c = str.charAt(t);
            if (c <= 32)
            {
                return t;
            }
        }
        return -1;
    }

    private static void consumeUntil(InputStream src, char item, ByteArrayOutputStream accumulator)
        throws IOException
    {
        accumulator.reset();
        int c;
        while ((c = src.read()) > -1)
        {
            if (c == item)
            {
                return;
            }
            accumulator.write(c);
        }
    }


    public static OpenedPGPKeyData parse(InputStream src, int maxExpressionDepth)
        throws IOException
    {

        OpenedPGPKeyData.Builder builder = OpenedPGPKeyData.builder();

        if (PGPSecretKeyParser.isExtendedSExpression(src))
        {

            ByteArrayOutputStream accumulator = new ByteArrayOutputStream();

            String key = null;

            for (; ; )
            {
                consumeUntil(src, ':', accumulator);
                String hunk = Strings.fromByteArray(accumulator.toByteArray()).trim();
                int ws = lastIndexOfWhitespace(hunk);
                if (ws == -1)
                {
                    key = hunk;
                }
                else
                {
                    builder.add(new PGPExtendedKeyHeader(key, hunk.substring(0, ws)));
                    key = hunk.substring(ws).trim();
                }

                if (key.equalsIgnoreCase("Key"))
                {
                    break;
                }

            }
        }

        builder.setKeyExpression(SExpression.parse(src, maxExpressionDepth));
        return builder.build();
    }

}
