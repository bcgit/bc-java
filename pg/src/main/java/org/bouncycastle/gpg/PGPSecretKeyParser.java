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

        // -1 is end of input, not an extended expression: treating it as one sent an empty stream
        // into the header loop below, which has no exit until it reads a "Key" header.
        return c != -1 && c != '(';
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

    /**
     * @return true if the delimiter was found, false if the stream ended first. The caller has to
     *         be able to tell the two apart: the header loop in {@link #parse} exits only on a
     *         "Key" header, so on a truncated stream it would otherwise spin forever accumulating
     *         nothing.
     */
    private static boolean consumeUntil(InputStream src, char item, ByteArrayOutputStream accumulator)
        throws IOException
    {
        accumulator.reset();
        int c;
        while ((c = src.read()) > -1)
        {
            if (c == item)
            {
                return true;
            }
            accumulator.write(c);
        }

        return false;
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
                if (!consumeUntil(src, ':', accumulator))
                {
                    throw new IOException("end of input before the Key header of an extended key expression");
                }
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
