package org.bouncycastle.mime;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;

import org.bouncycastle.util.Strings;

/**
 * Read regular text lines, allowing for a single character look ahead.
 */
class LineReader
{
    private final InputStream src;

    private int lastC = -1;

    LineReader(InputStream src)
    {
        this.src = src;
    }

    String readLine()
        throws IOException
    {
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();

        int ch;

        if (lastC != -1)
        {
            if (lastC == '\r')   // to get this we must have '\r\r' so blank line
            {
                return "";
            }
            ch = lastC;
            lastC = -1;
        }
        else
        {
            ch = src.read();
        }

        while (ch >= 0 && ch != '\r' && ch != '\n')
        {
            bOut.write(ch);
            ch = src.read();
        }

        if (ch == '\r')
        {
            int c = src.read();
            if (c != '\n' && c >= 0)
            {
                lastC = c;
            }
        }

        if (ch < 0)
        {
            return null;
        }

        return Strings.fromUTF8ByteArray(bOut.toByteArray());
    }
}
