package org.bouncycastle.est;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;

public class CTEChunkedInputStream
    extends InputStream
{
    private InputStream src;
    int chunkLen = 0;


    public CTEChunkedInputStream(InputStream inputStream)
    {
        this.src = inputStream;
    }

    private String readEOL()
        throws IOException
    {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        int c = 0;

        for (; ; )
        {
            c = src.read();
            if (c == -1)
            {
                if (bos.size() == 0)
                {
                    return null; // End of data
                }
                // return remaining buffer
                return bos.toString().trim();
            }
            bos.write(c & 0xFF);

            if (c == '\n')
            {
                return bos.toString().trim();
            }
        }
    }

    public int read()
        throws IOException
    {
        if (chunkLen == Integer.MIN_VALUE)
        {
            return -1;
        }

        if (chunkLen == 0)
        {
            String line = null;
            do
            {
                line = readEOL();
            }
            while (line != null && line.length() == 0); // skip empty lines.
            if (line == null)
            {
                return -1;
            }
            chunkLen = Integer.parseInt(line.trim(), 16);
            if (chunkLen == 0)
            {
                // Last block, burn off last line
                readEOL();
                chunkLen = Integer.MIN_VALUE;
                return -1;
            }
        }

        int i = src.read();
        chunkLen--;
        return i;
    }
}
