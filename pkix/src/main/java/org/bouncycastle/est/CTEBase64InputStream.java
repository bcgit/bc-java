package org.bouncycastle.est;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

import org.bouncycastle.util.encoders.Base64;


class CTEBase64InputStream
    extends InputStream
{
    protected final InputStream src;
    protected final byte[] rawBuf = new byte[1024];
    protected final byte[] data = new byte[768];
    protected final OutputStream dataOutputStream;
    protected final Long max;
    protected int rp;
    protected int wp;
    protected boolean end;
    protected long read;

    public CTEBase64InputStream(InputStream src, Long limit)
    {
        this.src = src;
        this.dataOutputStream = new OutputStream()
        {
            public void write(int b)
                throws IOException
            {
                data[wp++] = (byte)b;
            }
        };
        this.max = limit;
    }

    // Pulls a line from the source, decodes it and returns the decoded length.
    // Or returns -1 if there is nothing more to read and nothing was read in this pass.
    protected int pullFromSrc()
        throws IOException
    {

        if (this.read >= this.max)
        {
            return -1;
        }

        int j = 0;
        int c = 0;
        do
        {
            j = src.read();
            /*
             * RFC2045 All line breaks or other characters not
             * found in Table 1 must be ignored by decoding software.
             * https://tools.ietf.org/html/rfc2045#section-6.8
             * This uses the line brakes to to stop reading data and to decode a chunk.
             */
            if (j >= 33 || (j == '\r' || j == '\n'))
            {
                if (c >= rawBuf.length)
                {
                    throw new IOException("Content Transfer Encoding, base64 line length > 1024");
                }
                rawBuf[c++] = (byte)j;
                read += 1;
            }
            else if (j >= 0)
            {
                read += 1;
            }
        }
        while (j > -1 && c < rawBuf.length && j != 10 && this.read < this.max);

        if (c > 0)
        {
            try
            {
                Base64.decode(rawBuf, 0, c, dataOutputStream);
            }
            catch (Exception ex)
            {
                throw new IOException("Decode Base64 Content-Transfer-Encoding: " + ex);
            }
        }
        else
        {
            if (j == -1)
            {
                return -1;
            }
        }
        return wp;
    }

    public int read()
        throws IOException
    {
        // When we have read up to the write pointer (wp) pull some more.
        if (rp == wp)
        {
            rp = 0;
            wp = 0;
            int i = pullFromSrc();
            if (i == -1)
            {
                return i;
            }
        }
        return data[rp++] & 0xFF;
    }

    public void close()
        throws IOException
    {
        src.close();
    }
}
