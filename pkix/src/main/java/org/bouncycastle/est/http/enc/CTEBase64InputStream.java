package org.bouncycastle.est.http.enc;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

import org.bouncycastle.util.encoders.Base64;


public class CTEBase64InputStream
    extends InputStream
{
    protected InputStream src;
    protected byte[] rawBuf = new byte[1024];
    protected byte[] data = new byte[768];
    protected int rp;
    protected int wp;
    protected boolean end;
    protected OutputStream dataOutputStream;


    public CTEBase64InputStream(InputStream src)
        throws Exception
    {
        this.src = src;
        this.dataOutputStream = new OutputStream()
        {
            @Override
            public void write(int b)
                throws IOException
            {
                data[wp++] = (byte)b;
            }
        };
    }

    // Pulls a line from the source, decodes it and returns the decoded length.
    // Or returns -1 if there is nothing more to read and nothing was read in this pass.
    protected int pullFromSrc()
        throws IOException
    {
        int j = 0;
        int c = 0;
        do
        {
            j = src.read();
            if (j >= 0)
            {
                rawBuf[c++] = (byte)j;
            }
        }
        while (j > -1 && c < rawBuf.length && j != 10);

        if (c > 0)
        {
            Base64.decode(rawBuf, 0, c, dataOutputStream);
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

}
