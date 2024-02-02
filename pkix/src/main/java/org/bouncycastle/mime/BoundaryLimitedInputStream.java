package org.bouncycastle.mime;

import java.io.IOException;
import java.io.InputStream;

import org.bouncycastle.util.Strings;

public class BoundaryLimitedInputStream
    extends InputStream
{
    final private InputStream src;
    final private byte[] boundary;
    final private byte[] buf;

    private int bufOff = 0;
    private int index = 0;
    private boolean ended = false;

    private int lastI;

    public BoundaryLimitedInputStream(InputStream src, String startBoundary)
    {
        this.src = src;
        boundary = Strings.toByteArray(startBoundary);
        this.buf = new byte[startBoundary.length() + 3];
        this.bufOff = 0;
    }


    public int read()
        throws IOException
    {
        if (ended)
        {
            return -1;
        }

        int i;
        if (index < bufOff)
        {
            i = buf[index++] & 0xff;
            // if this happens we know we've already failed on a "\r\n"
            if (index < bufOff)
            {
                return i;
            }
            index = bufOff = 0;
        }
        else
        {
            i = src.read();
        }

        lastI = i;

        if (i < 0)
        {
            return -1;
        }

        if (i == '\r' || i == '\n') // check for start of boundary
        {
            int ch;
            index = 0;
            if (i == '\r')
            {
                ch = src.read();
                if (ch == '\n')
                {
                    buf[bufOff++] = '\n';
                    ch = src.read();
                }
            }
            else
            {
                ch = src.read();
            }

            if (ch == '-')
            {
                buf[bufOff++] = '-';
                ch = src.read();
            }

            if (ch == '-')
            {
                buf[bufOff++] = '-';

                int base = bufOff;
                int c;

                while ((bufOff - base) != boundary.length && (c = src.read()) >= 0)
                {
                    buf[bufOff] = (byte)c;
                    if (buf[bufOff] != boundary[bufOff - base])
                    {
                        bufOff++;
                        break;
                    }
                    bufOff++;
                }
                
                // we have a match
                if (bufOff - base == boundary.length)
                {
                    ended = true;
                    return -1;
                }
            }
            else
            {
                if (ch >= 0)
                {
                    buf[bufOff++] = (byte)ch;
                }
            }
        }

        return i;
    }
}
