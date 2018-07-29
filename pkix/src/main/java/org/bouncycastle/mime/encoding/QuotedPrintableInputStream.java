package org.bouncycastle.mime.encoding;

import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;

/**
 * Input stream that processes quoted-printable data, converting it into what was originally intended.
 */
public class QuotedPrintableInputStream
    extends FilterInputStream
{

    public QuotedPrintableInputStream(InputStream input)
    {
        super(input);
    }

    public int read(byte[] buf, int bufOff, int len) throws IOException
    {
        int i = 0;
        while (i != len)
        {
            int ch = this.read();
            if (ch < 0)
            {
                break;
            }
            buf[i + bufOff] = (byte)ch;
            i++;
        }

        if (i == 0)
        {
            return -1;
        }
        
        return i;
    }

    public int read()
        throws IOException
    {
        int v = in.read();
        if (v == -1)
        {
            return -1;
        }
 
        // V was the quote '=' character/
        while (v == '=')
        {
            //
            // Get the next character.
            //
            int j = in.read();
            if (j == -1)
            {
                throw new IllegalStateException("Quoted '=' at end of stream");
            }

            // For systems generating CRLF line endings.
            if (j == '\r')
            {
                j = in.read();
                if (j == '\n')
                {
                    //
                    // This was a line break that was not actually a line break in the original information.
                    // So return the next data.
                    //
                    j = in.read();
                }
                v = j;
                continue;
            }
            else if (j == '\n')
            {
                // As above but without preceding CR.
                v = in.read();
                continue;
            }
            else
            {

                int chr = 0;

                if (j >= '0' && j <= '9')
                {
                    chr = j - '0';
                }
                else if (j >= 'A' && j <= 'F')
                {
                    chr = 10 + (j - 'A');
                }
                else
                {
                    throw new IllegalStateException("Expecting '0123456789ABCDEF after quote that was not immediately followed by LF or CRLF");
                }

                chr <<= 4;

                j = in.read();

                if (j >= '0' && j <= '9')
                {
                    chr |= j - '0';
                }
                else if (j >= 'A' && j <= 'F')
                {
                    chr |= 10 + (j - 'A');
                }
                else
                {
                    throw new IllegalStateException("Expecting second '0123456789ABCDEF after quote that was not immediately followed by LF or CRLF");
                }

                return chr;
            }
        }

        return v;
    }
}
