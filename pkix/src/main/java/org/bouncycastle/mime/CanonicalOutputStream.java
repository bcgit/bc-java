package org.bouncycastle.mime;

import java.io.FilterOutputStream;
import java.io.IOException;
import java.io.OutputStream;

import org.bouncycastle.mime.smime.SMimeParserContext;

public class CanonicalOutputStream
    extends FilterOutputStream
{
    protected int lastb;
    protected static byte newline[];
    private final boolean is7Bit;

    public CanonicalOutputStream(SMimeParserContext parserContext, Headers headers, OutputStream outputstream)
    {
        super(outputstream);
        lastb = -1;
        // TODO: eventually may need to handle multiparts with binary...
        if (headers.getContentType() != null)
        {
            is7Bit = headers.getContentType() != null && !headers.getContentType().equals("binary");
        }
        else
        {
            is7Bit = parserContext.getDefaultContentTransferEncoding().equals("7bit");
        }
    }

    public void write(int i)
        throws IOException
    {
        if (is7Bit)
        {
            if (i == '\r')
            {
                out.write(newline);
            }
            else if (i == '\n')
            {
                if (lastb != '\r')
                {
                    out.write(newline);
                }
            }
            else
            {
                out.write(i);
            }
        }
        else
        {
            out.write(i);
        }
        
        lastb = i;
    }

    public void write(byte[] buf)
        throws IOException
    {
        this.write(buf, 0, buf.length);
    }

    public void write(byte buf[], int off, int len)
        throws IOException
    {
        for (int i = off; i != off + len; i++)
        {
            this.write(buf[i]);
        }
    }

    public void writeln()
        throws IOException
    {
        super.out.write(newline);
    }

    static 
    {
        newline = new byte[2];
        newline[0] = '\r';
        newline[1] = '\n';
    }
}
