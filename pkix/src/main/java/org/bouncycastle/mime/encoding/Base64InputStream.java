package org.bouncycastle.mime.encoding;

import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;

/**
 * Reader for Base64 armored objects which converts them into binary data.
 */
public class Base64InputStream
    extends InputStream
{
    /*
     * set up the decoding table.
     */
    private static final byte[] decodingTable;

    static
    {
        decodingTable = new byte[128];

        for (int i = 'A'; i <= 'Z'; i++)
        {
            decodingTable[i] = (byte)(i - 'A');
        }

        for (int i = 'a'; i <= 'z'; i++)
        {
            decodingTable[i] = (byte)(i - 'a' + 26);
        }

        for (int i = '0'; i <= '9'; i++)
        {
            decodingTable[i] = (byte)(i - '0' + 52);
        }

        decodingTable['+'] = 62;
        decodingTable['/'] = 63;
    }

    /**
     * decode the base 64 encoded input data.
     *
     * @return the offset the data starts in out.
     */
    private int decode(
        int      in0,
        int      in1,
        int      in2,
        int      in3,
        int[]    out)
        throws EOFException
    {
        int    b1, b2, b3, b4;

        if (in3 < 0)
        {
            throw new EOFException("unexpected end of file in armored stream.");
        }

        if (in2 == '=')
        {
            b1 = decodingTable[in0] &0xff;
            b2 = decodingTable[in1] & 0xff;

            out[2] = ((b1 << 2) | (b2 >> 4)) & 0xff;

            return 2;
        }
        else if (in3 == '=')
        {
            b1 = decodingTable[in0];
            b2 = decodingTable[in1];
            b3 = decodingTable[in2];

            out[1] = ((b1 << 2) | (b2 >> 4)) & 0xff;
            out[2] = ((b2 << 4) | (b3 >> 2)) & 0xff;

            return 1;
        }
        else
        {
            b1 = decodingTable[in0];
            b2 = decodingTable[in1];
            b3 = decodingTable[in2];
            b4 = decodingTable[in3];

            out[0] = ((b1 << 2) | (b2 >> 4)) & 0xff;
            out[1] = ((b2 << 4) | (b3 >> 2)) & 0xff;
            out[2] = ((b3 << 6) | b4) & 0xff;

            return 0;
        }
    }

    InputStream    in;
    int[]          outBuf = new int[3];
    int            bufPtr = 3;
    boolean        isEndOfStream;

    /**
     * Create a stream for reading a PGP armoured message, parsing up to a header
     * and then reading the data that follows.
     *
     * @param in
     */
    public Base64InputStream(
        InputStream    in)
    {
        this.in = in;
    }
    
    public int available()
        throws IOException
    {
        return in.available();
    }
    
    private int readIgnoreSpace() 
        throws IOException
    {
        int    c = in.read();
        
        while (c == ' ' || c == '\t')
        {
            c = in.read();
        }
        
        return c;
    }
    
    public int read()
        throws IOException
    {
        int    c;

        if (bufPtr > 2)
        {
            c = readIgnoreSpace();
            
            if (c == '\r' || c == '\n')
            {
                c = readIgnoreSpace();
                
                while (c == '\n' || c == '\r')
                {
                    c = readIgnoreSpace();
                }

                if (c < 0)                // EOF
                {
                    isEndOfStream = true;
                    return -1;
                }

                bufPtr = decode(c, readIgnoreSpace(), readIgnoreSpace(), readIgnoreSpace(), outBuf);
            }
            else
            {
                if (c >= 0)
                {
                    bufPtr = decode(c, readIgnoreSpace(), readIgnoreSpace(), readIgnoreSpace(), outBuf);
                }
                else
                {
                    isEndOfStream = true;
                    return -1;
                }
            }
        }

        c = outBuf[bufPtr++];

        return c;
    }
    
    public void close()
        throws IOException
    {
        in.close();
    }
}
