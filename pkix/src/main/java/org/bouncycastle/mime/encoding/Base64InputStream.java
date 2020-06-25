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
//    boolean        isEndOfStream;

    public Base64InputStream(
        InputStream    in)
    {
        this.in = in;
    }

    public int available()
        throws IOException
    {
        // We can't guarantee 'in.available()' bytes aren't all spaces
        return 0;
    }

    public int read()
        throws IOException
    {
        if (bufPtr > 2)
        {
            int in0 = readIgnoreSpaceFirst();
            if (in0 < 0)
            {
//                isEndOfStream = true;
                return -1;
            }

            int in1 = readIgnoreSpace();
            int in2 = readIgnoreSpace();
            int in3 = readIgnoreSpace();

            bufPtr = decode(in0, in1, in2, in3, outBuf);
        }

        return outBuf[bufPtr++];
    }

    public void close()
        throws IOException
    {
        in.close();
    }

    private int readIgnoreSpace()
        throws IOException
    {
        for (;;)
        {
            int c;
            switch (c = in.read())
            {
            case ' ':
            case '\t':
                break;
            default:
                return c;
            }
        }
    }

    private int readIgnoreSpaceFirst()
        throws IOException
    {
        for (;;)
        {
            int c;
            switch (c = in.read())
            {
            case ' ':
            case '\n':
            case '\r':
            case '\t':
                break;
            default:
                return c;
            }
        }
    }
}
