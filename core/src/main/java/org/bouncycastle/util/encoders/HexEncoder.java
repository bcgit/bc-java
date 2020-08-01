package org.bouncycastle.util.encoders;

import java.io.IOException;
import java.io.OutputStream;

/**
 * A streaming Hex encoder.
 */
public class HexEncoder
    implements Encoder
{
    protected final byte[] encodingTable =
    {
        (byte)'0', (byte)'1', (byte)'2', (byte)'3', (byte)'4', (byte)'5', (byte)'6', (byte)'7',
        (byte)'8', (byte)'9', (byte)'a', (byte)'b', (byte)'c', (byte)'d', (byte)'e', (byte)'f'
    };

    /*
     * set up the decoding table.
     */
    protected final byte[] decodingTable = new byte[128];

    protected void initialiseDecodingTable()
    {
        for (int i = 0; i < decodingTable.length; i++)
        {
            decodingTable[i] = (byte)0xff;
        }

        for (int i = 0; i < encodingTable.length; i++)
        {
            decodingTable[encodingTable[i]] = (byte)i;
        }

        decodingTable['A'] = decodingTable['a'];
        decodingTable['B'] = decodingTable['b'];
        decodingTable['C'] = decodingTable['c'];
        decodingTable['D'] = decodingTable['d'];
        decodingTable['E'] = decodingTable['e'];
        decodingTable['F'] = decodingTable['f'];
    }

    public HexEncoder()
    {
        initialiseDecodingTable();
    }

    public int encode(byte[] inBuf, int inOff, int inLen, byte[] outBuf, int outOff) throws IOException
    {
        int inPos = inOff;
        int inEnd = inOff + inLen;
        int outPos = outOff;

        while (inPos < inEnd)
        {
            int b = inBuf[inPos++] & 0xFF;

            outBuf[outPos++] = encodingTable[b >>> 4];
            outBuf[outPos++] = encodingTable[b & 0xF];
        }

        return outPos - outOff;
    }

    /**
     * encode the input data producing a Hex output stream.
     *
     * @return the number of bytes produced.
     */
    public int encode(byte[] buf, int off, int len, OutputStream out) 
        throws IOException
    {
        byte[] tmp = new byte[72];
        while (len > 0)
        {
            int inLen = Math.min(36, len);
            int outLen = encode(buf, off, inLen, tmp, 0);
            out.write(tmp, 0, outLen);
            off += inLen;
            len -= inLen;
        }
        return len * 2;
    }

    private static boolean ignore(
        char    c)
    {
        return c == '\n' || c =='\r' || c == '\t' || c == ' ';
    }

    /**
     * decode the Hex encoded byte data writing it to the given output stream,
     * whitespace characters will be ignored.
     *
     * @return the number of bytes produced.
     */
    public int decode(
        byte[]          data,
        int             off,
        int             length,
        OutputStream    out)
        throws IOException
    {
        byte    b1, b2;
        int     outLen = 0;
        byte[]  buf = new byte[36];
        int     bufOff = 0;

        int     end = off + length;

        while (end > off)
        {
            if (!ignore((char)data[end - 1]))
            {
                break;
            }

            end--;
        }

        int i = off;
        while (i < end)
        {
            while (i < end && ignore((char)data[i]))
            {
                i++;
            }

            b1 = decodingTable[data[i++]];

            while (i < end && ignore((char)data[i]))
            {
                i++;
            }

            b2 = decodingTable[data[i++]];

            if ((b1 | b2) < 0)
            {
                throw new IOException("invalid characters encountered in Hex data");
            }

            buf[bufOff++] = (byte)((b1 << 4) | b2);

            if (bufOff == buf.length)
            {
                out.write(buf);
                bufOff = 0;
            }
            outLen++;
        }

        if (bufOff > 0)
        {
            out.write(buf, 0, bufOff);
        }

        return outLen;
    }

    /**
     * decode the Hex encoded String data writing it to the given output stream,
     * whitespace characters will be ignored.
     *
     * @return the number of bytes produced.
     */
    public int decode(
        String          data,
        OutputStream    out)
        throws IOException
    {
        byte    b1, b2;
        int     length = 0;
        byte[]  buf = new byte[36];
        int     bufOff = 0;
        
        int     end = data.length();

        while (end > 0)
        {
            if (!ignore(data.charAt(end - 1)))
            {
                break;
            }

            end--;
        }

        int i = 0;
        while (i < end)
        {
            while (i < end && ignore(data.charAt(i)))
            {
                i++;
            }

            b1 = decodingTable[data.charAt(i++)];

            while (i < end && ignore(data.charAt(i)))
            {
                i++;
            }

            b2 = decodingTable[data.charAt(i++)];

            if ((b1 | b2) < 0)
            {
                throw new IOException("invalid characters encountered in Hex string");
            }

            buf[bufOff++] = (byte)((b1 << 4) | b2);

            if (bufOff == buf.length)
            {
                out.write(buf);
                bufOff = 0;
            }

            length++;
        }

        if (bufOff > 0)
        {
            out.write(buf, 0, bufOff);
        }

        return length;
    }

    byte[] decodeStrict(String str, int off, int len) throws IOException
    {
        if (null == str)
        {
            throw new NullPointerException("'str' cannot be null");
        }
        if (off < 0 || len < 0 || off > (str.length() - len))
        {
            throw new IndexOutOfBoundsException("invalid offset and/or length specified");
        }
        if (0 != (len & 1))
        {
            throw new IOException("a hexadecimal encoding must have an even number of characters");
        }

        int resultLen = len >>> 1;
        byte[] result = new byte[resultLen];

        int strPos = off;
        for (int i = 0; i < resultLen; ++i)
        {
            byte b1 = decodingTable[str.charAt(strPos++)];
            byte b2 = decodingTable[str.charAt(strPos++)];

            int n = (b1 << 4) | b2;
            if (n < 0)
            {
                throw new IOException("invalid characters encountered in Hex string");
            }

            result[i] = (byte)n;
        }
        return result;
    }
}
