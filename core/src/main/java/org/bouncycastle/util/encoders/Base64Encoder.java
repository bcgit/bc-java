package org.bouncycastle.util.encoders;

import java.io.IOException;
import java.io.OutputStream;

/**
 * A streaming Base64 encoder.
 */
public class Base64Encoder
    implements Encoder
{
    protected final byte[] encodingTable =
    {
        (byte)'A', (byte)'B', (byte)'C', (byte)'D', (byte)'E', (byte)'F', (byte)'G',
        (byte)'H', (byte)'I', (byte)'J', (byte)'K', (byte)'L', (byte)'M', (byte)'N',
        (byte)'O', (byte)'P', (byte)'Q', (byte)'R', (byte)'S', (byte)'T', (byte)'U',
        (byte)'V', (byte)'W', (byte)'X', (byte)'Y', (byte)'Z',
        (byte)'a', (byte)'b', (byte)'c', (byte)'d', (byte)'e', (byte)'f', (byte)'g',
        (byte)'h', (byte)'i', (byte)'j', (byte)'k', (byte)'l', (byte)'m', (byte)'n',
        (byte)'o', (byte)'p', (byte)'q', (byte)'r', (byte)'s', (byte)'t', (byte)'u',
        (byte)'v',
        (byte)'w', (byte)'x', (byte)'y', (byte)'z',
        (byte)'0', (byte)'1', (byte)'2', (byte)'3', (byte)'4', (byte)'5', (byte)'6',
        (byte)'7', (byte)'8', (byte)'9',
        (byte)'+', (byte)'/'
    };

    protected byte    padding = (byte)'=';
    
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
    }
    
    public Base64Encoder()
    {
        initialiseDecodingTable();
    }

    public int encode(byte[] inBuf, int inOff, int inLen, byte[] outBuf, int outOff) throws IOException
    {
        int inPos = inOff;
        int inEnd = inOff + inLen - 2;
        int outPos = outOff;

        while (inPos < inEnd)
        {
            int a1 = inBuf[inPos++];
            int a2 = inBuf[inPos++] & 0xFF;
            int a3 = inBuf[inPos++] & 0xFF;

            outBuf[outPos++] = encodingTable[(a1 >>> 2) & 0x3F];
            outBuf[outPos++] = encodingTable[((a1 << 4) | (a2 >>> 4)) & 0x3F];
            outBuf[outPos++] = encodingTable[((a2 << 2) | (a3 >>> 6)) & 0x3F];
            outBuf[outPos++] = encodingTable[a3 & 0x3F];
        }

        switch (inLen - (inPos - inOff))
        {
        case 1:
        {
            int a1 = inBuf[inPos++] & 0xFF;

            outBuf[outPos++] = encodingTable[(a1 >>> 2) & 0x3F];
            outBuf[outPos++] = encodingTable[(a1 << 4) & 0x3F];
            outBuf[outPos++] = padding;
            outBuf[outPos++] = padding;
            break;
        }
        case 2:
        {
            int a1 = inBuf[inPos++] & 0xFF;
            int a2 = inBuf[inPos++] & 0xFF;

            outBuf[outPos++] = encodingTable[(a1 >>> 2) & 0x3F];
            outBuf[outPos++] = encodingTable[((a1 << 4) | (a2 >>> 4)) & 0x3F];
            outBuf[outPos++] = encodingTable[(a2 << 2) & 0x3F];
            outBuf[outPos++] = padding;
            break;
        }
        }

        return outPos - outOff;
    }

    /**
     * encode the input data producing a base 64 output stream.
     *
     * @return the number of bytes produced.
     */
    public int encode(byte[] buf, int off, int len, OutputStream out) 
        throws IOException
    {
        byte[] tmp = new byte[72];
        while (len > 0)
        {
            int inLen = Math.min(54, len);
            int outLen = encode(buf, off, inLen, tmp, 0);
            out.write(tmp, 0, outLen);
            off += inLen;
            len -= inLen;
        }
        return ((len + 2) / 3) * 4;
    }

    private boolean ignore(
        char    c)
    {
        return (c == '\n' || c =='\r' || c == '\t' || c == ' ');
    }
    
    /**
     * decode the base 64 encoded byte data writing it to the given output stream,
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
        byte    b1, b2, b3, b4;
        byte[]  outBuffer = new byte[54];   // S/MIME standard
        int     bufOff = 0;
        int     outLen = 0;
        
        int     end = off + length;
        
        while (end > off)
        {
            if (!ignore((char)data[end - 1]))
            {
                break;
            }
            
            end--;
        }

        // empty data!
        if (end == 0)
        {
            return 0;
        }
        
        int  i = 0;
        int  finish = end;

        while (finish > off && i != 4)
        {
            if (!ignore((char)data[finish - 1]))
            {
                i++;
            }

            finish--;
        }

        i = nextI(data, off, finish);

        while (i < finish)
        {
            b1 = decodingTable[data[i++]];
            
            i = nextI(data, i, finish);
            
            b2 = decodingTable[data[i++]];
            
            i = nextI(data, i, finish);
            
            b3 = decodingTable[data[i++]];
            
            i = nextI(data, i, finish);
            
            b4 = decodingTable[data[i++]];

            if ((b1 | b2 | b3 | b4) < 0)
            {
                throw new IOException("invalid characters encountered in base64 data");
            }

            outBuffer[bufOff++] = (byte)((b1 << 2) | (b2 >> 4));
            outBuffer[bufOff++] = (byte)((b2 << 4) | (b3 >> 2));
            outBuffer[bufOff++] = (byte)((b3 << 6) | b4);
            
            if (bufOff == outBuffer.length)
            {
                out.write(outBuffer);
                bufOff = 0;
            }
            
            outLen += 3;
            
            i = nextI(data, i, finish);
        }

        if (bufOff > 0)
        {
            out.write(outBuffer, 0, bufOff);
        }

        int e0 = nextI(data, i, end);
        int e1 = nextI(data, e0 + 1, end);
        int e2 = nextI(data, e1 + 1, end);
        int e3 = nextI(data, e2 + 1, end);

        outLen += decodeLastBlock(out, (char)data[e0], (char)data[e1], (char)data[e2], (char)data[e3]);

        return outLen;
    }

    private int nextI(byte[] data, int i, int finish)
    {
        while ((i < finish) && ignore((char)data[i]))
        {
            i++;
        }
        return i;
    }
    
    /**
     * decode the base 64 encoded String data writing it to the given output stream,
     * whitespace characters will be ignored.
     *
     * @return the number of bytes produced.
     */
    public int decode(
        String          data,
        OutputStream    out)
        throws IOException
    {
        byte    b1, b2, b3, b4;
        byte[]  outBuffer = new byte[54];   // S/MIME standard
        int     bufOff = 0;
        int     length = 0;
        
        int     end = data.length();
        
        while (end > 0)
        {
            if (!ignore(data.charAt(end - 1)))
            {
                break;
            }
            
            end--;
        }

        // empty data!
        if (end == 0)
        {
            return 0;
        }
        
        int  i = 0;
        int  finish = end;

        while (finish > 0 && i != 4)
        {
            if (!ignore(data.charAt(finish - 1)))
            {
                i++;
            }

            finish--;
        }
        
        i = nextI(data, 0, finish);
        
        while (i < finish)
        {
            b1 = decodingTable[data.charAt(i++)];
            
            i = nextI(data, i, finish);
            
            b2 = decodingTable[data.charAt(i++)];
            
            i = nextI(data, i, finish);
            
            b3 = decodingTable[data.charAt(i++)];
            
            i = nextI(data, i, finish);
            
            b4 = decodingTable[data.charAt(i++)];

            if ((b1 | b2 | b3 | b4) < 0)
            {
                throw new IOException("invalid characters encountered in base64 data");
            }
               
            outBuffer[bufOff++] = (byte)((b1 << 2) | (b2 >> 4));
            outBuffer[bufOff++] = (byte)((b2 << 4) | (b3 >> 2));
            outBuffer[bufOff++] = (byte)((b3 << 6) | b4);
            
            length += 3;
            if (bufOff == outBuffer.length)
            {
                out.write(outBuffer);
                bufOff = 0;
            }

            i = nextI(data, i, finish);
        }

        if (bufOff > 0)
        {
            out.write(outBuffer, 0, bufOff);
        }

        int e0 = nextI(data, i, end);
        int e1 = nextI(data, e0 + 1, end);
        int e2 = nextI(data, e1 + 1, end);
        int e3 = nextI(data, e2 + 1, end);

        length += decodeLastBlock(out, data.charAt(e0), data.charAt(e1), data.charAt(e2), data.charAt(e3));
        
        return length;
    }

    private int decodeLastBlock(OutputStream out, char c1, char c2, char c3, char c4) 
        throws IOException
    {
        byte    b1, b2, b3, b4;
        
        if (c3 == padding)
        {
            if (c4 != padding)
            {
                throw new IOException("invalid characters encountered at end of base64 data");
            }
            
            b1 = decodingTable[c1];
            b2 = decodingTable[c2];

            if ((b1 | b2) < 0)
            {
                throw new IOException("invalid characters encountered at end of base64 data");
            }

            out.write((b1 << 2) | (b2 >> 4));
            
            return 1;
        }
        else if (c4 == padding)
        {
            b1 = decodingTable[c1];
            b2 = decodingTable[c2];
            b3 = decodingTable[c3];

            if ((b1 | b2 | b3) < 0)
            {
                throw new IOException("invalid characters encountered at end of base64 data");
            }
            
            out.write((b1 << 2) | (b2 >> 4));
            out.write((b2 << 4) | (b3 >> 2));
            
            return 2;
        }
        else
        {
            b1 = decodingTable[c1];
            b2 = decodingTable[c2];
            b3 = decodingTable[c3];
            b4 = decodingTable[c4];

            if ((b1 | b2 | b3 | b4) < 0)
            {
                throw new IOException("invalid characters encountered at end of base64 data");
            }
            
            out.write((b1 << 2) | (b2 >> 4));
            out.write((b2 << 4) | (b3 >> 2));
            out.write((b3 << 6) | b4);
            
            return 3;
        } 
    }

    private int nextI(String data, int i, int finish)
    {
        while ((i < finish) && ignore(data.charAt(i)))
        {
            i++;
        }
        return i;
    }
}
