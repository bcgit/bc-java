package org.bouncycastle.util.encoders;

import java.io.IOException;
import java.io.OutputStream;

import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Strings;

/**
 * A streaming Base32 encoder.
 */
public class Base32Encoder
    implements Encoder
{
    private static final byte[] DEAULT_ENCODING_TABLE =
    {
        (byte)'A', (byte)'B', (byte)'C', (byte)'D', (byte)'E', (byte)'F', (byte)'G',
        (byte)'H', (byte)'I', (byte)'J', (byte)'K', (byte)'L', (byte)'M', (byte)'N',
        (byte)'O', (byte)'P', (byte)'Q', (byte)'R', (byte)'S', (byte)'T', (byte)'U',
        (byte)'V', (byte)'W', (byte)'X', (byte)'Y', (byte)'Z',
        (byte)'2', (byte)'3', (byte)'4', (byte)'5', (byte)'6', (byte)'7'
    };

    private static final byte DEFAULT_PADDING = (byte)'=';

    /*
     * set up the decoding table.
     */
    private final byte[] encodingTable;
    private final byte   padding;
    private final byte[] decodingTable = new byte[128];

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

    /**
     * Base constructor for RFC 4648, Section 6.
     */
    public Base32Encoder()
    {
        this.encodingTable = DEAULT_ENCODING_TABLE;
        this.padding = DEFAULT_PADDING;

        initialiseDecodingTable();
    }

    /**
     * Constructor allowing the setting of an alternative alphabet.
     *
     * @param encodingTable a 32 entry encoding table to do the mapping.
     * @param padding the padding value to use.
     */
    public Base32Encoder(byte[] encodingTable, byte padding)
    {
        if (encodingTable.length != 32)
        {
            throw new IllegalArgumentException("encoding table needs to be length 32");
        }

        this.encodingTable = Arrays.clone(encodingTable);
        this.padding = padding;
        
        initialiseDecodingTable();
    }

    public int encode(byte[] inBuf, int inOff, int inLen, byte[] outBuf, int outOff) throws IOException
    {
        int inPos = inOff;
        int inEnd = inOff + inLen - 4;
        int outPos = outOff;

        while (inPos < inEnd)
        {
             encodeBlock(inBuf, inPos, outBuf, outPos);
             inPos += 5;
             outPos += 8;
        }

        int extra = inLen - (inPos - inOff);
        if (extra > 0)
        {
            byte[] in = new byte[5];
            System.arraycopy(inBuf, inPos, in, 0, extra);
            encodeBlock(in, 0, outBuf, outPos);
            switch (extra)
            {
            case 1:
                outBuf[outPos + 2] = padding;
                outBuf[outPos + 3] = padding;
                outBuf[outPos + 4] = padding;
                outBuf[outPos + 5] = padding;
                outBuf[outPos + 6] = padding;
                outBuf[outPos + 7] = padding;
                break;
            case 2:
                outBuf[outPos + 4] = padding;
                outBuf[outPos + 5] = padding;
                outBuf[outPos + 6] = padding;
                outBuf[outPos + 7] = padding;
                break;
            case 3:
                outBuf[outPos + 5] = padding;
                outBuf[outPos + 6] = padding;
                outBuf[outPos + 7] = padding;
                break;
            case 4:
                outBuf[outPos + 7] = padding;
                break;
            }

            outPos += 8;
        }

        return outPos - outOff;
    }

    private void encodeBlock(byte[] inBuf, int inPos, byte[] outBuf, int outPos)
    {
        int a1 = inBuf[inPos++];
        int a2 = inBuf[inPos++] & 0xFF;
        int a3 = inBuf[inPos++] & 0xFF;
        int a4 = inBuf[inPos++] & 0xFF;
        int a5 = inBuf[inPos] & 0xFF;

        outBuf[outPos++] = encodingTable[(a1 >>> 3) & 0x1F];
        outBuf[outPos++] = encodingTable[((a1 << 2) | (a2 >>> 6)) & 0x1F];
        outBuf[outPos++] = encodingTable[(a2 >>> 1) & 0x1F];
        outBuf[outPos++] = encodingTable[((a2 << 4) | (a3 >>> 4)) & 0x1F];
        outBuf[outPos++] = encodingTable[((a3 << 1) | (a4 >>> 7)) & 0x1F];
        outBuf[outPos++] = encodingTable[(a4 >>> 2) & 0x1F];
        outBuf[outPos++] = encodingTable[((a4 << 3) | (a5 >>> 5)) & 0x1F];
        outBuf[outPos] = encodingTable[a5 & 0x1F];
    }

    public int getEncodedLength(int inputLength)
    {
        return (inputLength + 4) / 5 * 8;
    }

    public int getMaxDecodedLength(int inputLength)
    {
        return inputLength / 8 * 5;
    }

    /**
     * encode the input data producing a base 32 output stream.
     *
     * @return the number of bytes produced.
     */
    public int encode(byte[] buf, int off, int len, OutputStream out) 
        throws IOException
    {
        if (len < 0)
        {
            return 0;
        }

        byte[] tmp = new byte[72];
        int remaining = len;
        while (remaining > 0)
        {
            int inLen = Math.min(45, remaining);
            int outLen = encode(buf, off, inLen, tmp, 0);
            out.write(tmp, 0, outLen);
            off += inLen;
            remaining -= inLen;
        }
        return (len + 2) / 3 * 4;
    }

    private boolean ignore(
        char    c)
    {
        return (c == '\n' || c =='\r' || c == '\t' || c == ' ');
    }
    
    /**
     * decode the base 32 encoded byte data writing it to the given output stream,
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
        byte    b1, b2, b3, b4, b5, b6, b7, b8;
        byte[]  outBuffer = new byte[55];
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

        while (finish > off && i != 8)
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

            i = nextI(data, i, finish);

            b5 = decodingTable[data[i++]];

            i = nextI(data, i, finish);

            b6 = decodingTable[data[i++]];

            i = nextI(data, i, finish);

            b7 = decodingTable[data[i++]];

            i = nextI(data, i, finish);

            b8 = decodingTable[data[i++]];

            if ((b1 | b2 | b3 | b4 | b5 | b6 | b7 | b8) < 0)
            {
                throw new IOException("invalid characters encountered in base32 data");
            }

            outBuffer[bufOff++] = (byte)((b1 << 3) | (b2 >> 2));
            outBuffer[bufOff++] = (byte)((b2 << 6) | (b3 << 1) | (b4 >> 4));
            outBuffer[bufOff++] = (byte)((b4 << 4) | (b5 >> 1));
            outBuffer[bufOff++] = (byte)((b5 << 7) | (b6 << 2) | (b7 >> 3));
            outBuffer[bufOff++] = (byte)((b7 << 5) | b8);

            if (bufOff == outBuffer.length)
            {
                out.write(outBuffer);
                bufOff = 0;
            }
            
            outLen += 5;
            
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
        int e4 = nextI(data, e3 + 1, end);
        int e5 = nextI(data, e4 + 1, end);
        int e6 = nextI(data, e5 + 1, end);
        int e7 = nextI(data, e6 + 1, end);

        outLen += decodeLastBlock(out,
            (char)data[e0], (char)data[e1], (char)data[e2], (char)data[e3],
            (char)data[e4], (char)data[e5], (char)data[e6], (char)data[e7]);

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
     * decode the base 32 encoded String data writing it to the given output stream,
     * whitespace characters will be ignored.
     *
     * @return the number of bytes produced.
     */
    public int decode(
        String          data,
        OutputStream    out)
        throws IOException
    {
        byte[] bytes = Strings.toByteArray(data);
        return decode(bytes, 0, bytes.length, out);
    }

    private int decodeLastBlock(OutputStream out,
                                char c1, char c2, char c3, char c4,
                                char c5, char c6, char c7, char c8)
        throws IOException
    {
        byte    b1, b2, b3, b4, b5, b6, b7, b8;
        
        if (c8 == padding)
        {
            if (c7 != padding)
            {
                b1 = decodingTable[c1];
                b2 = decodingTable[c2];
                b3 = decodingTable[c3];
                b4 = decodingTable[c4];
                b5 = decodingTable[c5];
                b6 = decodingTable[c6];
                b7 = decodingTable[c7];

                if ((b1 | b2 | b3 | b4 | b5 | b6 | b7) < 0)
                {
                    throw new IOException("invalid characters encountered at end of base32 data");
                }

                out.write((b1 << 3) | (b2 >> 2));
                out.write((b2 << 6) | (b3 << 1) | (b4 >> 4));
                out.write((b4 << 4) | (b5 >> 1));
                out.write((b5 << 7) | (b6 << 2) | (b7 >> 3));

                return 4;
            }
            if (c6 != padding)
            {
                throw new IOException("invalid characters encountered at end of base32 data");
            }

            if (c5 != padding)
            {
                b1 = decodingTable[c1];
                b2 = decodingTable[c2];
                b3 = decodingTable[c3];
                b4 = decodingTable[c4];
                b5 = decodingTable[c5];

                if ((b1 | b2 | b3 | b4 | b5) < 0)
                {
                    throw new IOException("invalid characters encountered at end of base32 data");
                }

                out.write((b1 << 3) | (b2 >> 2));
                out.write((b2 << 6) | (b3 << 1) | (b4 >> 4));
                out.write((b4 << 4) | (b5 >> 1));

                return 3;
            }

            if (c4 != padding)
            {
                b1 = decodingTable[c1];
                b2 = decodingTable[c2];
                b3 = decodingTable[c3];
                b4 = decodingTable[c4];

                if ((b1 | b2 | b3 | b4) < 0)
                {
                    throw new IOException("invalid characters encountered at end of base32 data");
                }

                out.write((b1 << 3) | (b2 >> 2));
                out.write((b2 << 6) | (b3 << 1) | (b4 >> 4));

                return 2;
            }
            
            if (c3 != padding)
            {
                throw new IOException("invalid characters encountered at end of base32 data");
            }

            b1 = decodingTable[c1];
            b2 = decodingTable[c2];

            if ((b1 | b2) < 0)
            {
                throw new IOException("invalid characters encountered at end of base32 data");
            }

            out.write((b1 << 3) | (b2 >> 2));
            
            return 1;
        }
        else
        {
            b1 = decodingTable[c1];
            b2 = decodingTable[c2];
            b3 = decodingTable[c3];
            b4 = decodingTable[c4];
            b5 = decodingTable[c5];
            b6 = decodingTable[c6];
            b7 = decodingTable[c7];
            b8 = decodingTable[c8];

            if ((b1 | b2 | b3 | b4 | b5 | b6 | b7 | b8) < 0)
            {
                throw new IOException("invalid characters encountered at end of base32 data");
            }
            
            out.write((b1 << 3) | (b2 >> 2));
            out.write((b2 << 6) | (b3 << 1) | (b4 >> 4));
            out.write((b4 << 4) | (b5 >> 1));
            out.write((b5 << 7) | (b6 << 2) | (b7 >> 3));
            out.write((b7 << 5) | b8);
            
            return 5;
        } 
    }
}
