package org.bouncycastle.bcpg;

import java.io.ByteArrayOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;

import org.bouncycastle.util.StringList;
import org.bouncycastle.util.Strings;

/**
 * reader for Base64 armored objects - read the headers and then start returning
 * bytes when the data is reached. An IOException is thrown if the CRC check
 * is detected and fails.
 * <p>
 * By default a missing CRC will not cause an exception. To force CRC detection use:
 * <pre>
 *     ArmoredInputStream aIn = ...
 *
 *     aIn.setDetectMissingCRC(true);
 * </pre>
 * </p>
 */
public class ArmoredInputStream
    extends InputStream
{
    /*
     * set up the decoding table.
     */
    private static final byte[] decodingTable;

    static
    {
        decodingTable = new byte[128];

        for (int i = 0; i < decodingTable.length; i++)
        {
            decodingTable[i] = (byte)0xff;
        }

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
    private static int decode(int in0, int in1, int in2, int in3, byte[] out)
        throws IOException
    {
        int b1, b2, b3, b4;

        if (in3 < 0)
        {
            throw new EOFException("unexpected end of file in armored stream.");
        }

        if (in2 == '=')
        {
            b1 = decodingTable[in0] &0xff;
            b2 = decodingTable[in1] & 0xff;

            if ((b1 | b2) < 0)
            {
                throw new ArmoredInputException("invalid armor");
            }

            out[2] = (byte)((b1 << 2) | (b2 >> 4));

            return 2;
        }
        else if (in3 == '=')
        {
            b1 = decodingTable[in0];
            b2 = decodingTable[in1];
            b3 = decodingTable[in2];

            if ((b1 | b2 | b3) < 0)
            {
                throw new ArmoredInputException("invalid armor");
            }

            out[1] = (byte)((b1 << 2) | (b2 >> 4));
            out[2] = (byte)((b2 << 4) | (b3 >> 2));

            return 1;
        }
        else
        {
            b1 = decodingTable[in0];
            b2 = decodingTable[in1];
            b3 = decodingTable[in2];
            b4 = decodingTable[in3];

            if ((b1 | b2 | b3 | b4) < 0)
            {
                throw new ArmoredInputException("invalid armor");
            }

            out[0] = (byte)((b1 << 2) | (b2 >> 4));
            out[1] = (byte)((b2 << 4) | (b3 >> 2));
            out[2] = (byte)((b3 << 6) | b4);

            return 0;
        }
    }

    /*
     * Ignore missing CRC checksums.
     * https://tests.sequoia-pgp.org/#ASCII_Armor suggests that missing CRC sums do not invalidate the message.
     */
    private boolean detectMissingChecksum = false;

    private final CRC24   crc;

    InputStream    in;
    boolean        start = true;
    byte[]         outBuf = new byte[3];
    int            bufPtr = 3;
    boolean        crcFound = false;
    boolean        hasHeaders = true;
    String         header = null;
    boolean        newLineFound = false;
    boolean        clearText = false;
    boolean        restart = false;
    StringList     headerList= Strings.newList();
    int            lastC = 0;
    boolean        isEndOfStream;
    
    /**
     * Create a stream for reading a PGP armoured message, parsing up to a header 
     * and then reading the data that follows.
     * 
     * @param in
     */
    public ArmoredInputStream(
        InputStream    in) 
        throws IOException
    {
        this(in, true);
    }

    /**
     * Create an armoured input stream which will assume the data starts
     * straight away, or parse for headers first depending on the value of 
     * hasHeaders.
     * 
     * @param in
     * @param hasHeaders true if headers are to be looked for, false otherwise.
     */
    public ArmoredInputStream(
        InputStream    in,
        boolean        hasHeaders) 
        throws IOException
    {
        this.in = in;
        this.hasHeaders = hasHeaders;
        this.crc = new FastCRC24();
        
        if (hasHeaders)
        {
            parseHeaders();
        }

        start = false;
    }

    private ArmoredInputStream(
        InputStream    in,
        Builder        builder)
        throws IOException
    {
        this.in = in;
        this.hasHeaders = builder.hasHeaders;
        this.detectMissingChecksum = builder.detectMissingCRC;
        this.crc = builder.ignoreCRC ? null : new FastCRC24();

        if (hasHeaders)
        {
            parseHeaders();
        }

        start = false;
    }

    public int available()
        throws IOException
    {
        return in.available();
    }
    
    private boolean parseHeaders()
        throws IOException
    {
        header = null;
        
        int        c;
        int        last = 0;
        boolean    headerFound = false;
        
        headerList = Strings.newList();
        
        //
        // if restart we already have a header
        //
        if (restart)
        {
            headerFound = true;
        }
        else
        {
            while ((c = in.read()) >= 0)
            {
                if (c == '-' && (last == 0 || last == '\n' || last == '\r'))
                {
                    headerFound = true;
                    break;
                }
    
                last = c;
            }
        }

        if (headerFound)
        {
            boolean         eolReached = false;
            boolean         crLf = false;

            ByteArrayOutputStream buf = new ByteArrayOutputStream();
            buf.write('-');

            if (restart)    // we've had to look ahead two '-'
            {
                buf.write('-');
            }
            
            while ((c = in.read()) >= 0)
            {
                if (last == '\r' && c == '\n')
                {
                    crLf = true;
                }
                if (eolReached && (last != '\r' && c == '\n'))
                {
                    break;
                }
                if (eolReached && c == '\r')
                {
                    break;
                }
                if (c == '\r' || (last != '\r' && c == '\n'))
                {
                    String line = Strings.fromUTF8ByteArray(buf.toByteArray());
                    if (line.trim().length() == 0)
                    {
                        break;
                    }
                    if (headerList.size() != 0 && line.indexOf(':') < 0)
                    {
                        throw new ArmoredInputException("invalid armor header");
                    }
                    headerList.add(line);
                    buf.reset();
                }

                if (c != '\n' && c != '\r')
                {
                    buf.write(c);
                    eolReached = false;
                }
                else
                {
                    if (c == '\r' || (last != '\r' && c == '\n'))
                    {
                        eolReached = true;
                    }
                }
                
                last = c;
            }
            
            if (crLf)
            {
                int nl = in.read(); // skip last \n
                if (nl != '\n')
                {
                    throw new ArmoredInputException("inconsistent line endings in headers");
                }
            }
        }
        
        if (headerList.size() > 0)
        {
            header = headerList.get(0);
        }
        
        clearText = "-----BEGIN PGP SIGNED MESSAGE-----".equals(header);
        newLineFound = true;

        return headerFound;
    }

    /**
     * @return true if we are inside the clear text section of a PGP
     * signed message.
     */
    public boolean isClearText()
    {
        return clearText;
    }

    /**
     * @return true if the stream is actually at end of file.
     */
    public boolean isEndOfStream()
    {
        return isEndOfStream;
    }

    /**
     * Return the armor header line (if there is one)
     * @return the armor header line, null if none present.
     */
    public String    getArmorHeaderLine()
    {
        return header;
    }
    
    /**
     * Return the armor headers (the lines after the armor header line),
     * @return an array of armor headers, null if there aren't any.
     */
    public String[] getArmorHeaders()
    {
        if (headerList.size() <= 1)
        {
            return null;
        }

        return headerList.toStringArray(1, headerList.size());
    }
    
    private int readIgnoreSpace() 
        throws IOException
    {
        int    c = in.read();
        
        while (c == ' ' || c == '\t' || c == '\f' || c == '\u000B') // \u000B ~ \v
        {
            c = in.read();
        }

        if (c >= 128)
        {
            throw new ArmoredInputException("invalid armor");
        }

        return c;
    }
    
    public int read()
        throws IOException
    {
        int    c;

        if (start)
        {
            if (hasHeaders)
            {
                parseHeaders();
            }

            if (crc != null)
            {
                crc.reset();
            }
            start = false;
        }
        
        if (clearText)
        {
            c = in.read();

            if (c == '\r' || (c == '\n' && lastC != '\r'))
            {
                newLineFound = true;
            }
            else if (newLineFound && c == '-')
            {
                c = in.read();
                if (c == '-')            // a header, not dash escaped
                {
                    clearText = false;
                    start = true;
                    restart = true;
                }
                else                   // a space - must be a dash escape
                {
                    c = in.read();
                }
                newLineFound = false;
            }
            else
            {
                if (c != '\n' && lastC != '\r')
                {
                    newLineFound = false;
                }
            }
            
            lastC = c;

            if (c < 0)
            {
                isEndOfStream = true;
            }
            
            return c;
        }

        if (bufPtr > 2 || crcFound)
        {
            c = readIgnoreSpace();
            
            if (c == '\r' || c == '\n')
            {
                c = readIgnoreSpace();
                
                while (c == '\n' || c == '\r')
                {
                    c = readIgnoreSpace();
                }

                if (c == '=')            // crc reached
                {
                    bufPtr = decode(readIgnoreSpace(), readIgnoreSpace(), readIgnoreSpace(), readIgnoreSpace(), outBuf);
                    if (bufPtr != 0)
                    {
                        throw new ArmoredInputException("malformed crc in armored message");
                    }

                    crcFound = true;

                    if (crc != null)
                    {
                        int i = ((outBuf[0] & 0xff) << 16)
                            | ((outBuf[1] & 0xff) << 8)
                            | (outBuf[2] & 0xff);
                        if (i != crc.getValue())
                        {
                            throw new ArmoredInputException("crc check failed in armored message");
                        }
                    }

                    return read();
                }

                if (c == '-')        // end of record reached
                {
                    while ((c = in.read()) >= 0)
                    {
                        if (c == '\n' || c == '\r')
                        {
                            break;
                        }
                    }

                    if (!crcFound && detectMissingChecksum)
                    {
                        throw new ArmoredInputException("crc check not found");
                    }

                    crcFound = false;
                    start = true;
                    bufPtr = 3;

                    if (c < 0)
                    {
                        isEndOfStream = true;
                    }

                    return -1;
                }
            }

            if (c < 0)
            {
                isEndOfStream = true;
                return -1;
            }

            bufPtr = decode(c, readIgnoreSpace(), readIgnoreSpace(), readIgnoreSpace(), outBuf);

            if (crc != null)
            {
                if (bufPtr == 0)
                {
                    crc.update3(outBuf, 0);
                }
                else
                {
                    for (int i = bufPtr; i < 3; ++i)
                    {
                        crc.update(outBuf[i] & 0xFF);
                    }
                }
            }
        }

        return outBuf[bufPtr++] & 0xFF;
    }

    /**
     * Reads up to <code>len</code> bytes of data from the input stream into
     * an array of bytes.  An attempt is made to read as many as
     * <code>len</code> bytes, but a smaller number may be read.
     * The number of bytes actually read is returned as an integer.
     *
     * The first byte read is stored into element <code>b[off]</code>, the
     * next one into <code>b[off+1]</code>, and so on. The number of bytes read
     * is, at most, equal to <code>len</code>.
     *
     * NOTE: We need to override the custom behavior of Java's {@link InputStream#read(byte[], int, int)},
     * as the upstream method silently swallows {@link IOException IOExceptions}.
     * This would cause CRC checksum errors to go unnoticed.
     *
     * @see <a href="https://github.com/bcgit/bc-java/issues/998">Related BC bug report</a>
     * @param b byte array
     * @param off offset at which we start writing data to the array
     * @param len number of bytes we write into the array
     * @return total number of bytes read into the buffer
     *
     * @throws IOException if an exception happens AT ANY POINT
     */
    public int read(byte[] b, int off, int len) throws IOException
    {
        checkIndexSize(b.length, off, len);

        if (len == 0)
        {
            return 0;
        }

        int c = read();
        if (c == -1)
        {
            return -1;
        }
        b[off] = (byte)c;

        int i = 1;
        for (; i < len ; i++)
        {
            c = read();
            if (c == -1)
            {
                break;
            }
            b[off + i] = (byte)c;
        }
        return i;
    }

    private void checkIndexSize(int size, int off, int len)
    {
        if (off < 0 || len < 0)
        {
            throw new IndexOutOfBoundsException("Offset and length cannot be negative.");
        }
        if (off > size - len)
        {
            throw new IndexOutOfBoundsException("Invalid offset and length.");
        }
    }

    public void close()
        throws IOException
    {
        in.close();
    }

    /**
     * Change how the stream should react if it encounters missing CRC checksum.
     * The default value is false (ignore missing CRC checksums). If the behavior is set to true,
     * an {@link IOException} will be thrown if a missing CRC checksum is encountered.
     *
     * @param detectMissing false if ignore missing CRC sums, true for exception
     * @deprecated use Builder class for configuring this.
     */
    public void setDetectMissingCRC(boolean detectMissing)
    {
        this.detectMissingChecksum = detectMissing;
    }

    public static Builder builder()
    {
        return new Builder();
    }

    public static class Builder
    {
        private boolean hasHeaders = false;
        private boolean detectMissingCRC = false;
        private boolean ignoreCRC = false;

        private Builder()
        {

        }

        /**
         * Turn on header parsing (default value false).
         *
         * @param hasHeaders true if headers should be expected, false otherwise.
         * @return the current builder instance.
         */
        public Builder setParseForHeaders(boolean hasHeaders)
        {
            this.hasHeaders = hasHeaders;

            return this;
        }

        /**
         * Change how the stream should react if it encounters missing CRC checksum.
         * The default value is false (ignore missing CRC checksums). If the behavior is set to true,
         * an {@link IOException} will be thrown if a missing CRC checksum is encountered.
         *
         * @param detectMissingCRC false if ignore missing CRC sums, true for exception
         */
        public Builder setDetectMissingCRC(boolean detectMissingCRC)
        {
            this.detectMissingCRC = detectMissingCRC;

            return this;
        }

        /**
         * Specifically ignore the CRC if in place (this will also avoid the cost of calculation).
         *
         * @param ignoreCRC true if CRC should be ignored, false otherwise.
         * @return the current builder instance.
         */
        public Builder setIgnoreCRC(boolean ignoreCRC)
        {
            this.ignoreCRC = ignoreCRC;

            return this;
        }

        public ArmoredInputStream build(InputStream inputStream)
            throws IOException
        {
            return new ArmoredInputStream(inputStream, this);
        }
    }
}
