package org.bouncycastle.bcpg;

import java.io.IOException;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Hashtable;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.StringTokenizer;

import org.bouncycastle.util.Strings;

/**
 * Output stream that writes data in ASCII Armored format.
 * <p>
 * Note 1: close() needs to be called on an ArmoredOutputStream to write the final checksum. flush() will not do this as
 * other classes assume it is always fine to call flush() - it is not though if the checksum gets output.
 * Note 2: as multiple PGP blobs are often written to the same stream, close() does not close the underlying stream.
 * </p>
 */
public class ArmoredOutputStream
    extends OutputStream
{
    public static final String VERSION_HDR = "Version";
    public static final String COMMENT_HDR = "Comment";
    public static final String MESSAGE_ID_HDR = "MessageID";
    public static final String HASH_HDR = "Hash";
    public static final String CHARSET_HDR = "Charset";

    public static final String DEFAULT_VERSION = "BCPG v@RELEASE_NAME@";
    
    private static final byte[] encodingTable =
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

    /**
     * encode the input data producing a base 64 encoded byte array.
     */
    private static void encode(OutputStream out, byte[] data, int len)
        throws IOException
    {
        int d1, d2, d3;

        switch (len)
        {
        case 1:
            d1 = data[0] & 0xFF;

            out.write(encodingTable[(d1 >>> 2) & 0x3f]);
            out.write(encodingTable[(d1 << 4) & 0x3f]);
            out.write('=');
            out.write('=');
            break;
        case 2:
            d1 = data[0] & 0xFF;
            d2 = data[1] & 0xFF;

            out.write(encodingTable[(d1 >>> 2) & 0x3f]);
            out.write(encodingTable[((d1 << 4) | (d2 >>> 4)) & 0x3f]);
            out.write(encodingTable[(d2 << 2) & 0x3f]);
            out.write('=');
            break;
        case 3:
            d1 = data[0] & 0xFF;
            d2 = data[1] & 0xFF;
            d3 = data[2] & 0xFF;

            out.write(encodingTable[(d1 >>> 2) & 0x3f]);
            out.write(encodingTable[((d1 << 4) | (d2 >>> 4)) & 0x3f]);
            out.write(encodingTable[((d2 << 2) | (d3 >>> 6)) & 0x3f]);
            out.write(encodingTable[d3 & 0x3f]);
            break;
        default:
            throw new IOException("unknown length in encode");
        }
    }

    /**
     * encode the input data producing a base 64 encoded byte array.
     */
    private static void encode3(OutputStream out, byte[] data)
        throws IOException
    {
        int d1 = data[0] & 0xFF;
        int d2 = data[1] & 0xFF;
        int d3 = data[2] & 0xFF;

        out.write(encodingTable[(d1 >>> 2) & 0x3f]);
        out.write(encodingTable[((d1 << 4) | (d2 >>> 4)) & 0x3f]);
        out.write(encodingTable[((d2 << 2) | (d3 >>> 6)) & 0x3f]);
        out.write(encodingTable[d3 & 0x3f]);
    }

    OutputStream out;
    byte[] buf = new byte[3];
    int bufPtr = 0;
    CRC24 crc = new FastCRC24();
    int chunkCount = 0;
    int lastb;

    boolean start = true;
    boolean clearText = false;
    boolean newLine = false;

    String nl = Strings.lineSeparator();

    String type;
    String headerStart = "-----BEGIN PGP ";
    String headerTail = "-----";
    String footerStart = "-----END PGP ";
    String footerTail = "-----";

    final Hashtable headers = new Hashtable();

    /**
     * Constructs an armored output stream with {@link #resetHeaders() default headers}.
     *
     * @param out the OutputStream to wrap.
     */
    public ArmoredOutputStream(
        OutputStream out)
    {
        this.out = out;

        if (nl == null)
        {
            nl = "\r\n";
        }

        setHeader(VERSION_HDR, DEFAULT_VERSION);
    }

    /**
     * Constructs an armored output stream with default and custom headers.
     *
     * @param out     the OutputStream to wrap.
     * @param headers additional headers that add to or override the {@link #resetHeaders() default
     *                headers}.
     */
    public ArmoredOutputStream(
        OutputStream out,
        Hashtable<String, String> headers)
    {
        this(out);

        Enumeration<String> e = headers.keys();

        while (e.hasMoreElements())
        {
            String key = (String)e.nextElement();
            List<String> headerList = new ArrayList<String>();
            headerList.add(headers.get(key));
            this.headers.put(key, headerList);
        }
    }

    ArmoredOutputStream(OutputStream out, Builder builder)
    {
        this(out);
        if (!builder.computeCRCSum)
        {
            crc = null;
        }
        this.headers.clear();

        Map<String, List<String>> headerMap = builder.headers;
        for (Iterator it = headerMap.keySet().iterator(); it.hasNext();)
        {
            String key = (String)it.next();

            this.headers.put(key, headerMap.get(key));
        }
    }

    /**
     * Set an additional header entry. Any current value(s) under the same name will be
     * replaced by the new one. A null value will clear the entry for name.
     *
     * @param name  the name of the header entry.
     * @param value the value of the header entry.
     * @deprecated use appropriate methods in {@link Builder} instead.
     */
    public void setHeader(
        String name,
        String value)
    {
        if (value == null)
        {
            this.headers.remove(name);
        }
        else
        {
            List<String> valueList = (List)headers.get(name);
            if (valueList == null)
            {
                valueList = new ArrayList<String>();
                headers.put(name, valueList);
            }
            else
            {
                valueList.clear();
            }
            valueList.add(value);
        }
    }

    /**
     * Remove all headers.
     *
     * @deprecated use appropriate methods in {@link Builder} instead.
     */
    public void clearHeaders()
    {
        headers.clear();
    }

    /**
     * Set an additional header entry. The current value(s) will continue to exist together
     * with the new one. Adding a null value has no effect.
     *
     * @param name  the name of the header entry.
     * @param value the value of the header entry.
     * @deprecated use appropriate methods in {@link Builder} instead
     */
    public void addHeader(
        String name,
        String value)
    {
        if (value == null || name == null)
        {
            return;
        }
        List<String> valueList = (List)headers.get(name);
        if (valueList == null)
        {
            valueList = new ArrayList<String>();
            headers.put(name, valueList);
        }
        valueList.add(value);
    }


    /**
     * Reset the headers to only contain a Version string (if one is present)
     *
     * @deprecated use {@link Builder#clearHeaders()} instead.
     */
    public void resetHeaders()
    {
        List<String> versions = (List)headers.get(VERSION_HDR);

        headers.clear();

        if (versions != null)
        {
            headers.put(VERSION_HDR, versions);
        }
    }

    /**
     * Start a clear text signed message - backwards compatibility.
     *
     * @param hashAlgorithm hash algorithm
     */
    public void beginClearText(
        int hashAlgorithm)
        throws IOException
    {
        beginClearText(new int[]{hashAlgorithm});
    }

    /**
     * Start a clear text signed message.
     *
     * @param hashAlgorithms hash algorithms
     */
    public void beginClearText(
        int... hashAlgorithms)
        throws IOException
    {
        StringBuffer sb = new StringBuffer("-----BEGIN PGP SIGNED MESSAGE-----");
        sb.append(nl);
        for (int i = 0; i != hashAlgorithms.length; i++)
        {
            int hashAlgorithm = hashAlgorithms[i];

            String hash;
            switch (hashAlgorithm)
            {
            case HashAlgorithmTags.MD5:
                hash = "MD5";
                break;
            case HashAlgorithmTags.SHA1:
                hash = "SHA1";
                break;
            case HashAlgorithmTags.RIPEMD160:
                hash = "RIPEMD160";
                break;
            case HashAlgorithmTags.MD2:
                hash = "MD2";
                break;
            case HashAlgorithmTags.SHA256:
                hash = "SHA256";
                break;
            case HashAlgorithmTags.SHA384:
                hash = "SHA384";
                break;
            case HashAlgorithmTags.SHA512:
                hash = "SHA512";
                break;
            case HashAlgorithmTags.SHA224:
                hash = "SHA224";
                break;
            case HashAlgorithmTags.SHA3_256:
            case HashAlgorithmTags.SHA3_256_OLD:
                hash = "SHA3-256";
                break;
            case HashAlgorithmTags.SHA3_384: // OLD
                hash = "SHA3-384";
                break;
            case HashAlgorithmTags.SHA3_512:
            case HashAlgorithmTags.SHA3_512_OLD:
                hash = "SHA3-512";
                break;
            case HashAlgorithmTags.SHA3_224:
                hash = "SHA3-224";
                break;
            default:
                throw new IOException("unknown hash algorithm tag in beginClearText: " + hashAlgorithm);
            }
            sb.append(HASH_HDR).append(": ").append(hash).append(nl);
        }
        sb.append(nl);

        write(sb.toString());
        clearText = true;
        newLine = true;
        lastb = 0;
    }

    public void endClearText()
    {
        clearText = false;
    }

    private void writeHeaderEntry(
        String name,
        String value)
        throws IOException
    {
        write(name);
        write(": ");
        write(value);
        write(nl);
    }

    public void write(
        int b)
        throws IOException
    {
        if (clearText)
        {
            out.write(b);

            if (newLine)
            {
                if (!(b == '\n' && lastb == '\r'))
                {
                    newLine = false;
                }
                if (b == '-')
                {
                    out.write(' ');
                    out.write('-');      // dash escape
                }
            }
            if (b == '\r' || (b == '\n' && lastb != '\r'))
            {
                newLine = true;
            }
            lastb = b;
            return;
        }

        if (start)
        {
            boolean newPacket = (b & 0x40) != 0;
            int tag = 0;

            if (newPacket)
            {
                tag = b & 0x3f;
            }
            else
            {
                tag = (b & 0x3f) >> 2;
            }

            switch (tag)
            {
            case PacketTags.PUBLIC_KEY:
                type = "PUBLIC KEY BLOCK";
                break;
            case PacketTags.SECRET_KEY:
                type = "PRIVATE KEY BLOCK";
                break;
            case PacketTags.SIGNATURE:
                type = "SIGNATURE";
                break;
            default:
                type = "MESSAGE";
            }

            write(headerStart);
            write(type);
            write(headerTail);
            write(nl);

            if (headers.containsKey(VERSION_HDR))
            {
                writeHeaderEntry(VERSION_HDR, (String)((List)headers.get(VERSION_HDR)).get(0));
            }

            Enumeration<String> e = headers.keys();
            while (e.hasMoreElements())
            {
                String key = (String)e.nextElement();

                if (!key.equals(VERSION_HDR))
                {
                    List<String> values = (List)headers.get(key);
                    for (Iterator<String> it = values.iterator(); it.hasNext(); )
                    {
                        writeHeaderEntry(key, (String)it.next());
                    }
                }
            }

            write(nl);
            start = false;
        }

        if (bufPtr == 3)
        {
            if (crc != null)
            {
                crc.update3(buf, 0);
            }
            encode3(out, buf);
            bufPtr = 0;
            if ((++chunkCount & 0xf) == 0)
            {
                write(nl);
            }
        }

        buf[bufPtr++] = (byte)b;
    }

    public void flush()
        throws IOException
    {
    }

    /**
     * <b>Note</b>: close() does not close the underlying stream. So it is possible to write
     * multiple objects using armoring to a single stream.
     */
    public void close()
        throws IOException
    {
        if (type != null)
        {
            if (bufPtr > 0)
            {
                if (crc != null)
                {
                    for (int i = 0; i < bufPtr; ++i)
                    {
                        crc.update(buf[i] & 0xFF);
                    }
                }
                encode(out, buf, bufPtr);
            }

            write(nl);

            if (crc != null)
            {
                out.write('=');

                int crcV = crc.getValue();

                buf[0] = (byte)(crcV >>> 16);
                buf[1] = (byte)(crcV >>> 8);
                buf[2] = (byte)crcV;

                encode3(out, buf);
                write(nl);
            }

            write(footerStart);
            write(type);
            write(footerTail);
            write(nl);

            out.flush();

            type = null;
            start = true;
        }
    }

    private void write(String string)
        throws IOException
    {
        out.write(Strings.toUTF8ByteArray(string));
    }

    public static Builder builder()
    {
        return new Builder();
    }

    public static class Builder
    {
        private final Map<String, List<String>> headers = new HashMap<String, List<String>>();
        private boolean computeCRCSum = true;

        private Builder()
        {

        }

        public ArmoredOutputStream build(OutputStream outputStream)
        {
            return new ArmoredOutputStream(outputStream, this);
        }

        /**
         * Set a <pre>Version:</pre> header.
         * Note: Adding version headers to ASCII armored output is discouraged to minimize metadata.
         *
         * @param version version
         * @return builder
         */
        public Builder setVersion(String version)
        {
            return setSingletonHeader(VERSION_HDR, version);
        }

        /**
         * Replace the <pre>Comment:</pre> header field with the given comment.
         * If the comment contains newlines, multiple headers will be added, one for each newline.
         * If the comment is <pre>null</pre>, then the output will contain no comments.
         *
         * @param comment comment
         * @return builder
         */
        public Builder setComment(String comment)
        {
            return replaceHeader(COMMENT_HDR, comment);
        }

        /**
         * Replace the <pre>MessageID:</pre> header field with the given messageId.
         *
         * @param messageId message ID
         * @return builder
         */
        public Builder setMessageId(String messageId)
        {
            return replaceHeader(MESSAGE_ID_HDR, messageId);
        }

        /**
         * Replace the <pre>Charset:</pre> header with the given value.
         *
         * @param charset charset
         * @return builder
         */
        public Builder setCharset(String charset)
        {
            return replaceHeader(CHARSET_HDR, charset);
        }

        /**
         * Add the given value as one or more additional <pre>Comment:</pre> headers to the already present comments.
         * If the comment contains newlines, multiple headers will be added, one for each newline.
         * If the comment is <pre>null</pre>, this method does nothing.
         *
         * @param comment comment
         * @return builder
         */
        public Builder addComment(String comment)
        {
            return addHeader(COMMENT_HDR, comment);
        }

        /**
         * Set and replace the given header value with a single-line header.
         * If the value is <pre>null</pre>, this method will remove the header entirely.
         *
         * @param key   header key
         * @param value header value
         * @return builder
         */
        private Builder setSingletonHeader(String key, String value)
        {
            if (value == null || value.trim().length() == 0)
            {
                this.headers.remove(key);
            }
            else
            {
                String trimmed = value.trim();
                if (trimmed.indexOf("\n") >= 0)
                {
                    throw new IllegalArgumentException("Armor header value for key " + key + " cannot contain newlines.");
                }
                List h = new ArrayList();
                h.add(value);
                this.headers.put(key, h);
            }
            return this;
        }

        /**
         * Add a header, splitting it into multiple headers if required (newlines).
         *
         * @param key   key
         * @param value value
         * @return builder
         */
        private Builder addHeader(String key, String value)
        {
            if (value == null || value.trim().length() == 0)
            {
                return this;
            }

            List<String> values = (List)headers.get(key);
            if (values == null)
            {
                values = new ArrayList<String>();
                headers.put(key, values);
            }

            // handle multi-line values
            String trimmed = value.trim();
            for (StringTokenizer sTok = new StringTokenizer(trimmed, "\n"); sTok.hasMoreTokens();)
            {
                String line = sTok.nextToken().trim();
                if (line.length() == 0)
                {
                    continue;
                }
                values.add(line);
            }
            return this;
        }

        /**
         * Replace all header values for the given key with the given value.
         * If the value is <pre>null</pre>, existing headers for the given key are removed.
         * The value is split into multiple headers if it contains newlines.
         *
         * @param key   key
         * @param value value
         * @return builder
         */
        private Builder replaceHeader(String key, String value)
        {
            if (value == null || value.trim().length() == 0)
            {
                return this;
            }

            List<String> values = new ArrayList<String>();

            // handle multi-line values
            String trimmed = value.trim();
            for (StringTokenizer sTok = new StringTokenizer(trimmed, "\n"); sTok.hasMoreTokens();)
            {
                String line = sTok.nextToken().trim();
                if (line.length() == 0)
                {
                    continue;
                }
                values.add(line);
            }

            headers.put(key, values);
            return this;
        }

        public Builder clearHeaders()
        {
            headers.clear();
            return this;
        }

        /**
         * Enable calculation and inclusion of the CRC check sum (default is true).
         * @param doComputeCRC true if CRC to be included, false otherwise.
         * @return the current builder instance.
         */
        public Builder enableCRC(boolean doComputeCRC)
        {
            this.computeCRCSum = doComputeCRC;
            return this;
        }
    }
}
