package org.bouncycastle.bcpg;

import java.io.IOException;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.Iterator;
import java.util.List;

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

    OutputStream    out;
    byte[]           buf = new byte[3];
    int             bufPtr = 0;
    CRC24           crc = new FastCRC24();
    int             chunkCount = 0;
    int             lastb;

    boolean         start = true;
    boolean         clearText = false;
    boolean         newLine = false;

    String          nl = Strings.lineSeparator();

    String          type;
    String          headerStart = "-----BEGIN PGP ";
    String          headerTail = "-----";
    String          footerStart = "-----END PGP ";
    String          footerTail = "-----";

    String          version = "BCPG v@RELEASE_NAME@";

    Hashtable<String, List<String>> headers = new Hashtable<String, List<String>>();

    /**
     * Constructs an armored output stream with {@link #resetHeaders() default headers}.
     *
     * @param out the OutputStream to wrap.
     */
    public ArmoredOutputStream(
        OutputStream    out)
    {
        this.out = out;

        if (nl == null)
        {
            nl = "\r\n";
        }

        setHeader(VERSION_HDR, version);
    }

    /**
     * Constructs an armored output stream with default and custom headers.
     *
     * @param out the OutputStream to wrap.
     * @param headers additional headers that add to or override the {@link #resetHeaders() default
     *            headers}.
     */
    public ArmoredOutputStream(
        OutputStream out,
        Hashtable<String, String> headers)
    {
        this(out);

        Enumeration<String> e = headers.keys();

        while (e.hasMoreElements())
        {
            String key = e.nextElement();
            List<String> headerList = new ArrayList<String>();
            headerList.add(headers.get(key));
            this.headers.put(key, headerList);
        }
    }

    /**
     * Set an additional header entry. Any current value(s) under the same name will be
     * replaced by the new one. A null value will clear the entry for name.
     *
     * @param name the name of the header entry.
     * @param value the value of the header entry.
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
            List<String> valueList = headers.get(name);
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
     */
    public void clearHeaders()
    {
        headers.clear();
    }

    /**
     * Set an additional header entry. The current value(s) will continue to exist together
     * with the new one. Adding a null value has no effect.
     *
     * @param name the name of the header entry.
     * @param value the value of the header entry.
     */
    public void addHeader(
        String name,
        String value)
    {
        if (value == null || name == null)
        {
            return;
        }
        List<String> valueList = headers.get(name);
        if (valueList == null)
        {
            valueList = new ArrayList<String>();
            headers.put(name, valueList);
        }
        valueList.add(value);
    }


    /**
     * Reset the headers to only contain a Version string (if one is present)
     */
    public void resetHeaders()
    {
        List<String> versions = headers.get(VERSION_HDR);

        headers.clear();

        if (versions != null)
        {
            headers.put(VERSION_HDR, versions);
        }
    }

    /**
     * Start a clear text signed message - backwards compatibility.
     * @param hashAlgorithm hash algorithm
     */
    public void beginClearText(
        int hashAlgorithm)
        throws IOException
    {
        beginClearText(new int[] { hashAlgorithm });
    }

    /**
     * Start a clear text signed message.
     * @param hashAlgorithms hash algorithms
     */
    public void beginClearText(
        int... hashAlgorithms)
        throws IOException
    {
        StringBuilder sb = new StringBuilder("-----BEGIN PGP SIGNED MESSAGE-----");
        sb.append(nl);
        for (int hashAlgorithm : hashAlgorithms)
        {
            String hash;
            switch (hashAlgorithm)
            {
                case HashAlgorithmTags.SHA1:
                    hash = "SHA1";
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
                case HashAlgorithmTags.SHA3_256:
                    hash = "SHA3-256";
                    break;
                case HashAlgorithmTags.SHA3_512:
                    hash = "SHA3-512";
                    break;
                case HashAlgorithmTags.MD2:
                    hash = "MD2";
                    break;
                case HashAlgorithmTags.MD5:
                    hash = "MD5";
                    break;
                case HashAlgorithmTags.RIPEMD160:
                    hash = "RIPEMD160";
                    break;
                case HashAlgorithmTags.SHA224:
                    hash = "SHA224";
                    break;
                default:
                    throw new IOException("unknown hash algorithm tag in beginClearText: " + hashAlgorithm);
            }
            sb.append("Hash: ").append(hash).append(nl);
        }
        sb.append(nl);

        for (int i = 0; i != sb.length(); i++)
        {
            out.write(sb.charAt(i));
        }

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
        for (int i = 0; i != name.length(); i++)
        {
            out.write(name.charAt(i));
        }

        out.write(':');
        out.write(' ');

        out.write(Strings.toUTF8ByteArray(value));

        for (int i = 0; i != nl.length(); i++)
        {
            out.write(nl.charAt(i));
        }
    }

    public void write(
        int    b)
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
            boolean     newPacket = (b & 0x40) != 0;
            int         tag = 0;

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

            for (int i = 0; i != headerStart.length(); i++)
            {
                out.write(headerStart.charAt(i));
            }

            for (int i = 0; i != type.length(); i++)
            {
                out.write(type.charAt(i));
            }

            for (int i = 0; i != headerTail.length(); i++)
            {
                out.write(headerTail.charAt(i));
            }

            for (int i = 0; i != nl.length(); i++)
            {
                out.write(nl.charAt(i));
            }

            if (headers.containsKey(VERSION_HDR))
            {
                writeHeaderEntry(VERSION_HDR, headers.get(VERSION_HDR).get(0));
            }

            Enumeration<String> e = headers.keys();
            while (e.hasMoreElements())
            {
                String  key = e.nextElement();

                if (!key.equals(VERSION_HDR))
                {
                    List<String> values = headers.get(key);
                    for (Iterator<String> it = values.iterator(); it.hasNext();)
                    {
                        writeHeaderEntry(key, it.next());
                    }
                }
            }

            for (int i = 0; i != nl.length(); i++)
            {
                out.write(nl.charAt(i));
            }

            start = false;
        }

        if (bufPtr == 3)
        {
            crc.update3(buf, 0);
            encode3(out, buf);
            bufPtr = 0;
            if ((++chunkCount & 0xf) == 0)
            {
                for (int i = 0; i != nl.length(); i++)
                {
                    out.write(nl.charAt(i));
                }
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
                for (int i = 0; i < bufPtr; ++i)
                {
                    crc.update(buf[i] & 0xFF);
                }
                encode(out, buf, bufPtr);
            }

            for (int i = 0; i != nl.length(); i++)
            {
                out.write(nl.charAt(i));
            }
            out.write('=');

            int crcV = crc.getValue();

            buf[0] = (byte)(crcV >>> 16);
            buf[1] = (byte)(crcV >>> 8);
            buf[2] = (byte)crcV;

            encode3(out, buf);

            for (int i = 0; i != nl.length(); i++)
            {
                out.write(nl.charAt(i));
            }

            for (int i = 0; i != footerStart.length(); i++)
            {
                out.write(footerStart.charAt(i));
            }

            for (int i = 0; i != type.length(); i++)
            {
                out.write(type.charAt(i));
            }

            for (int i = 0; i != footerTail.length(); i++)
            {
                out.write(footerTail.charAt(i));
            }

            for (int i = 0; i != nl.length(); i++)
            {
                out.write(nl.charAt(i));
            }

            out.flush();

            type = null;
            start = true;
        }
    }
}
