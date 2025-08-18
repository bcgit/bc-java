package org.bouncycastle.bcpg;

import java.io.BufferedInputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;

import org.bouncycastle.util.io.Streams;

/**
 * Stream reader for PGP objects
 */
public class BCPGInputStream
    extends InputStream
    implements PacketTags
{
    /**
     * If the argument is a {@link BCPGInputStream}, return it.
     * Otherwise wrap it in a {@link BCPGInputStream} and then return the result.
     *
     * @param in input stream
     * @return BCPGInputStream
     */
    public static BCPGInputStream wrap(InputStream in)
    {
        if (in instanceof BCPGInputStream)
        {
            return (BCPGInputStream)in;
        }
        return new BCPGInputStream(in);
    }

    InputStream in;
    boolean next = false;
    int nextB;

    boolean mNext = false;
    int mNextB;

    public BCPGInputStream(
        InputStream in)
    {
        this.in = in;
    }

    public int available()
        throws IOException
    {
        return in.available();
    }

    public boolean markSupported()
    {
        return in.markSupported();
    }

    public synchronized void mark(int readLimit)
    {
        mNext = next;
        mNextB = nextB;
        in.mark(readLimit);
    }

    public synchronized void reset()
        throws IOException
    {
        next = mNext;
        nextB = mNextB;
        in.reset();
    }

    public int read()
        throws IOException
    {
        if (next)
        {
            next = false;

            return nextB;
        }
        else
        {
            return in.read();
        }
    }

    public int read(
        byte[] buf,
        int off,
        int len)
        throws IOException
    {
        if (len == 0)
        {
            return 0;
        }

        if (!next)
        {
            return in.read(buf, off, len);
        }

        // We have next byte waiting, so return it

        if (nextB < 0)
        {
            return -1; // EOF
        }

        buf[off] = (byte)nextB;  // May throw NullPointerException...
        next = false;            // ...so only set this afterwards

        return 1;
    }

    public void readFully(
        byte[] buf,
        int off,
        int len)
        throws IOException
    {
        if (Streams.readFully(this, buf, off, len) < len)
        {
            throw new EOFException();
        }
    }

    public byte[] readAll()
        throws IOException
    {
        return Streams.readAll(this);
    }

    public void readFully(
        byte[] buf)
        throws IOException
    {
        readFully(buf, 0, buf.length);
    }

    /**
     * Obtains the tag of the next packet in the stream.
     *
     * @return the {@link PacketTags tag number}.
     * @throws IOException if an error occurs reading the tag from the stream.
     */
    public int nextPacketTag()
        throws IOException
    {
        if (!next)
        {
            try
            {
                nextB = this.read();
            }
            catch (EOFException e)
            {
                nextB = -1;
            }

            next = true;
        }

        if (nextB < 0)
        {
            return nextB;
        }

        int maskB = nextB & 0x3f;
        if ((nextB & 0x40) == 0)    // old
        {
            maskB >>= 2;
        }
        return maskB;
    }

    /**
     * Reads the next packet from the stream.
     *
     * @throws IOException
     */
    public Packet readPacket()
        throws IOException
    {
        int hdr = this.read();

        if (hdr < 0)
        {
            return null;
        }

        if ((hdr & 0x80) == 0)
        {
            throw new IOException("invalid header encountered");
        }

        boolean newPacket = (hdr & 0x40) != 0;
        int tag = 0;
        int bodyLen = 0;
        boolean partial = false;

        if (newPacket)
        {
            tag = hdr & 0x3f;
            boolean[] flags = new boolean[3];
            bodyLen = StreamUtil.readBodyLen(this, flags);
            partial = flags[StreamUtil.flag_partial];
        }
        else
        {
            int lengthType = hdr & 0x3;

            tag = (hdr & 0x3f) >> 2;

            switch (lengthType)
            {
            case 0:
                bodyLen = this.read();
                break;
            case 1:
                bodyLen = StreamUtil.read2OctetLength(this);
                break;
            case 2:
                bodyLen = StreamUtil.read4OctetLength(this);
                break;
            case 3:
                partial = true;
                break;
            default:
                throw new IOException("unknown length type encountered");
            }
        }

        BCPGInputStream objStream;

        if (bodyLen == 0 && partial)
        {
            objStream = this;
        }
        else
        {
//            assert !this.next;
            PartialInputStream pis = new PartialInputStream(this.in, partial, bodyLen);
            objStream = new BCPGInputStream(new BufferedInputStream(pis));
        }

        switch (tag)
        {
        case RESERVED:
            return new ReservedPacket(objStream, newPacket);
        case PUBLIC_KEY_ENC_SESSION:
            return new PublicKeyEncSessionPacket(objStream, newPacket);
        case SIGNATURE:
            return new SignaturePacket(objStream, newPacket);
        case SYMMETRIC_KEY_ENC_SESSION:
            return new SymmetricKeyEncSessionPacket(objStream, newPacket);
        case ONE_PASS_SIGNATURE:
            return new OnePassSignaturePacket(objStream, newPacket);
        case SECRET_KEY:
            return new SecretKeyPacket(objStream, newPacket);
        case PUBLIC_KEY:
            return new PublicKeyPacket(objStream, newPacket);
        case SECRET_SUBKEY:
            return new SecretSubkeyPacket(objStream, newPacket);
        case COMPRESSED_DATA:
            return new CompressedDataPacket(objStream, newPacket);
        case SYMMETRIC_KEY_ENC:
            return new SymmetricEncDataPacket(objStream, newPacket);
        case MARKER:
            return new MarkerPacket(objStream, newPacket);
        case LITERAL_DATA:
            return new LiteralDataPacket(objStream, newPacket);
        case TRUST:
            return new TrustPacket(objStream, newPacket);
        case USER_ID:
            return new UserIDPacket(objStream, newPacket);
        case USER_ATTRIBUTE:
            return new UserAttributePacket(objStream, newPacket);
        case PUBLIC_SUBKEY:
            return new PublicSubkeyPacket(objStream, newPacket);
        case SYM_ENC_INTEGRITY_PRO:
            return new SymmetricEncIntegrityPacket(objStream, newPacket);
        case MOD_DETECTION_CODE:
            return new ModDetectionCodePacket(objStream, newPacket);
        case AEAD_ENC_DATA:
            return new AEADEncDataPacket(objStream, newPacket);
        case PADDING:
            return new PaddingPacket(objStream, newPacket);
        case EXPERIMENTAL_1:
        case EXPERIMENTAL_2:
        case EXPERIMENTAL_3:
        case EXPERIMENTAL_4:
            return new ExperimentalPacket(tag, objStream, newPacket);
        default:
            return new UnknownPacket(tag, objStream, newPacket);
        }
    }

    /**
     * @return the tag for the next non-marker/padding packet
     * @throws IOException on a parsing issue.
     * @deprecated use skipMarkerAndPaddingPackets
     */
    public int skipMarkerPackets()
        throws IOException
    {
        return skipMarkerAndPaddingPackets();
    }

    /**
     * skip any marker and padding packets found in the stream.
     *
     * @return the tag for the next non-marker/padding packet
     * @throws IOException on a parsing issue.
     */
    public int skipMarkerAndPaddingPackets()
        throws IOException
    {
        int tag;
        while ((tag = nextPacketTag()) == PacketTags.MARKER
            || tag == PacketTags.PADDING)
        {
            readPacket();
        }

        return tag;
    }

    public void close()
        throws IOException
    {
        in.close();
    }

    /**
     * a stream that overlays our input stream, allowing the user to only read a segment of it.
     * <p>
     * NB: dataLength will be negative if the segment length is in the upper range above 2**31.
     */
    private static class PartialInputStream
        extends InputStream
    {
        private final InputStream in;
        private boolean partial;
        private int dataLength;

        PartialInputStream(InputStream in, boolean partial, int dataLength)
        {
            this.in = in;
            this.partial = partial;
            this.dataLength = dataLength;
        }

        public int available()
            throws IOException
        {
            int avail = in.available();

            if (avail <= dataLength || dataLength < 0)
            {
                return avail;
            }
            else
            {
                if (partial && dataLength == 0)
                {
                    return 1;
                }
                return dataLength;
            }
        }

        private int loadDataLength()
            throws IOException
        {
            boolean[] flags = new boolean[3];
            dataLength = StreamUtil.readBodyLen(in, flags);
            if (flags[StreamUtil.flag_eof])
            {
                return -1;
            }
            partial = flags[StreamUtil.flag_partial];
            return dataLength;
        }

        public int read(byte[] buf, int offset, int len)
            throws IOException
        {
            do
            {
                if (dataLength != 0)
                {
                    int readLen = (dataLength > len || dataLength < 0) ? len : dataLength;
                    readLen = in.read(buf, offset, readLen);
                    if (readLen < 0)
                    {
                        throw new EOFException("premature end of stream in PartialInputStream");
                    }
                    dataLength -= readLen;
                    if (partial && dataLength == 0)
                    {
                        loadDataLength();
                    }
                    return readLen;
                }
            }
            while (partial && loadDataLength() >= 0);

            return -1;
        }

        public int read()
            throws IOException
        {
            do
            {
                if (dataLength != 0)
                {
                    int ch = in.read();
                    if (ch < 0)
                    {
                        throw new EOFException("premature end of stream in PartialInputStream");
                    }
                    dataLength--;
                    if (partial && dataLength == 0)
                    {
                        loadDataLength();
                    }
                    return ch;
                }
            }
            while (partial && loadDataLength() >= 0);

            return -1;
        }
    }
}
