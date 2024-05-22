package org.bouncycastle.bcpg;

import java.io.IOException;
import java.io.OutputStream;

import org.bouncycastle.util.Arrays;

/**
 * Basic output stream.
 */
public class BCPGOutputStream
    extends OutputStream
    implements PacketTags, CompressionAlgorithmTags
{
    /**
     * If the argument is a {@link BCPGOutputStream}, return it.
     * Otherwise wrap it in a {@link BCPGOutputStream} and then return the result.
     *
     * @param out output stream
     * @return BCPGOutputStream
     */
    public static BCPGOutputStream wrap(OutputStream out)
    {
        if (out instanceof BCPGOutputStream)
        {
            return (BCPGOutputStream)out;
        }
        return new BCPGOutputStream(out);
    }

    OutputStream out;
    private PacketFormat packetFormat;
    private byte[] partialBuffer;
    private int partialBufferLength;
    private int partialPower;
    private int partialOffset;

    private static final int BUF_SIZE_POWER = 16; // 2^16 size buffer on long files

    /**
     * Base constructor - generate a PGP protocol encoding with old-style packets whenever
     * there is an alternative for backwards compatibility.
     *
     * @param out output stream to write encoded data to.
     */
    public BCPGOutputStream(
        OutputStream out)
    {
        this(out, PacketFormat.ROUNDTRIP);
    }

    /**
     * Base constructor specifying whether to use packets in the new format
     * wherever possible.
     *
     * @param out           output stream to write encoded data to.
     * @param newFormatOnly true if use new format packets, false if backwards compatible preferred.
     */
    public BCPGOutputStream(
        OutputStream out,
        boolean newFormatOnly)
    {
        this(out, newFormatOnly ? PacketFormat.CURRENT : PacketFormat.ROUNDTRIP);
    }

    public BCPGOutputStream(
            OutputStream out,
            PacketFormat packetFormat)
    {
        this.out = out;
        this.packetFormat = packetFormat;
    }

    /**
     * Create a stream representing an old style partial object.
     *
     * @param tag the packet tag for the object.
     */
    public BCPGOutputStream(
        OutputStream out,
        int tag)
        throws IOException
    {
        this.out = out;
        this.packetFormat = PacketFormat.LEGACY;
        this.writeHeader(tag, true, true, 0);
    }

    /**
     * Create a stream representing a general packet.
     *
     * @param out
     * @param tag
     * @param length
     * @param oldFormat
     * @throws IOException
     */
    public BCPGOutputStream(
        OutputStream out,
        int tag,
        long length,
        boolean oldFormat)
        throws IOException
    {
        this.out = out;
        this.packetFormat = oldFormat ? PacketFormat.LEGACY : PacketFormat.CURRENT;

        if (length > 0xFFFFFFFFL)
        {
            this.writeHeader(tag, false, true, 0);
            this.partialBufferLength = 1 << BUF_SIZE_POWER;
            this.partialBuffer = new byte[partialBufferLength];
            this.partialPower = BUF_SIZE_POWER;
            this.partialOffset = 0;
        }
        else
        {
            this.writeHeader(tag, oldFormat, false, length);
        }
    }

    /**
     * @param tag
     * @param length
     * @throws IOException
     */
    public BCPGOutputStream(
        OutputStream out,
        int tag,
        long length)
        throws IOException
    {
        this.out = out;
        this.packetFormat = PacketFormat.CURRENT;

        this.writeHeader(tag, false, false, length);
    }

    /**
     * Create a new style partial input stream buffered into chunks.
     *
     * @param out    output stream to write to.
     * @param tag    packet tag.
     * @param buffer size of chunks making up the packet.
     * @throws IOException
     */
    public BCPGOutputStream(
        OutputStream out,
        int tag,
        byte[] buffer)
        throws IOException
    {
        this.out = out;
        this.packetFormat = PacketFormat.CURRENT;
        this.writeHeader(tag, false, true, 0);

        this.partialBuffer = buffer;

        int length = partialBuffer.length;

        for (partialPower = 0; length != 1; partialPower++)
        {
            length >>>= 1;
        }

        if (partialPower > 30)
        {
            throw new IOException("Buffer cannot be greater than 2^30 in length.");
        }

        this.partialBufferLength = 1 << partialPower;
        this.partialOffset = 0;
    }

    private void writeHeader(
        int tag,
        boolean oldPackets,
        boolean partial,
        long bodyLen)
        throws IOException
    {
        int hdr = 0x80;

        if (partialBuffer != null)
        {
            partialFlush(true);
            partialBuffer = null;
        }

        // only tags <= 0xF in value can be written as old packets.
        if (tag <= 0xF && oldPackets)
        {
            hdr |= tag << 2;

            if (partial)
            {
                this.write(hdr | 0x03);
            }
            else
            {
                if (bodyLen <= 0xff)
                {
                    this.write(hdr);
                    this.write((byte)bodyLen);
                }
                else if (bodyLen <= 0xffff)
                {
                    this.write(hdr | 0x01);
                    this.write((byte)(bodyLen >> 8));
                    this.write((byte)(bodyLen));
                }
                else
                {
                    this.write(hdr | 0x02);
                    StreamUtil.writeBodyLen(this, bodyLen);
                }
            }
        }
        else
        {
            hdr |= 0x40 | tag;
            this.write(hdr);

            if (partial)
            {
                partialOffset = 0;
            }
            else
            {
                StreamUtil.writeNewPacketLength(out, bodyLen);
            }
        }
    }

    private void partialFlush(
        boolean isLast)
        throws IOException
    {
        if (isLast)
        {
            StreamUtil.writeNewPacketLength(out, partialOffset);
            out.write(partialBuffer, 0, partialOffset);
        }
        else
        {
            out.write(0xE0 | partialPower);
            out.write(partialBuffer, 0, partialBufferLength);
        }

        partialOffset = 0;
    }

    private void writePartial(
        byte b)
        throws IOException
    {
        if (partialOffset == partialBufferLength)
        {
            partialFlush(false);
        }

        partialBuffer[partialOffset++] = b;
    }

    private void writePartial(
        byte[] buf,
        int off,
        int len)
        throws IOException
    {
        if (partialOffset == partialBufferLength)
        {
            partialFlush(false);
        }

        if (len <= (partialBufferLength - partialOffset))
        {
            System.arraycopy(buf, off, partialBuffer, partialOffset, len);
        }
        else
        {
            System.arraycopy(buf, off, partialBuffer, partialOffset, partialBufferLength - partialOffset);
            off += partialBufferLength - partialOffset;
            len -= partialBufferLength - partialOffset;
            partialFlush(false);

            while (len > partialBufferLength)
            {
                System.arraycopy(buf, off, partialBuffer, 0, partialBufferLength);
                off += partialBufferLength;
                len -= partialBufferLength;
                partialFlush(false);
            }

            System.arraycopy(buf, off, partialBuffer, 0, len);
        }
        partialOffset += len;
    }

    public void write(
        int b)
        throws IOException
    {
        if (partialBuffer != null)
        {
            writePartial((byte)b);
        }
        else
        {
            out.write(b);
        }
    }

    public void write(
        byte[] bytes,
        int off,
        int len)
        throws IOException
    {
        if (partialBuffer != null)
        {
            writePartial(bytes, off, len);
        }
        else
        {
            out.write(bytes, off, len);
        }
    }

    /**
     * Write a packet to the stream.
     * @param p packet
     * @throws IOException
     */
    public void writePacket(
        ContainedPacket p)
        throws IOException
    {
        p.encode(this);
    }

    /**
     * Write a packet to the stream.
     * The packet will use the old encoding format if {@link #packetFormat} is {@link PacketFormat#LEGACY}, otherwise
     * it will be encoded using the new packet format.
     * @param tag packet tag
     * @param body packet body
     * @throws IOException
     */
    void writePacket(
        int tag,
        byte[] body)
        throws IOException
    {
        this.writeHeader(tag, packetFormat == PacketFormat.LEGACY, false, body.length);
        this.write(body);
    }

    /**
     * Write a packet.
     * The packet format will be chosen primarily based on {@link #packetFormat}.
     * If {@link #packetFormat} is {@link PacketFormat#CURRENT}, the packet will be encoded using the new format.
     * If it is {@link PacketFormat#LEGACY}, the packet will use old encoding format.
     * If it is {@link PacketFormat#ROUNDTRIP}, then the format will be determined by objectPrefersNewPacketFormat.
     *
     * @param objectPrefersNewPacketFormat whether the packet prefers to be encoded using the new packet format
     * @param tag packet tag
     * @param body packet body
     * @throws IOException
     */
    void writePacket(
            boolean objectPrefersNewPacketFormat,
            int tag,
            byte[] body)
            throws IOException
    {
        boolean oldPacketFormat = packetFormat == PacketFormat.LEGACY ||
                (packetFormat == PacketFormat.ROUNDTRIP && !objectPrefersNewPacketFormat);
        this.writeHeader(tag, oldPacketFormat, false, body.length);
        this.write(body);
    }

    /**
     * Write a packet, forcing the packet format to be either old or new.
     * @param tag packet tag
     * @param body packet body
     * @param oldFormat if true, old format is forced, else force new format
     * @throws IOException
     */
    void writePacket(
        int tag,
        byte[] body,
        boolean oldFormat)
        throws IOException
    {
        this.writeHeader(tag, oldFormat, false, body.length);
        this.write(body);
    }

    public void writeObject(
        BCPGObject o)
        throws IOException
    {
        o.encode(this);
    }

    /**
     * Flush the underlying stream.
     */
    public void flush()
        throws IOException
    {
        out.flush();
    }

    /**
     * Finish writing out the current packet without closing the underlying stream.
     */
    public void finish()
        throws IOException
    {
        if (partialBuffer != null)
        {
            partialFlush(true);
            Arrays.fill(partialBuffer, (byte)0);
            partialBuffer = null;
        }
    }

    public void close()
        throws IOException
    {
        this.finish();
        out.flush();
        out.close();
    }

}
