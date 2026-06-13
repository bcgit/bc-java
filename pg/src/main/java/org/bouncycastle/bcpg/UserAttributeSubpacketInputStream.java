package org.bouncycastle.bcpg;

import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;

import org.bouncycastle.bcpg.attr.ImageAttribute;

/**
 * reader for user attribute sub-packets
 */
public class UserAttributeSubpacketInputStream
    extends InputStream
    implements UserAttributeSubpacketTags
{
    /**
     * Hard upper bound on a single user-attribute subpacket body. This is an absolute cap applied
     * independently of {@link StreamUtil#findLimit(InputStream)}, which for the non-seekable
     * streams used during packet parsing returns close to the JVM heap size and so does not bound
     * the per-packet allocation. Without it a crafted 4-octet length header could force a
     * multi-gigabyte {@code new byte[]} before any body bytes are read. 2 MiB matches the ceiling
     * used for signature subpackets ({@link SignaturePacket#MAX_SUBPACKET_LEN}) and public-key
     * packets ({@link PublicKeyPacket#MAX_LEN}); user-attribute (image) subpackets are not
     * expected to approach it.
     */
    public static final int MAX_SUBPACKET_LEN = 2 * 1024 * 1024;

    InputStream in;
    private final int limit;

    public UserAttributeSubpacketInputStream(
        InputStream in)
    {
        this(in, StreamUtil.findLimit(in));
    }

    public UserAttributeSubpacketInputStream(
        InputStream in,
        int limit)
    {
        this.in = in;
        this.limit = limit;
    }

    public int available()
        throws IOException
    {
        return in.available();
    }

    public int read()
        throws IOException
    {
        return in.read();
    }

    private void readFully(
        byte[] buf,
        int off,
        int len)
        throws IOException
    {
        if (len > 0)
        {
            int b = this.read();

            if (b < 0)
            {
                throw new EOFException();
            }

            buf[off] = (byte)b;
            off++;
            len--;
        }

        while (len > 0)
        {
            int l = in.read(buf, off, len);

            if (l < 0)
            {
                throw new EOFException();
            }

            off += l;
            len -= l;
        }
    }

    public UserAttributeSubpacket readPacket()
        throws IOException
    {
        boolean[] flags = new boolean[3];
        int bodyLen = StreamUtil.readBodyLen(this, flags);
        if (flags[StreamUtil.flag_eof])
        {
            return null;
        }
        else if (flags[StreamUtil.flag_partial])
        {
            throw new MalformedPacketException("unrecognised length reading user attribute sub packet");
        }
        if (bodyLen < 1)
        {
            throw new MalformedPacketException("Body length octet too small.");
        }
        if (bodyLen > limit)
        {
            throw new MalformedPacketException("Body length octet (" + bodyLen + ") exceeds limitations (" + limit + ").");
        }
        // Absolute cap, independent of the findLimit() hint above (which is ~heap-sized for the
        // BCPGInputStream used during parsing), so a crafted length cannot drive a huge allocation.
        if (bodyLen > MAX_SUBPACKET_LEN)
        {
            throw new MalformedPacketException("Body length octet (" + bodyLen + ") exceeds max user attribute subpacket length (" + MAX_SUBPACKET_LEN + ").");
        }
        boolean longLength = flags[StreamUtil.flag_isLongLength];

        int tag = in.read();

        if (tag < 0)
        {
            throw new EOFException("unexpected EOF reading user attribute sub packet");
        }

        byte[] data = new byte[bodyLen - 1];

        this.readFully(data, 0, data.length);

        int type = tag;

        try
        {
            switch (type)
            {
            case IMAGE_ATTRIBUTE:
                return new ImageAttribute(longLength, data);
            }
        }
        catch (IllegalArgumentException e)
        {
            throw new MalformedPacketException("Malformed UserAttribute subpacket.", e);
        }

        return new UserAttributeSubpacket(type, longLength, data);
    }
}
