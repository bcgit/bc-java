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
    InputStream in;

    public UserAttributeSubpacketInputStream(
        InputStream in)
    {
        this.in = in;
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
            throw new IOException("unrecognised length reading user attribute sub packet");
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

        switch (type)
        {
        case IMAGE_ATTRIBUTE:
            return new ImageAttribute(longLength, data);
        }

        return new UserAttributeSubpacket(type, longLength, data);
    }
}
