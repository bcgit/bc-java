package org.bouncycastle.bcpg;

import java.io.IOException;
import java.io.OutputStream;

import org.bouncycastle.util.Arrays;

/**
 * Basic type for a user attribute sub-packet.
 */
public class UserAttributeSubpacket 
{
    int                type;
    private boolean    forceLongLength;   // we preserve this as not everyone encodes length properly.
    protected byte[]   data;
    
    protected UserAttributeSubpacket(
        int            type,
        byte[]         data)
    {    
        this(type, false, data);
    }

    protected UserAttributeSubpacket(
        int            type,
        boolean        forceLongLength,
        byte[]         data)
    {
        this.type = type;
        this.forceLongLength = forceLongLength;
        this.data = data;
    }
    
    public int getType()
    {
        return type;
    }
    
    /**
     * return the generic data making up the packet.
     */
    public byte[] getData()
    {
        return data;
    }

    public void encode(
        OutputStream    out)
        throws IOException
    {
        int    bodyLen = data.length + 1;

        if (bodyLen < 192 && !forceLongLength)
        {
            out.write((byte)bodyLen);
        }
        else if (bodyLen <= 8383 && !forceLongLength)
        {
            bodyLen -= 192;

            out.write((byte)(((bodyLen >> 8) & 0xff) + 192));
            out.write((byte)bodyLen);
        }
        else
        {
            out.write(0xff);
            StreamUtil.writeBodyLen(out, bodyLen);
        }

        out.write(type);        
        out.write(data);
    }

    public boolean equals(
        Object o)
    {
        if (o == this)
        {
            return true;
        }

        if (!(o instanceof UserAttributeSubpacket))
        {
            return false;
        }

        UserAttributeSubpacket other = (UserAttributeSubpacket)o;

        return this.type == other.type
            && Arrays.areEqual(this.data, other.data);
    }

    public int hashCode()
    {
        return type ^ Arrays.hashCode(data);
    }
}
