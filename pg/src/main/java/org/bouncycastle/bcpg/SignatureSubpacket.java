package org.bouncycastle.bcpg;

import java.io.IOException;
import java.io.OutputStream;

import org.bouncycastle.util.Arrays;

/**
 * Basic type for a PGP Signature sub-packet.
 */
public class SignatureSubpacket 
{
    int               type;
    boolean           critical;
    boolean           isLongLength;
    protected byte[]  data;

    protected SignatureSubpacket(
        int           type,
        boolean       critical,
        boolean       isLongLength,
        byte[]        data)
    {    
        this.type = type;
        this.critical = critical;
        this.isLongLength = isLongLength;
        this.data = data;
    }
    
    public int getType()
    {
        return type;
    }
    
    public boolean isCritical()
    {
        return critical;
    }

    public boolean isLongLength()
    {
        return isLongLength;
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

        if (isLongLength)
        {
            out.write(0xff);
            out.write((byte)(bodyLen >> 24));
            out.write((byte)(bodyLen >> 16));
            out.write((byte)(bodyLen >> 8));
            out.write((byte)bodyLen);
        }
        else
        {
            if (bodyLen < 192)
            {
                out.write((byte)bodyLen);
            }
            else if (bodyLen <= 8383)
            {
                bodyLen -= 192;

                out.write((byte)(((bodyLen >> 8) & 0xff) + 192));
                out.write((byte)bodyLen);
            }
            else
            {
                out.write(0xff);
                out.write((byte)(bodyLen >> 24));
                out.write((byte)(bodyLen >> 16));
                out.write((byte)(bodyLen >> 8));
                out.write((byte)bodyLen);
            }
        }
        
        if (critical)
        {
            out.write(0x80 | type);
        }
        else
        {
            out.write(type);
        }
        
        out.write(data);
    }

    public int hashCode()
    {
        return (this.critical ? 1 : 0) + 7 * this.type + 49 * Arrays.hashCode(data);
    }

    public boolean equals(Object other)
    {
        if (other == this)
        {
            return true;
        }

        if (other instanceof SignatureSubpacket)
        {
             SignatureSubpacket ot = (SignatureSubpacket)other;

             if (this.type == ot.type && this.critical == ot.critical)
             {
                 return Arrays.areEqual(this.data, ot.data);
             }
        }

        return false;
    }
}
