package org.bouncycastle.bcpg;

import java.io.*;
import java.math.BigInteger;

/**
 * a multiple precision integer
 */
public class MPInteger 
    extends BCPGObject
{
    BigInteger    value = null;
    
    public MPInteger(
        BCPGInputStream    in)
        throws IOException
    {
        int       length = (in.read() << 8) | in.read();
        byte[]    bytes = new byte[(length + 7) / 8];
        
        in.readFully(bytes);
        
        value = new BigInteger(1, bytes);
    }
    
    public MPInteger(
        BigInteger    value)
    {
        if (value == null || value.signum() < 0)
        {
            throw new IllegalArgumentException("value must not be null, or negative");
        }

        this.value = value;
    }
    
    public BigInteger getValue()
    {
        return value;
    }
    
    public void encode(
        BCPGOutputStream    out)
        throws IOException
    {
        int length = value.bitLength();
        
        out.write(length >> 8);
        out.write(length);
        
        byte[]    bytes = value.toByteArray();
        
        int off = 0;
        
        while (off < bytes.length && bytes[off] == 0) {
            off += 1;
        }
        
        out.write(bytes, off, bytes.length - off);
    }
}
