package org.bouncycastle.bcpg;

import java.io.IOException;
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
        int       length = StreamUtil.read2OctetLength(in);
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
        StreamUtil.write2OctetLength(out, value.bitLength());

        byte[]    bytes = value.toByteArray();
        
        if (bytes[0] == 0)
        {
            out.write(bytes, 1, bytes.length - 1);
        }
        else
        {
            out.write(bytes, 0, bytes.length);
        }
    }
}
