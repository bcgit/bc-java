package org.bouncycastle.bcpg;

import java.io.IOException;
import java.math.BigInteger;

/**
 * base class for a DSA Secret Key.
 */
public class DSASecretBCPGKey 
    extends BCPGObject implements BCPGKey 
{
    MPInteger    x;
    
    /**
     * 
     * @param in
     * @throws IOException
     */
    public DSASecretBCPGKey(
        BCPGInputStream    in)
        throws IOException
    {
        this.x = new MPInteger(in);
    }

    /**
     * 
     * @param x
     */
    public DSASecretBCPGKey(
        BigInteger    x)
    {
        this.x = new MPInteger(x);
    }
    
    /**
     *  return "PGP"
     * 
     * @see org.bouncycastle.bcpg.BCPGKey#getFormat()
     */
    public String getFormat() 
    {
        return "PGP";
    }

    /**
     * return the standard PGP encoding of the key.
     * 
     * @see org.bouncycastle.bcpg.BCPGKey#getEncoded()
     */
    public byte[] getEncoded() 
    {
        try
        {
            return super.getEncoded();
        }
        catch (IOException e)
        {
            return null;
        }
    }
    
    public void encode(
        BCPGOutputStream    out)
        throws IOException
    {
        out.writeObject(x);
    }
    
    /**
     * @return x
     */
    public BigInteger getX()
    {
        return x.getValue();
    }
}
