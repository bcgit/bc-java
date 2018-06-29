package org.bouncycastle.bcpg;

import java.io.IOException;
import java.math.BigInteger;

/**
 * base class for an Edwards Curve Secret Key.
 */
public class EdSecretBCPGKey
    extends BCPGObject
    implements BCPGKey
{
    MPInteger x;

    /**
     * @param in
     * @throws IOException
     */
    public EdSecretBCPGKey(
        BCPGInputStream in)
        throws IOException
    {
        this.x = new MPInteger(in);
    }

    /**
     * @param x
     */
    public EdSecretBCPGKey(
        BigInteger x)
    {
        this.x = new MPInteger(x);
    }

    /**
     * return "PGP"
     *
     * @see BCPGKey#getFormat()
     */
    public String getFormat()
    {
        return "PGP";
    }

    /**
     * return the standard PGP encoding of the key.
     *
     * @see BCPGKey#getEncoded()
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
        BCPGOutputStream out)
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
