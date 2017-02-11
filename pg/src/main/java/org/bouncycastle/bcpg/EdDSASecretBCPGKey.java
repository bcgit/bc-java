package org.bouncycastle.bcpg;

import java.io.IOException;
import java.math.BigInteger;

import org.bouncycastle.util.BigIntegers;


/**
 * base class for an EC Secret Key.
 */
public class EdDSASecretBCPGKey
    extends BCPGObject
    implements BCPGKey
{
    MPInteger x;

    /**
     * @param in
     * @throws IOException
     */
    public EdDSASecretBCPGKey(
        BCPGInputStream in)
        throws IOException
    {
        this.x = new MPInteger(in);
    }

    /**
     * @param x
     */
    public EdDSASecretBCPGKey(
        BigInteger x)
    {
        this.x = new MPInteger(x);
    }

    /**
     * @param seed
     */
    public EdDSASecretBCPGKey(
            byte[] seed)
    {
        BigInteger x = BigIntegers.fromUnsignedByteArray(seed);
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

    public byte[] getSeed()
    {
        return BigIntegers.asUnsignedByteArray(x.getValue());
    }
}
