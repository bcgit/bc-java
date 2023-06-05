package org.bouncycastle.bcpg;

import java.io.IOException;

import org.bouncycastle.util.Arrays;

/**
 * Public/Secret BCPGKey which is encoded as an array of octets rather than an MPI.
 */
public abstract class OctetArrayBCPGKey
    extends BCPGObject
    implements BCPGKey
{
    private final byte[] key;

    OctetArrayBCPGKey(int length, BCPGInputStream in)
        throws IOException
    {
        key = new byte[length];
        in.readFully(key);
    }

    OctetArrayBCPGKey(int length, byte[] key)
    {
        if (key.length != length)
        {
            throw new IllegalArgumentException("unexpected key encoding length: expected " + length + " bytes, got " + key.length);
        }
        this.key = new byte[length];
        System.arraycopy(key, 0, this.key, 0, length);
    }

    /**
     * return the standard PGP encoding of the key.
     *
     * @see org.bouncycastle.bcpg.BCPGKey#getEncoded()
     */
    @Override
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

    @Override
    public String getFormat()
    {
        return "PGP";
    }

    @Override
    public void encode(BCPGOutputStream out)
        throws IOException
    {
        out.write(key);
    }

    public byte[] getKey()
    {
        return Arrays.clone(key);
    }
}
