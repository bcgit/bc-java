package org.bouncycastle.bcpg;

import org.bouncycastle.util.Arrays;

import java.io.IOException;

/**
 * SecretBCPGKey which is encoded as an array of octets rather than an MPI.
 */
public abstract class OctetArraySecretBCPGKey
        extends BCPGObject
        implements BCPGKey
{

    private final byte[] key;

    OctetArraySecretBCPGKey(int length, BCPGInputStream in)
        throws IOException
    {
        this.key = new byte[length];
        in.readFully(key);
    }

    OctetArraySecretBCPGKey(int length, byte[] key)
    {
        if (key.length != length)
        {
            throw new IllegalArgumentException("Unexpected key encoding length. Expected " + length + " bytes, got " + key.length);
        }
        this.key = new byte[length];
        System.arraycopy(key, 0, this.key, 0, length);
    }

    @Override
    public String getFormat()
    {
        return "PGP";
    }

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
