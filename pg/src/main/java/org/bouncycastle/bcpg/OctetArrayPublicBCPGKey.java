package org.bouncycastle.bcpg;

import org.bouncycastle.util.Arrays;

import java.io.IOException;

/**
 * PublicBCPGKey which is encoded as an array of octets rather than an MPI.
 */
public abstract class OctetArrayPublicBCPGKey
        extends BCPGObject
        implements BCPGKey
{

    private final byte[] key;

    OctetArrayPublicBCPGKey(int length, BCPGInputStream in)
            throws IOException
    {
        key = new byte[length];
        in.readFully(key);
    }

    OctetArrayPublicBCPGKey(int length, byte[] key)
    {
        if (key.length != length)
        {
            throw new IllegalArgumentException("Unexpected key encoding length. Expected " + length + " bytes, got " + key.length);
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
    public String getFormat() {
        return "PGP";
    }

    @Override
    public void encode(BCPGOutputStream out) throws IOException {
        out.write(key);
    }

    public byte[] getKey() {
        return Arrays.clone(key);
    }
}
