package org.bouncycastle.bcpg;

import org.bouncycastle.util.Arrays;

import java.io.IOException;

public class X448PublicBCPGKey
        extends BCPGObject
        implements BCPGKey
{
    public static final int LENGTH = 56;
    private final byte[] key;

    public X448PublicBCPGKey(BCPGInputStream in)
            throws IOException
    {
        key = new byte[LENGTH];
        in.readFully(key);
    }

    public X448PublicBCPGKey(byte[] key) {
        if (key.length != LENGTH)
        {
            throw new IllegalArgumentException("Unexpected key encoding length. Expected " + LENGTH + " bytes, got " + key.length);
        }
        this.key = new byte[LENGTH];
        System.arraycopy(key, 0, this.key, 0, LENGTH);
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
