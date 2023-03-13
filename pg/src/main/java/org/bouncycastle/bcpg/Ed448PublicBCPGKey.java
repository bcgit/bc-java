package org.bouncycastle.bcpg;

import org.bouncycastle.util.Arrays;

import java.io.IOException;

public class Ed448PublicBCPGKey
        extends BCPGObject
        implements BCPGKey
{
    public static final int LENGTH = 56;
    private final byte[] key;

    public Ed448PublicBCPGKey(BCPGInputStream in)
            throws IOException
    {
        key = new byte[LENGTH];
        in.readFully(key);
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
