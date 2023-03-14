package org.bouncycastle.bcpg;

import java.io.IOException;

public class X448SecretBCPGKey
        extends BCPGObject
        implements BCPGKey
{
    public static final int LENGTH = 56;
    private final byte[] key;

    public X448SecretBCPGKey(BCPGInputStream in) throws IOException {
        this.key = new byte[LENGTH];
        in.readFully(key);
    }

    public X448SecretBCPGKey(byte[] key) {
        if (key.length != LENGTH)
        {
            throw new IllegalArgumentException("Unexpected key encoding length. Expected " + LENGTH + " bytes, got " + key.length);
        }
        this.key = new byte[LENGTH];
        System.arraycopy(key, 0, this.key, 0, LENGTH);
    }

    @Override
    public String getFormat() {
        return "PGP";
    }

    @Override
    public byte[] getEncoded() {
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
}
