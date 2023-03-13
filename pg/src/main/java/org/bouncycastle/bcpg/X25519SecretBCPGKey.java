package org.bouncycastle.bcpg;

import java.io.IOException;

public class X25519SecretBCPGKey
        extends BCPGObject
        implements BCPGKey
{
    public static final int LENGTH = 32;
    private final byte[] key;

    public X25519SecretBCPGKey(BCPGInputStream in) throws IOException {
        this.key = new byte[LENGTH];
        in.readFully(key);
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
