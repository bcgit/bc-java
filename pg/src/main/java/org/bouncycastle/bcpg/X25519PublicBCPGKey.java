package org.bouncycastle.bcpg;

import org.bouncycastle.util.Arrays;

import java.io.IOException;

public class X25519PublicBCPGKey
        extends BCPGObject
        implements BCPGKey
{
    public static final int LENGTH = 32;
    byte[] key;

    public X25519PublicBCPGKey(BCPGInputStream in) throws IOException {
        key = new byte[LENGTH];
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
    public void encode(BCPGOutputStream out) throws IOException {
        out.write(key);
    }

    public byte[] getKey() {
        return Arrays.clone(key);
    }
}
