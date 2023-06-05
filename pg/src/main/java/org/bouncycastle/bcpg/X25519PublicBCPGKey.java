package org.bouncycastle.bcpg;

import java.io.IOException;

public class X25519PublicBCPGKey
        extends OctetArrayBCPGKey
{
    public static final int LENGTH = 32;

    public X25519PublicBCPGKey(BCPGInputStream in)
            throws IOException
    {
        super(LENGTH, in);
    }

    public X25519PublicBCPGKey(byte[] key)
    {
        super(LENGTH, key);
    }
}
