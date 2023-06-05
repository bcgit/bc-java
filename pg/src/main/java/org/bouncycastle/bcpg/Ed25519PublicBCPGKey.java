package org.bouncycastle.bcpg;

import java.io.IOException;

public class Ed25519PublicBCPGKey
        extends OctetArrayBCPGKey
{
    public static final int LENGTH = 32;

    public Ed25519PublicBCPGKey(BCPGInputStream in)
            throws IOException
    {
        super(LENGTH, in);
    }

    public Ed25519PublicBCPGKey(byte[] key)
    {
        super(LENGTH, key);
    }
}
