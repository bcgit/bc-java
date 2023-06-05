package org.bouncycastle.bcpg;

import java.io.IOException;

public class X448PublicBCPGKey
        extends OctetArrayBCPGKey
{
    public static final int LENGTH = 56;

    public X448PublicBCPGKey(BCPGInputStream in)
            throws IOException
    {
        super(LENGTH, in);
    }

    public X448PublicBCPGKey(byte[] key)
    {
        super(LENGTH, key);
    }
}
