package org.bouncycastle.bcpg;

import java.io.IOException;

public class Ed448PublicBCPGKey
        extends OctetArrayBCPGKey
{
    public static final int LENGTH = 57;

    public Ed448PublicBCPGKey(BCPGInputStream in)
            throws IOException
    {
        super(LENGTH, in);
    }

    public Ed448PublicBCPGKey(byte[] key)
    {
        super(LENGTH, key);
    }

}
