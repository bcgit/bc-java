package org.bouncycastle.bcpg;

import java.io.IOException;

public class X448SecretBCPGKey
    extends OctetArrayBCPGKey
{
    public static final int LENGTH = 56;

    public X448SecretBCPGKey(BCPGInputStream in)
            throws IOException
    {
        super(LENGTH, in);
    }

    public X448SecretBCPGKey(byte[] key)
    {
        super(LENGTH, key);
    }
}
