package org.bouncycastle.bcpg;

import java.io.IOException;

public class X25519SecretBCPGKey
    extends OctetArrayBCPGKey
{
    public static final int LENGTH = 32;

    public X25519SecretBCPGKey(BCPGInputStream in)
            throws IOException
    {
        super(LENGTH, in);
    }

    public X25519SecretBCPGKey(byte[] key)
    {
        super(LENGTH, key);
    }
}
