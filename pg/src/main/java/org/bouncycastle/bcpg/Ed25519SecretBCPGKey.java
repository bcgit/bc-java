package org.bouncycastle.bcpg;

import java.io.IOException;

public class Ed25519SecretBCPGKey
    extends OctetArrayBCPGKey
{
    public static final int LENGTH = 32;

    public Ed25519SecretBCPGKey(BCPGInputStream in)
            throws IOException
    {
        super(LENGTH, in);
    }

    public Ed25519SecretBCPGKey(byte[] key)
    {
        super(LENGTH, key);
    }
}
