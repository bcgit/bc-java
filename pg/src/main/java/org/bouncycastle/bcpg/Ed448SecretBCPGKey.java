package org.bouncycastle.bcpg;

import java.io.IOException;

public class Ed448SecretBCPGKey
        extends OctetArraySecretBCPGKey
{
    public static final int LENGTH = 57;

    public Ed448SecretBCPGKey(BCPGInputStream in)
            throws IOException
    {
        super(LENGTH, in);
    }

    public Ed448SecretBCPGKey(byte[] key)
    {
        super(LENGTH, key);
    }
}
