package org.bouncycastle.bcpg;

import java.io.IOException;

/**
 * Key class for unknown/unsupported OpenPGP key types.
 */
public class UnknownBCPGKey
        extends OctetArrayBCPGKey
{
    public UnknownBCPGKey(int length, BCPGInputStream in)
            throws IOException
    {
        super(length, in);
    }

    public UnknownBCPGKey(int length, byte[] key)
    {
        super(length, key);
    }
}
