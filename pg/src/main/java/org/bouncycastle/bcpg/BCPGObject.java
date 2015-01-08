package org.bouncycastle.bcpg;

import java.io.IOException;

/**
 * Base class for a PGP object.
 */
public abstract class BCPGObject implements Encodeable
{
    public byte[] getEncoded()
        throws IOException
    {
        return BCPGUtil.getEncoded(this);
    }
 
}
