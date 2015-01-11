package org.bouncycastle.bcpg;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

import org.bouncycastle.util.Encodable;

/**
 * Base class for a PGP object.
 */
public abstract class BCPGObject
    implements Encodable
{
    public byte[] getEncoded()
        throws IOException
    {
        ByteArrayOutputStream    bOut = new ByteArrayOutputStream();
        BCPGOutputStream         pOut = new BCPGOutputStream(bOut);

        pOut.writeObject(this);

        pOut.close();

        return bOut.toByteArray();
    }

    public abstract void encode(BCPGOutputStream out)
        throws IOException;
}
