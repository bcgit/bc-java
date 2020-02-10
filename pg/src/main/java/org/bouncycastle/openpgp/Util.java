package org.bouncycastle.openpgp;

import java.io.IOException;
import java.io.InputStream;

import org.bouncycastle.bcpg.BCPGInputStream;

class Util
{
    static BCPGInputStream createBCPGInputStream(InputStream pgIn, int tag1)
        throws IOException
    {
        BCPGInputStream bcIn = new BCPGInputStream(pgIn);

        if (bcIn.nextPacketTag() == tag1)
        {
            return bcIn;
        }

        throw new IOException("unexpected tag " + bcIn.nextPacketTag() + " encountered");
    }

    static BCPGInputStream createBCPGInputStream(InputStream pgIn, int tag1, int tag2)
        throws IOException
    {
        BCPGInputStream bcIn = new BCPGInputStream(pgIn);

        if (bcIn.nextPacketTag() == tag1 || bcIn.nextPacketTag() == tag2)
        {
            return bcIn;
        }

        throw new IOException("unexpected tag " + bcIn.nextPacketTag() + " encountered");
    }
}
