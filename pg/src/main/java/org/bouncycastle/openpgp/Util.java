package org.bouncycastle.openpgp;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.List;

import org.bouncycastle.bcpg.BCPGInputStream;

class Util
{
    static BCPGInputStream createBCPGInputStream(InputStream pgIn, int tag1)
        throws IOException
    {
        BCPGInputStream bcIn = BCPGInputStream.wrap(pgIn);
        int nextTag = bcIn.nextPacketTag();

        if (nextTag == tag1)
        {
            return bcIn;
        }

        throw new IOException("unexpected tag " + nextTag + " encountered");
    }

    static BCPGInputStream createBCPGInputStream(InputStream pgIn, int tag1, int tag2)
        throws IOException
    {
        BCPGInputStream bcIn = BCPGInputStream.wrap(pgIn);
        int nextTag = bcIn.nextPacketTag();

        if (nextTag == tag1 || nextTag == tag2)
        {
            return bcIn;
        }

        throw new IOException("unexpected tag " + nextTag + " encountered");
    }

    static void encodePGPSignatures(OutputStream stream, List<PGPSignature> sigs, boolean forTransfer)
        throws IOException
    {
        for (int i = 0; i != sigs.size(); i++)
        {
            ((PGPSignature)sigs.get(i)).encode(stream, forTransfer);
        }
    }
}
