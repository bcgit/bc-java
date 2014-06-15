package org.bouncycastle.bcpg;

import java.io.IOException;

/**
 * A symmetric key encrypted packet with an associated integrity check code.
 */
public class SymmetricEncIntegrityPacket
    extends InputStreamPacket
{
    int        version;

    SymmetricEncIntegrityPacket(
        BCPGInputStream    in)
        throws IOException
    {
        super(in);

        version = in.read();
    }
}
