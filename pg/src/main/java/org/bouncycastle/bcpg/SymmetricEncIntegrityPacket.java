package org.bouncycastle.bcpg;

import java.io.IOException;

/**
 * A symmetric key encrypted packet with an associated integrity check code.
 */
public class SymmetricEncIntegrityPacket
    extends InputStreamPacket
    implements BCPGHeaderObject
{
    int        version;

    SymmetricEncIntegrityPacket(
        BCPGInputStream    in)
        throws IOException
    {
        super(in);

        version = in.read();
    }

    public SymmetricEncIntegrityPacket()
    {
        super(null);

        version = 1;
    }

    public int getVersion()
    {
        return version;
    }

    @Override
    public int getType()
    {
        return SYM_ENC_INTEGRITY_PRO;
    }

    @Override
    public void encode(BCPGOutputStream bcpgOut)
        throws IOException
    {
        bcpgOut.write(getVersion());
    }
}
