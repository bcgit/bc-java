package org.bouncycastle.bcpg;

import java.io.IOException;

/**
 * Basic type for a symmetric key encrypted packet
 */
public class SymmetricEncDataPacket 
    extends InputStreamPacket
    implements BCPGHeaderObject
{
    public SymmetricEncDataPacket(
            BCPGInputStream  in)
    {
        this(in, false);
    }

    public SymmetricEncDataPacket(
        BCPGInputStream  in,
        boolean newPacketFormat)
    {
        super(in, SYMMETRIC_KEY_ENC, newPacketFormat);
    }

    public SymmetricEncDataPacket()
    {
        super(null, SYMMETRIC_KEY_ENC);
    }

    @Override
    public int getType()
    {
        return SYMMETRIC_KEY_ENC;
    }

    @Override
    public void encode(BCPGOutputStream bcpgOut)
        throws IOException
    {
         // nothing to add
    }
}
