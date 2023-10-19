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
        super(in, SYMMETRIC_KEY_ENC);
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
