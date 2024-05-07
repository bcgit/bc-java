package org.bouncycastle.bcpg;

public class ReservedPacket
    extends InputStreamPacket
{
    public ReservedPacket(BCPGInputStream in)
    {
        this(in, false);
    }

    public ReservedPacket(BCPGInputStream in, boolean newPacketFormat)
    {
        super(in, RESERVED, newPacketFormat);
    }
}
