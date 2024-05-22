package org.bouncycastle.bcpg;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

import org.bouncycastle.util.Encodable;

/**
 * Basic type for a PGP packet.
 */
public abstract class ContainedPacket
    extends Packet
    implements Encodable
{

    ContainedPacket(int packetTag)
    {
        this(packetTag, false);
    }

    ContainedPacket(int packetTag, boolean newPacketFormat)
    {
        super(packetTag, newPacketFormat);
    }

    public byte[] getEncoded()
        throws IOException
    {
        return getEncoded(PacketFormat.ROUNDTRIP);
    }

    public byte[] getEncoded(PacketFormat format)
            throws IOException
    {
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        BCPGOutputStream pOut = new BCPGOutputStream(bOut, format);
        pOut.writePacket(this);
        pOut.close();
        return bOut.toByteArray();
    }
    
    public abstract void encode(
        BCPGOutputStream    pOut)
        throws IOException;
}
