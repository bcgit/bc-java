package org.bouncycastle.bcpg;

/**
 * A block of data associated with other packets in a PGP object stream.
 */
public class InputStreamPacket
    extends Packet
{
    private BCPGInputStream        in;

    // it's unlikely this is being used, but just in case we'll mark
    // unknown inputs as reserved.
    public InputStreamPacket(
        BCPGInputStream  in)
    {
        super(RESERVED);

        this.in = in;
    }

    InputStreamPacket(
        BCPGInputStream  in,
        int packetTag)
    {
        this(in, packetTag, false);
    }

    InputStreamPacket(
            BCPGInputStream in,
            int packetTag,
            boolean newPacketFormat)
    {
        super(packetTag, newPacketFormat);
        this.in = in;
    }

    /**
     * Obtains an input stream to read the contents of the packet.
     *
     * @return the data in this packet.
     */
    public BCPGInputStream getInputStream()
    {
        return in;
    }
}
