package org.bouncycastle.bcpg;

/**
 * A block of data associated with other packets in a PGP object stream.
 */
public class InputStreamPacket
    extends Packet
{
    private BCPGInputStream        in;

    public InputStreamPacket(
        BCPGInputStream  in)
    {
        this.in = in;
    }

    /**
     * Obtains an input stream to read the contents of the packet.
     * <p>
     * Note: you can only read from this once...
     * </p>
     * @return the data in this packet.
     */
    public BCPGInputStream getInputStream()
    {
        return in;
    }
}
