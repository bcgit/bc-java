package org.bouncycastle.bcpg;

import java.io.BufferedInputStream;

/**
 * A block of data associated with other packets in a PGP object stream.
 */
public class InputStreamPacket
    extends Packet
{
    private BufferedInputStream        in;

    public InputStreamPacket(
        BCPGInputStream  in)
    {
        this.in = new BufferedInputStream(in);
    }

    /**
     * Obtains an input stream to read the contents of the packet.
     *
     * @return the data in this packet.
     */
    public BufferedInputStream getInputStream()
    {
        return in;
    }
}
