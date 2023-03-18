package org.bouncycastle.openpgp;

import java.io.IOException;

import org.bouncycastle.bcpg.BCPGInputStream;
import org.bouncycastle.bcpg.Packet;
import org.bouncycastle.bcpg.PaddingPacket;

/**
 * The PGPPadding contains random data, and can be used to defend against traffic analysis on version 2 SEIPD messages
 * and Transferable Public Keys.
 * <p>
 * Such a padding packet MUST be ignored when received.
 */
public class PGPPadding
{
    private PaddingPacket p;

    /**
     * Default constructor.
     *
     * @param in
     * @throws IOException
     */
    public PGPPadding(
        BCPGInputStream in)
        throws IOException
    {
        Packet packet = in.readPacket();
        if (!(packet instanceof PaddingPacket))
        {
            throw new IOException("unexpected packet in stream: " + packet);
        }
        p = (PaddingPacket)packet;
    }

    public byte[] getPadding()
    {
        return p.getPadding();
    }
}
