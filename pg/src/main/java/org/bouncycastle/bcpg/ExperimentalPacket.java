package org.bouncycastle.bcpg;

import java.io.IOException;

import org.bouncycastle.util.Arrays;

/**
 * basic packet for an experimental packet.
 */
public class ExperimentalPacket 
    extends ContainedPacket implements PublicKeyAlgorithmTags
{
    private byte[] contents;

    /**
     *
     * @param in
     * @throws IOException
     */
    ExperimentalPacket(
            int                tag,
            BCPGInputStream    in)
            throws IOException
    {
        this(tag, in, false);
    }

    /**
     * 
     * @param in
     * @throws IOException
     */
    ExperimentalPacket(
        int                tag,
        BCPGInputStream    in,
        boolean newPacketFormat)
        throws IOException
    {
        super(tag, newPacketFormat);

        this.contents = in.readAll();
    }

    /**
     * @deprecated use getPacketTag();
     */
    public int getTag()
    {
        return getPacketTag();
    }
    
    public byte[] getContents()
    {
        return Arrays.clone(contents);
    }

    public void encode(
        BCPGOutputStream    out)
        throws IOException
    {
        out.writePacket(hasNewPacketFormat(), getPacketTag(), contents);
    }
}
