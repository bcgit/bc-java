package org.bouncycastle.bcpg;

import java.io.IOException;

import org.bouncycastle.util.Arrays;

/**
 * basic packet for an experimental packet.
 */
public class ExperimentalPacket 
    extends ContainedPacket implements PublicKeyAlgorithmTags
{
    private int    tag;
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
        super(tag);

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
        out.writePacket(tag, contents);
    }
}
