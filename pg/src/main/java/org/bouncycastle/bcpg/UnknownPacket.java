package org.bouncycastle.bcpg;

import org.bouncycastle.util.Arrays;

import java.io.IOException;

public class UnknownPacket
        extends ContainedPacket
{

    private final int tag;
    private final byte[] contents;

    public UnknownPacket(int tag, BCPGInputStream in)
            throws IOException
    {
        this.tag = tag;
        this.contents = in.readAll();
    }

    public byte[] getContents()
    {
        return Arrays.clone(contents);
    }

    @Override
    public void encode(
            BCPGOutputStream    out)
            throws IOException
    {
        out.writePacket(tag, contents);
    }

    @Override
    public int getPacketTag()
    {
        return tag;
    }
}
