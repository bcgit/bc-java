package org.bouncycastle.bcpg;

import java.io.IOException;

import org.bouncycastle.util.Arrays;

public class UnknownPacket
        extends ContainedPacket
{
    private final byte[] contents;

    public UnknownPacket(int tag, BCPGInputStream in)
            throws IOException
    {
        super(tag);
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
        out.writePacket(getPacketTag(), contents);
    }
}
