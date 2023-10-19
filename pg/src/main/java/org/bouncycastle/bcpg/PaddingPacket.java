package org.bouncycastle.bcpg;

import java.io.IOException;
import java.security.SecureRandom;

import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.io.Streams;

public class PaddingPacket
    extends ContainedPacket
{
    private final byte[] padding;

    public PaddingPacket(BCPGInputStream in)
        throws IOException
    {
        super(PADDING);

        padding = Streams.readAll(in);
    }

    public PaddingPacket(byte[] padding)
    {
        super(PADDING);

        this.padding = padding;
    }

    public PaddingPacket(int octetLen, SecureRandom random)
    {
        this(randomBytes(octetLen, random));
    }

    private static byte[] randomBytes(int octetCount, SecureRandom random)
    {
        byte[] bytes = new byte[octetCount];
        random.nextBytes(bytes);
        return bytes;
    }

    public byte[] getPadding()
    {
        return Arrays.clone(padding);
    }

    @Override
    public void encode(BCPGOutputStream pOut)
        throws IOException
    {
        pOut.writePacket(PacketTags.PADDING, padding);
    }
}
