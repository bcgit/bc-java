package org.bouncycastle.openpgp;

import java.io.IOException;

import org.bouncycastle.bcpg.BCPGInputStream;
import org.bouncycastle.bcpg.TrustPacket;
import org.bouncycastle.util.Arrays;

public class PGPTrust
{

    private final TrustPacket packet;

    public PGPTrust(TrustPacket packet)
    {
        this.packet = packet;
    }

    public PGPTrust(BCPGInputStream inputStream)
        throws IOException
    {
        this((TrustPacket) inputStream.readPacket());
    }

    public TrustPacket getPacket()
    {
        return packet;
    }

    public byte[] getLevelAndTrust()
    {
        return Arrays.clone(packet.getLevelAndTrustAmount());
    }
}
