package org.bouncycastle.bcpg;

import java.io.IOException;

/**
 * Packet representing AEAD encrypted data. At the moment this appears to exist in the following
 * expired draft only, but it's appearing despite this.
 *
 * @ref https://datatracker.ietf.org/doc/html/draft-ietf-openpgp-rfc4880bis-04#section-5.16
 */
public class AEADEncDataPacket
    extends InputStreamPacket
    implements AEADAlgorithmTags
{
    private final byte version;
    private final byte algorithm;
    private final byte aeadAlgorithm;
    private final byte chunkSize;
    private final byte[] iv;

    public AEADEncDataPacket(BCPGInputStream in)
        throws IOException
    {
        super(in);

        version = (byte)in.read();
        if (version != 1)
        {
            throw new IllegalArgumentException("wrong AEAD packet version: " + version);
        }

        algorithm = (byte)in.read();
        aeadAlgorithm = (byte)in.read();
        chunkSize = (byte)in.read();

        iv = new byte[getIVLength(aeadAlgorithm)];
        in.read(iv, 0, iv.length);
    }

    private int getIVLength(byte mode)
    {
        switch (mode)
        {
        case EAX:
            return 16;
        case OCB:
            return 15;
        case GCM:
            return 12;
        default:
            throw new IllegalArgumentException("unknown mode: " + mode);
        }
    }

    public byte getVersion()
    {
        return version;
    }

    public byte getAlgorithm()
    {
        return algorithm;
    }

    public byte getAEADAlgorithm()
    {
        return aeadAlgorithm;
    }

    public int getChunkSize()
    {
        return chunkSize;
    }

    public byte[] getIV()
    {
        return iv;
    }
}