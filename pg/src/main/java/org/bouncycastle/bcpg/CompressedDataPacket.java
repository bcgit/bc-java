package org.bouncycastle.bcpg;

import java.io.IOException;

/**
 * A generic compressed data object.
 */
public class CompressedDataPacket
    extends InputStreamPacket
{
    int    algorithm;

    CompressedDataPacket(
            BCPGInputStream    in)
            throws IOException
    {
        this(in, false);
    }

    CompressedDataPacket(
        BCPGInputStream    in,
        boolean newPacketFormat)
        throws IOException
    {
        super(in, COMPRESSED_DATA, newPacketFormat);

        algorithm = in.read();
    }

    /**
     * Gets the {@link CompressionAlgorithmTags compression algorithm} used for this packet.
     * 
     * @return the compression algorithm tag value.
     */
    public int getAlgorithm()
    {
        return algorithm;
    }
}
