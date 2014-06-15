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
        super(in);

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
