package org.bouncycastle.bcpg;

import java.io.IOException;

import org.bouncycastle.util.Arrays;

/**
 * Packet representing LibrePGP-style AEAD encrypted data.
 * Known as OCB Encrypted Data Packet in the LibrePGP specification.
 * Note: This packet is not part of the official OpenPGP standard.
 * OpenPGP uses the Symmetrically Encrypted Integrity Protected Data Packet version 2 instead.
 *
 * @see <a href="https://www.ietf.org/archive/id/draft-koch-librepgp-01.html#name-ocb-encrypted-data-packet-t">
 *     OCB Encrypted Data Packet</a>
 */
public class AEADEncDataPacket
    extends InputStreamPacket
    implements AEADAlgorithmTags, BCPGHeaderObject
{
    public static final int VERSION_1 = 1;

    private final byte version;
    private final byte algorithm;
    private final byte aeadAlgorithm;
    private final byte chunkSize;
    private final byte[] iv;

    public AEADEncDataPacket(BCPGInputStream in)
            throws IOException
    {
        this(in, false);
    }

    public AEADEncDataPacket(BCPGInputStream in,
                             boolean newPacketFormat)
        throws IOException
    {
        super(in, AEAD_ENC_DATA, newPacketFormat);

        version = (byte)in.read();
        if (version != VERSION_1)
        {
            throw new IllegalArgumentException("wrong AEAD packet version: " + version);
        }

        algorithm = (byte)in.read();
        aeadAlgorithm = (byte)in.read();
        chunkSize = (byte)in.read();

        iv = new byte[AEADUtils.getIVLength(aeadAlgorithm)];
        in.readFully(iv);
    }

    public AEADEncDataPacket(int algorithm, int aeadAlgorithm, int chunkSize, byte[] iv)
    {
        super(null, AEAD_ENC_DATA);

        this.version = VERSION_1;
        this.algorithm = (byte)algorithm;
        this.aeadAlgorithm = (byte)aeadAlgorithm;
        this.chunkSize = (byte)chunkSize;
        this.iv = Arrays.clone(iv);
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

    public byte[] getAAData()
    {
        return createAAData(getVersion(), getAlgorithm(), getAEADAlgorithm(), getChunkSize());
    }

    public static byte[] createAAData(int version, int symAlgorithm, int aeadAlgorithm, int chunkSize)
    {
        byte[] aaData = new byte[5];

        aaData[0] = (byte)(0xC0 | PacketTags.AEAD_ENC_DATA);
        aaData[1] = (byte)(version & 0xff);
        aaData[2] = (byte)(symAlgorithm & 0xff);
        aaData[3] = (byte)(aeadAlgorithm & 0xff);
        aaData[4] = (byte)(chunkSize & 0xff);

        return aaData;
    }

    @Override
    public int getType()
    {
        return AEAD_ENC_DATA;
    }
    
    @Override
    public void encode(BCPGOutputStream pgOut)
        throws IOException
    {
        pgOut.write(1);           // version
        pgOut.write(this.getAlgorithm());
        pgOut.write(this.getAEADAlgorithm());
        pgOut.write(this.getChunkSize());
        pgOut.write(iv);
    }

    /**
     * @deprecated use AEADUtils.getIVLength()
     */
    public static int getIVLength(byte aeadAlgorithm)
    {
        return AEADUtils.getIVLength(aeadAlgorithm);
    }
}