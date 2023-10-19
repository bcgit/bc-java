package org.bouncycastle.bcpg;

import java.io.EOFException;
import java.io.IOException;

import org.bouncycastle.util.Arrays;

/**
 * A symmetric key encrypted packet with an associated integrity check code.
 */
public class SymmetricEncIntegrityPacket
    extends InputStreamPacket
    implements BCPGHeaderObject
{
    /**
     * Version 1 SEIPD packet.
     * Used only with {@link SymmetricKeyEncSessionPacket#VERSION_4} or {@link PublicKeyEncSessionPacket#VERSION_3}.
     */
    public static final int VERSION_1 = 1;

    /**
     * Version 2 SEIPD packet.
     * Used only with {@link SymmetricKeyEncSessionPacket#VERSION_6} or {@link PublicKeyEncSessionPacket#VERSION_6}.
     */
    public static final int VERSION_2 = 2;

    int version;             // V1, V2
    int cipherAlgorithm;     // V2
    int aeadAlgorithm;       // V2
    int chunkSize;           // V2
    byte[] salt;                // V2

    SymmetricEncIntegrityPacket(
        BCPGInputStream in)
        throws IOException
    {
        super(in, SYM_ENC_INTEGRITY_PRO);

        version = in.read();

        // V2 packet has additional fields
        if (version == VERSION_2)
        {
            cipherAlgorithm = in.read();
            aeadAlgorithm = in.read();
            chunkSize = in.read();
            salt = new byte[32];
            if (in.read(salt) != salt.length)
            {
                throw new EOFException("Premature end of stream.");
            }
        }
    }

    /**
     * @deprecated use createVersion1Packet()
     */
    public SymmetricEncIntegrityPacket()
    {
        super(null, SYM_ENC_INTEGRITY_PRO);

        version = VERSION_1;
    }

    private SymmetricEncIntegrityPacket(int version, int algorithm, int aeadAlgorithm, int chunkSize, byte[] salt)
    {
        super(null, SYM_ENC_INTEGRITY_PRO);
        this.version = version;
        this.cipherAlgorithm = algorithm;
        this.aeadAlgorithm = aeadAlgorithm;
        this.chunkSize = chunkSize;
        this.salt = Arrays.clone(salt);
    }

    public static SymmetricEncIntegrityPacket createVersion1Packet()
    {
        return new SymmetricEncIntegrityPacket();
    }

    public static SymmetricEncIntegrityPacket createVersion2Packet(int algorithm, int aeadAlgorithm, int chunkSize, byte[] salt)
    {
        return new SymmetricEncIntegrityPacket(VERSION_2, algorithm, aeadAlgorithm, chunkSize, salt);
    }

    public int getVersion()
    {
        return version;
    }

    @Override
    public int getType()
    {
        return SYM_ENC_INTEGRITY_PRO;
    }

    @Override
    public void encode(BCPGOutputStream bcpgOut)
        throws IOException
    {
        bcpgOut.write(getVersion());

        if (version == VERSION_2)
        {
            bcpgOut.write(cipherAlgorithm);
            bcpgOut.write(aeadAlgorithm);
            bcpgOut.write(chunkSize);
            bcpgOut.write(salt);
        }
    }

    /**
     * Return the cipher algorithm.
     * V2 SEIPD packet only.
     *
     * @return cipher algorithm
     */
    public int getCipherAlgorithm()
    {
        return cipherAlgorithm;
    }

    /**
     * Return the AEAD algorithm.
     * V2 SEIPD packet only.
     *
     * @return AEAD algorithm
     */
    public int getAeadAlgorithm()
    {
        return aeadAlgorithm;
    }

    /**
     * Return the chunksize for the AEAD construction.
     * V2 SEIPD packet only.
     *
     * @return chunksize
     */
    public int getChunkSize()
    {
        return chunkSize;
    }

    /**
     * Return the AEAD additional authenticated data, which is also used as HKDF info.
     * V2 SEIPD packet only.
     *
     * @return aadata
     */
    public byte[] getAAData()
    {
        return createAAData(getVersion(), getCipherAlgorithm(), getAeadAlgorithm(), getChunkSize());
    }

    public static byte[] createAAData(int version, int cipherAlgorithm, int aeadAlgorithm, int chunkSize)
    {
        return new byte[]{
            (byte)(0xC0 | PacketTags.SYM_ENC_INTEGRITY_PRO),
            (byte)(version & 0xff),
            (byte)(cipherAlgorithm & 0xff),
            (byte)(aeadAlgorithm & 0xff),
            (byte)(chunkSize & 0xff)
        };
    }

    /**
     * Return the salt used to derive the message key.
     * V2 SEIPD packet only.
     *
     * @return salt
     */
    public byte[] getSalt()
    {
        return Arrays.copyOf(salt, salt.length);
    }
}
