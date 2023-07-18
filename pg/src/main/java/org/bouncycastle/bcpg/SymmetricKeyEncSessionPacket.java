package org.bouncycastle.bcpg;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.EOFException;
import java.io.IOException;

/**
 * Basic type for a symmetric encrypted session key packet
 */
public class SymmetricKeyEncSessionPacket
    extends ContainedPacket
{
    /**
     * Version 4 SKESK packet.
     * Used only with {@link SymmetricEncIntegrityPacket#VERSION_1 V1 SEIPD} or {@link SymmetricEncDataPacket SED} packets.
     */
    public static final int VERSION_4 = 4;

    /**
     * Version 5 SKESK packet.
     * Used only with {@link AEADEncDataPacket AED} packets.
     */
    public static final int VERSION_5 = 5;

    /**
     * Version 6 SKESK packet.
     * Used only with {@link SymmetricEncIntegrityPacket#VERSION_2 V2 SEIPD} packets.
     */
    public static final int VERSION_6 = 6;

    private int version;          // V4, V5, V6
    private int encAlgorithm;     // V4, V5, V6
    private S2K s2k;              // V4,
    // array for exposing raw S2K parameters. Useful for forwards compat.
    private byte[] s2kBytes;         // Makes only sense for v6, since there we have a counter
    private byte[] secKeyData;       // V4, V5, V6
    private int aeadAlgorithm;    // V5, V6
    private byte[] iv;               // V5, V6
    private byte[] authTag;          // V5, V6

    public SymmetricKeyEncSessionPacket(
        BCPGInputStream in)
        throws IOException
    {
        super(SYMMETRIC_KEY_ENC_SESSION);

        version = in.read();
        if (version == VERSION_4)
        {
            encAlgorithm = in.read();

            s2k = new S2K(in);

            this.secKeyData = in.readAll();
        }
        else if (version == VERSION_5 || version == VERSION_6)
        {
            // https://www.ietf.org/archive/id/draft-ietf-openpgp-crypto-refresh-07.html#section-5.3.2-3.2
            // SymAlg + AEADAlg + S2KCount + S2K + IV
            int next5Fields5Count = in.read();
            encAlgorithm = in.read();
            aeadAlgorithm = in.read();

            // https://www.ietf.org/archive/id/draft-ietf-openpgp-crypto-refresh-07.html#section-5.3.2-3.5
            int s2kOctetCount = in.read();
            s2kBytes = new byte[s2kOctetCount];
            in.readFully(s2kBytes);
            try
            {
                s2k = new S2K(new ByteArrayInputStream(s2kBytes));
            }
            catch (UnsupportedPacketVersionException e)
            {

                // We gracefully catch the error.
            }

            int ivLen = next5Fields5Count - 3 - s2kOctetCount;
            iv = new byte[ivLen]; // also called nonce
            if (in.read(iv) != iv.length)
            {
                throw new EOFException("Premature end of stream.");
            }

            int authTagLen = AEADUtils.getAuthTagLength(aeadAlgorithm);
            authTag = new byte[authTagLen];

            // Read all trailing bytes
            byte[] sessKeyAndAuthTag = in.readAll();
            // determine session key length by subtracting auth tag
            this.secKeyData = new byte[sessKeyAndAuthTag.length - authTagLen];

            System.arraycopy(sessKeyAndAuthTag, 0, secKeyData, 0, secKeyData.length);
            System.arraycopy(sessKeyAndAuthTag, secKeyData.length, authTag, 0, authTagLen);
        }
        else
        {
            throw new UnsupportedPacketVersionException("Unsupported PGP symmetric-key encrypted session key packet version encountered: " + version);
        }

    }

    /**
     * Create a v4 SKESK packet.
     *
     * @param encAlgorithm symmetric encryption algorithm
     * @param s2k          s2k specifier
     * @param secKeyData   encrypted session key
     */
    public static SymmetricKeyEncSessionPacket createV4Packet(
        int encAlgorithm,
        S2K s2k,
        byte[] secKeyData)
    {
        return new SymmetricKeyEncSessionPacket(encAlgorithm, s2k, secKeyData);
    }

    /**
     * Create a v5 SKESK packet.
     *
     * @param encAlgorithm  symmetric encryption algorithm
     * @param aeadAlgorithm aead algorithm
     * @param iv            initialization vector
     * @param s2k           s2k specifier
     * @param secKeyData    encrypted session key
     * @param authTag       authentication tag
     */
    public static SymmetricKeyEncSessionPacket createV5Packet(
        int encAlgorithm,
        int aeadAlgorithm,
        byte[] iv,
        S2K s2k,
        byte[] secKeyData,
        byte[] authTag)
    {
        return new SymmetricKeyEncSessionPacket(VERSION_5, encAlgorithm, aeadAlgorithm, iv, s2k, secKeyData, authTag);
    }

    /**
     * Create a v6 SKESK packet.
     *
     * @param encAlgorithm  symmetric encryption algorithm
     * @param aeadAlgorithm aead algorithm
     * @param s2k           s2k specifier
     * @param iv            initialization vector
     * @param secKeyData    encrypted session key
     * @param authTag       authentication tag
     */
    public static SymmetricKeyEncSessionPacket createV6Packet(
        int encAlgorithm,
        int aeadAlgorithm,
        byte[] iv,
        S2K s2k,
        byte[] secKeyData,
        byte[] authTag)
    {
        return new SymmetricKeyEncSessionPacket(VERSION_6, encAlgorithm, aeadAlgorithm, iv, s2k, secKeyData, authTag);
    }

    /**
     * Create a v4 SKESK packet.
     *
     * @param encAlgorithm symmetric encryption algorithm
     * @param s2k          s2k
     * @param secKeyData   encrypted session key
     * @deprecated use createVersion4Packet()
     */
    public SymmetricKeyEncSessionPacket(
        int encAlgorithm,
        S2K s2k,
        byte[] secKeyData)
    {
        super(SYMMETRIC_KEY_ENC_SESSION);

        this.version = VERSION_4;
        this.encAlgorithm = encAlgorithm;
        this.s2k = s2k;
        this.secKeyData = secKeyData;
    }

    /**
     * Create a v5 or v6 SKESK packet.
     *
     * @param encAlgorithm  symmetric encryption algorithm
     * @param aeadAlgorithm aead algorithm
     * @param iv            initialization vector
     * @param s2k           s2k specifier
     * @param secKeyData    encrypted session key
     * @param authTag       authentication tag
     */
    private SymmetricKeyEncSessionPacket(
        int version,
        int encAlgorithm,
        int aeadAlgorithm,
        byte[] iv,
        S2K s2k,
        byte[] secKeyData,
        byte[] authTag)
    {
        super(SYMMETRIC_KEY_ENC_SESSION);

        this.version = version;
        this.encAlgorithm = encAlgorithm;
        this.aeadAlgorithm = aeadAlgorithm;
        this.s2k = s2k;
        this.secKeyData = secKeyData;

        int expectedIVLen = AEADUtils.getIVLength(aeadAlgorithm);
        if (expectedIVLen != iv.length)
        {
            throw new IllegalArgumentException("Mismatched AEAD IV length. " +
                "Expected " + expectedIVLen + ", got " + iv.length);
        }
        this.iv = iv;

        int expectedAuthTagLen = AEADUtils.getAuthTagLength(aeadAlgorithm);
        if (expectedAuthTagLen != authTag.length)
        {
            throw new IllegalArgumentException("Mismatched AEAD AuthTag length. " +
                "Expected " + expectedAuthTagLen + ", got " + authTag.length);
        }
        this.authTag = authTag;
    }

    /**
     * @return int
     */
    public int getEncAlgorithm()
    {
        return encAlgorithm;
    }

    /**
     * @return S2K
     */
    public S2K getS2K()
    {
        return s2k;
    }

    /**
     * @return byte[]
     */
    public byte[] getSecKeyData()
    {
        return secKeyData;
    }

    /**
     * @return int
     */
    public int getVersion()
    {
        return version;
    }

    /**
     * Return the AEAD algorithm tag.
     * V5 packet only.
     *
     * @return aead algorithm
     */
    public int getAeadAlgorithm()
    {
        return aeadAlgorithm;
    }

    /**
     * Return the IV for the AEAD mode. This is also called nonce.
     * V5 packet only.
     *
     * @return iv
     */
    public byte[] getIv()
    {
        return iv;
    }

    /**
     * Return the authentication tag for the AEAD mode.
     * V5 packet only.
     *
     * @return AEAD auth tag
     */
    public byte[] getAuthTag()
    {
        return authTag;
    }

    public byte[] getAAData()
    {
        return createAAData(getVersion(), getEncAlgorithm(), getAeadAlgorithm());
    }

    public static byte[] createAAData(int version, int encAlgorithm, int aeadAlgorithm)
    {
        byte[] aaData = new byte[4];
        aaData[0] = (byte)(0xC0 | PacketTags.SYMMETRIC_KEY_ENC_SESSION);
        aaData[1] = (byte)(version & 0xff);
        aaData[2] = (byte)(encAlgorithm & 0xff);
        aaData[3] = (byte)(aeadAlgorithm & 0xff);
        return aaData;
    }

    public void encode(
        BCPGOutputStream out)
        throws IOException
    {
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        BCPGOutputStream pOut;
        if (version == 4)
        {
            pOut = new BCPGOutputStream(bOut);
        }
        else
        {
            pOut = new BCPGOutputStream(bOut, true);
        }

        pOut.write(version);
        if (version == VERSION_4)
        {
            pOut.write(encAlgorithm);
            pOut.writeObject(s2k);

            if (secKeyData != null && secKeyData.length > 0)
            {
                pOut.write(secKeyData);
            }
        }
        else if (version == VERSION_5 || version == VERSION_6)
        {
            int s2kLen = s2k.getEncoded().length;
            int count = 1 + 1 + 1 + s2kLen + iv.length;
            pOut.write(count); // len of 5 following fields
            pOut.write(encAlgorithm);
            pOut.write(aeadAlgorithm);
            pOut.write(s2kLen);
            pOut.writeObject(s2k);
            pOut.write(iv);

            if (secKeyData != null && secKeyData.length > 0)
            {
                pOut.write(secKeyData);
            }
            pOut.write(authTag);
        }

        pOut.close();

        out.writePacket(SYMMETRIC_KEY_ENC_SESSION, bOut.toByteArray());
    }
}
