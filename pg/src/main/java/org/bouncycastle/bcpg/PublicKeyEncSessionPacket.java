package org.bouncycastle.bcpg;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.io.Streams;

/**
 * basic packet for a PGP public key
 */
public class PublicKeyEncSessionPacket
    extends ContainedPacket
    implements PublicKeyAlgorithmTags
{
    /**
     * Version 3 PKESK packet.
     * Used only with {@link SymmetricEncIntegrityPacket#VERSION_1 V1 SEIPD} or {@link SymmetricEncDataPacket SED} packets.
     */
    public static final int VERSION_3 = 3;

    /**
     * Version 6 PKESK packet.
     * Used only with {@link SymmetricEncIntegrityPacket#VERSION_2 V2 SEIPD} packets.
     */
    public static final int VERSION_6 = 6;

    private int version;         // v3, v6
    private long keyID;           // v3
    private int algorithm;       // v3, v6
    private byte[][] data;            // v3, v6
    private int keyVersion;      // v6
    private byte[] keyFingerprint;  // v6

    PublicKeyEncSessionPacket(
            BCPGInputStream in)
            throws IOException
    {
        this(in, false);
    }

    PublicKeyEncSessionPacket(
        BCPGInputStream in,
        boolean newPacketFormat)
        throws IOException
    {
        super(PUBLIC_KEY_ENC_SESSION, newPacketFormat);

        version = in.read();

        if (version == VERSION_3)
        {
            keyID = StreamUtil.readKeyID(in);
        }
        else if (version == VERSION_6)
        {
            int keyInfoLen = in.read();
            if (keyInfoLen == 0)
            {
                // anon recipient
                keyVersion = 0;
                keyFingerprint = new byte[0];
            }
            else
            {
                keyVersion = in.read();
                keyFingerprint = new byte[keyInfoLen - 1];
                in.readFully(keyFingerprint);
            }
        }
        else
        {
            throw new UnsupportedPacketVersionException("Unsupported PGP public key encrypted session key packet version encountered: " + version);
        }

        // common between v3 and v6
        algorithm = in.read();

        switch (algorithm)
        {
        case RSA_ENCRYPT:
        case RSA_GENERAL:
            data = new byte[1][];

            data[0] = new MPInteger(in).getEncoded();
            break;
        case ELGAMAL_ENCRYPT:
        case ELGAMAL_GENERAL:
            data = new byte[2][];

            data[0] = new MPInteger(in).getEncoded();
            data[1] = new MPInteger(in).getEncoded();
            break;
        case ECDH:
        case X448:
        case X25519:
            data = new byte[1][];

            data[0] = Streams.readAll(in);
            break;
        default:
            throw new IOException("unknown PGP public key algorithm encountered");
        }

    }

    /**
     * Create a new V3 PKESK packet.
     *
     * @param keyID     ID of the recipient key, 0 for anonymous
     * @param algorithm public key algorithm
     * @param data      session data
     */
    public PublicKeyEncSessionPacket(
        long keyID,
        int algorithm,
        byte[][] data)
    {
        super(PUBLIC_KEY_ENC_SESSION);

        this.version = VERSION_3;
        this.keyID = keyID;
        this.algorithm = algorithm;
        this.data = new byte[data.length][];

        for (int i = 0; i != data.length; i++)
        {
            this.data[i] = Arrays.clone(data[i]);
        }
    }

    /**
     * Create a new V6 PKESK packet.
     *
     * @param keyVersion     version of the key
     * @param keyFingerprint fingerprint of the key
     * @param algorithm      public key algorithm
     * @param data           session data
     */
    public PublicKeyEncSessionPacket(
        int keyVersion,
        byte[] keyFingerprint,
        int algorithm,
        byte[][] data)
    {

        super(PUBLIC_KEY_ENC_SESSION);

        this.version = VERSION_6;
        this.keyVersion = keyVersion;
        this.keyFingerprint = Arrays.clone(keyFingerprint);
        this.algorithm = algorithm;
        this.data = new byte[data.length][];

        for (int i = 0; i < data.length; i++)
        {
            this.data[i] = Arrays.clone(data[i]);
        }
    }

    /**
     * Create a new V3 PKESK packet.
     *
     * @param keyID     ID of the recipient key, 0 for anonymous
     * @param algorithm public key algorithm
     * @param data      session data
     */
    public static PublicKeyEncSessionPacket createV3PKESKPacket(
        long keyID,
        int algorithm,
        byte[][] data)
    {
        return new PublicKeyEncSessionPacket(keyID, algorithm, data);
    }

    /**
     * Create a new V6 PKESK packet.
     *
     * @param keyVersion     version of the key
     * @param keyFingerprint fingerprint of the key
     * @param algorithm      public key algorithm
     * @param data           session data
     */
    public static PublicKeyEncSessionPacket createV6PKESKPacket(
        int keyVersion,
        byte[] keyFingerprint,
        int algorithm,
        byte[][] data)
    {
        return new PublicKeyEncSessionPacket(keyVersion, keyFingerprint, algorithm, data);
    }

    /**
     * Return the version of this PKESK packet.
     *
     * @return version
     */
    public int getVersion()
    {
        return version;
    }

    /**
     * Return the id of the recipient key.
     * V3 PKESK only. TODO: Add conversion from fingerprint to key-id for V6 PKESK?
     *
     * @return key id
     */
    public long getKeyID()
    {
        return keyID;
    }

    /**
     * Return the fingerprint of the recipient key.
     * If the recipient key is anonymous, this method returns an empty array.
     * V6 PKESK packet only.
     *
     * @return key fingerprint
     */
    public byte[] getKeyFingerprint()
    {
        return Arrays.clone(keyFingerprint);
    }

    /**
     * Return the version number of the recipient key.
     * If the recipient key is anonymous, this method returns 0.
     * V6 PKESK packet only.
     *
     * @return key version
     */
    public int getKeyVersion()
    {
        return keyVersion;
    }

    /**
     * Return the public key algorithm of the recipient key.
     *
     * @return public key algorithm
     */
    public int getAlgorithm()
    {
        return algorithm;
    }

    public byte[][] getEncSessionKey()
    {
        return data;
    }

    public void encode(
        BCPGOutputStream out)
        throws IOException
    {
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        BCPGOutputStream pOut = new BCPGOutputStream(bOut);

        pOut.write(version);

        if (version == VERSION_3)
        {
            StreamUtil.writeKeyID(pOut, keyID);
        }
        else if (version == VERSION_6)
        {
            pOut.write(keyFingerprint.length + 1);
            pOut.write(keyVersion);
            pOut.write(keyFingerprint);
        }

        pOut.write(algorithm);

        for (int i = 0; i != data.length; i++)
        {
            pOut.write(data[i]);
        }

        pOut.close();

        out.writePacket(hasNewPacketFormat(), PUBLIC_KEY_ENC_SESSION, bOut.toByteArray());
    }
}
