package org.bouncycastle.bcpg;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Date;

/**
 * basic packet for a PGP public key
 */
public class PublicKeyPacket
    extends ContainedPacket
    implements PublicKeyAlgorithmTags
{
    public static final int VERSION_3 = 3;
    public static final int VERSION_4 = 4;
    public static final int VERSION_6 = 6;

    private int version;
    private long time;
    private int validDays;
    private int algorithm;
    private BCPGKey key;

    PublicKeyPacket(
            BCPGInputStream in)
            throws IOException
    {
        this(in, false);
    }
    PublicKeyPacket(
        BCPGInputStream in,
        boolean newPacketFormat)
        throws IOException
    {
        this(PUBLIC_KEY, in, newPacketFormat);
    }

    PublicKeyPacket(
            int keyTag,
            BCPGInputStream in)
            throws IOException
    {
        this(keyTag, in, false);
    }

    PublicKeyPacket(
        int keyTag,
        BCPGInputStream in,
        boolean newPacketFormat)
        throws IOException
    {
        super(keyTag, newPacketFormat);

        version = in.read();
        time = StreamUtil.read4OctetLength(in);

        if (version <= VERSION_3)
        {
            validDays = (in.read() << 8) | in.read();
        }

        algorithm = (byte)in.read();
        if (version == VERSION_6)
        {
            // TODO: Use keyOctets to be able to parse unknown keys
            long keyOctets = StreamUtil.read4OctetLength(in);
        }

        switch (algorithm)
        {
        case RSA_ENCRYPT:
        case RSA_GENERAL:
        case RSA_SIGN:
            key = new RSAPublicBCPGKey(in);
            break;
        case DSA:
            key = new DSAPublicBCPGKey(in);
            break;
        case ELGAMAL_ENCRYPT:
        case ELGAMAL_GENERAL:
            key = new ElGamalPublicBCPGKey(in);
            break;
        case ECDH:
            key = new ECDHPublicBCPGKey(in);
            break;
        case X25519:
            key = new X25519PublicBCPGKey(in);
            break;
        case X448:
            key = new X448PublicBCPGKey(in);
            break;
        case ECDSA:
            key = new ECDSAPublicBCPGKey(in);
            break;
        case EDDSA_LEGACY:
            key = new EdDSAPublicBCPGKey(in);
            break;
        case Ed25519:
            key = new Ed25519PublicBCPGKey(in);
            break;
        case Ed448:
            key = new Ed448PublicBCPGKey(in);
            break;
        default:
            throw new IOException("unknown PGP public key algorithm encountered: " + algorithm);
        }
    }

    /**
     * Construct version 4 public key packet.
     *
     * @param algorithm
     * @param time
     * @param key
     */
    public PublicKeyPacket(
        int algorithm,
        Date time,
        BCPGKey key)
    {
        this(VERSION_4, algorithm, time, key);
    }

    public PublicKeyPacket(
         int version,
         int algorithm,
         Date time,
         BCPGKey key)
     {
         this(PUBLIC_KEY, version, algorithm, time, key);
     }

    PublicKeyPacket(int keyTag, int version, int algorithm, Date time, BCPGKey key)
    {
        super(keyTag);

        this.version = version;
        this.time = time.getTime() / 1000;
        this.algorithm = algorithm;
        this.key = key;
    }


    public int getVersion()
    {
        return version;
    }

    public int getAlgorithm()
    {
        return algorithm;
    }

    public int getValidDays()
    {
        return validDays;
    }

    public Date getTime()
    {
        return new Date(time * 1000);
    }

    public BCPGKey getKey()
    {
        return key;
    }

    public byte[] getEncodedContents()
        throws IOException
    {
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        BCPGOutputStream pOut = new BCPGOutputStream(bOut);

        pOut.write(version);

        StreamUtil.writeTime(pOut, time);

        if (version <= VERSION_3)
        {
            pOut.writeShort((short)validDays);
        }

        pOut.write(algorithm);

        if (version == VERSION_6)
        {
            pOut.writeInt(key.getEncoded().length);
        }

        pOut.writeObject((BCPGObject)key);

        pOut.close();

        return bOut.toByteArray();
    }

    public void encode(
        BCPGOutputStream out)
        throws IOException
    {
        out.writePacket(hasNewPacketFormat(), getPacketTag(), getEncodedContents());
    }
}
