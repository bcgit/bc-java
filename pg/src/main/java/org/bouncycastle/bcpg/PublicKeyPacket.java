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
        this(PUBLIC_KEY, in);
    }

    PublicKeyPacket(
        int keyTag,
        BCPGInputStream in)
        throws IOException
    {
        super(keyTag);

        version = in.read();
        time = ((long)in.read() << 24) | (in.read() << 16) | (in.read() << 8) | in.read();

        if (version <= VERSION_3)
        {
            validDays = (in.read() << 8) | in.read();
        }

        algorithm = (byte)in.read();
        if (version == VERSION_6)
        {
            // TODO: Use keyOctets to be able to parse unknown keys
            long keyOctets = ((long)in.read() << 24) | ((long)in.read() << 16) | ((long)in.read() << 8) | in.read();
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
        case ECDSA:
            key = new ECDSAPublicBCPGKey(in);
            break;
        case EDDSA_LEGACY:
            key = new EdDSAPublicBCPGKey(in);
            break;
        case X25519:
            key = new X25519PublicBCPGKey(in);
            break;
        case X448:
            key = new X448PublicBCPGKey(in);
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

        pOut.write((byte)(time >> 24));
        pOut.write((byte)(time >> 16));
        pOut.write((byte)(time >> 8));
        pOut.write((byte)time);

        if (version <= VERSION_3)
        {
            pOut.write((byte)(validDays >> 8));
            pOut.write((byte)validDays);
        }

        pOut.write(algorithm);

        if (version == VERSION_6)
        {
            int keyOctets = key.getEncoded().length;
            pOut.write(keyOctets >> 24);
            pOut.write(keyOctets >> 16);
            pOut.write(keyOctets >> 8);
            pOut.write(keyOctets);
        }

        pOut.writeObject((BCPGObject)key);

        pOut.close();

        return bOut.toByteArray();
    }

    public void encode(
        BCPGOutputStream out)
        throws IOException
    {
        out.writePacket(getPacketTag(), getEncodedContents());
    }
}
